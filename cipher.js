'use strict';

// ── Helpers ───────────────────────────────────────────────────────────────────

// Derives a 96-byte master key material from the password and nonce
async function _derive(key, nonce) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(key), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: nonce, iterations: 200_000, hash: 'SHA-256' },
    raw, 96 * 8
  );
  return new Uint8Array(bits);
}

// Generates a 256-byte Substitution Box (S-Box) and its inverse from a seed
function _makeSub(seed) {
  const perm = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const a = seed[i % seed.length];
    const b = seed[(i * 7 + 1) % seed.length];
    const j = ((a << 8) | b) % (i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  const inv = new Array(256).fill(0);
  for (let i = 0; i < 256; i++) inv[perm[i]] = i;
  return [perm, inv];
}

async function _sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// Generates a deterministic keystream of length `n` bytes
async function _ks(seed, n) {
  const out = new Uint8Array(n);
  let blk = 0, pos = 0;
  while (pos < n) {
    const buf = new Uint8Array(seed.length + 4);
    buf.set(seed);
    new DataView(buf.buffer).setUint32(seed.length, blk, false);
    const hash = await _sha256(buf);
    for (let i = 0; i < hash.length && pos < n; i++) {
      out[pos++] = hash[i];
    }
    blk++;
  }
  return out;
}

// Self-inverse array block shuffler
function _shuffle(lst, size) {
  const result = new Uint8Array(lst.length);
  let pos = 0;
  for (let i = 0; i * size < lst.length; i++) {
    const block = lst.slice(i * size, (i + 1) * size);
    if (i % 2 === 1) block.reverse();
    result.set(block, pos);
    pos += block.length;
  }
  return result;
}

// Safe Base64 encoding/decoding for arbitrary byte lengths
function bytesToBase64(bytes) {
  let binString = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binString += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binString);
}

function base64ToBytes(base64) {
  const cleanB64 = base64.replace(/\s+/g, ''); // Fix: allows decrypting formatted/spaced Base64
  const binString = atob(cleanB64);
  const bytes = new Uint8Array(binString.length);
  for (let i = 0; i < binString.length; i++) {
    bytes[i] = binString.charCodeAt(i);
  }
  return bytes;
}

// ── Encrypt ───────────────────────────────────────────────────────────────────
async function cipherEncrypt(text, key) {
  const plain = new TextEncoder().encode(text);
  if (!plain.length) return '[error: empty message]';

  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const dk = await _derive(key, nonce);
  const [SUB] = _makeSub(dk.slice(0, 32));
  const ksMaster = dk.slice(32, 64);
  const macKey   = dk.slice(64, 96);

  let state = new Uint8Array(plain);
  
  // 3-Round Substitution-Permutation Network
  for (let rnd = 0; rnd < 3; rnd++) {
    const rndBuf = new Uint8Array(ksMaster.length + 1);
    rndBuf.set(ksMaster); rndBuf[ksMaster.length] = rnd;
    const rndSeed = await _sha256(rndBuf);
    const keystream = await _ks(rndSeed, state.length);
    
    const out = new Uint8Array(state.length);
    let prev = 0;
    for (let i = 0; i < state.length; i++) {
      const enc = (SUB[state[i]] + keystream[i] + prev) % 256;
      prev = enc; 
      out[i] = enc;
    }
    state = _shuffle(out, 7 + rnd * 2);
  }

  // HMAC Authentication
  const payload = new Uint8Array(nonce.length + state.length);
  payload.set(nonce); payload.set(state, nonce.length);

  const k = await crypto.subtle.importKey(
    'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const fullTag = new Uint8Array(await crypto.subtle.sign('HMAC', k, payload));
  const tag = fullTag.slice(0, 10);

  // Combine Nonce (16) + Tag (10) + Ciphertext (N)
  const final = new Uint8Array(16 + 10 + state.length);
  final.set(nonce, 0);
  final.set(tag, 16);
  final.set(state, 26);

  return bytesToBase64(final);
}

// ── Decrypt ───────────────────────────────────────────────────────────────────
async function cipherDecrypt(text, key) {
  let finalBytes;
  try {
    finalBytes = base64ToBytes(text.trim());
  } catch (e) {
    return '[error: invalid ciphertext format]';
  }

  if (finalBytes.length < 26) return '[error: message too short]';

  const nonce = finalBytes.slice(0, 16);
  const tagRcv = finalBytes.slice(16, 26);
  const body = finalBytes.slice(26);

  const dk = await _derive(key, nonce);
  const [, INV] = _makeSub(dk.slice(0, 32));
  const ksMaster = dk.slice(32, 64);
  const macKey   = dk.slice(64, 96);

  // Verify HMAC Authentication
  const payload = new Uint8Array(nonce.length + body.length);
  payload.set(nonce); payload.set(body, nonce.length);

  const k = await crypto.subtle.importKey(
    'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const fullTag = new Uint8Array(await crypto.subtle.sign('HMAC', k, payload));
  const tagExp = fullTag.slice(0, 10);

  let match = true;
  for(let i = 0; i < 10; i++) {
    if (tagRcv[i] !== tagExp[i]) match = false;
  }
  if (!match) return '[error: authentication failed — wrong key or tampered message]';

  let state = new Uint8Array(body);
  
  // Reverse 3-Round SPN
  for (let rnd = 2; rnd >= 0; rnd--) {
    state = _shuffle(state, 7 + rnd * 2);
    const rndBuf = new Uint8Array(ksMaster.length + 1);
    rndBuf.set(ksMaster); rndBuf[ksMaster.length] = rnd;
    const rndSeed = await _sha256(rndBuf);
    const keystream = await _ks(rndSeed, state.length);
    
    const out = new Uint8Array(state.length);
    let prev = 0;
    for (let i = 0; i < state.length; i++) {
      let dec = (state[i] - keystream[i] - prev) % 256;
      if (dec < 0) dec += 256; // Standardize JS negative modulo
      
      out[i] = INV[dec];
      prev = state[i];
    }
    state = out;
  }

  try {
    return new TextDecoder().decode(state);
  } catch (e) {
    return '[error: failed to decode text]';
  }
}
