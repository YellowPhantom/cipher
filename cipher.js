'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

// ── Helpers ───────────────────────────────────────────────────────────────────
function _toAlpha(bytes) {
  return Array.from(bytes).map(b => ALPHA[b % 26]).join('');
}

function _encNum(n, w) {
  const r = [];
  for (let i = 0; i < w; i++) { r.push(ALPHA[n % 26]); n = Math.floor(n / 26); }
  return r.reverse().join('');
}

function _decNum(s) {
  let n = 0;
  for (const c of s) n = n * 26 + ALPHA.indexOf(c);
  return n;
}

async function _derive(key, nonceStr) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(key), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(nonceStr), iterations: 200_000, hash: 'SHA-256' },
    raw, 96 * 8
  );
  return new Uint8Array(bits);
}

function _makeSub(seed) {
  const perm = Array.from({ length: 26 }, (_, i) => i);
  for (let i = 25; i > 0; i--) {
    const idx = (i * 2) % 32;
    const j = ((seed[idx] << 8) | seed[idx + 1]) % (i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  const inv = new Array(26).fill(0);
  for (let i = 0; i < 26; i++) inv[perm[i]] = i;
  return [perm, inv];
}

async function _sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function _ks(seed, n) {
  const out = [];
  let blk = 0;
  while (out.length < n) {
    const buf = new Uint8Array(seed.length + 4);
    buf.set(seed);
    new DataView(buf.buffer).setUint32(seed.length, blk, false);
    const hash = await _sha256(buf);
    for (const b of hash) out.push(b % 26);
    blk++;
  }
  return out.slice(0, n);
}

// Self-inverse: applying twice restores original
function _shuffle(lst, size) {
  const result = [];
  for (let i = 0; i * size < lst.length; i++) {
    const block = lst.slice(i * size, (i + 1) * size);
    result.push(...(i % 2 === 1 ? block.reverse() : block));
  }
  return result;
}

async function _hmac(key, data) {
  const k = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

// ── Encrypt ───────────────────────────────────────────────────────────────────
async function cipherEncrypt(text, key) {
  const t = text.toUpperCase();
  const spaces = [];
  for (let i = 0; i < t.length; i++) if (t[i] === ' ') spaces.push(i);

  const plain = [];
  for (const c of t) if (ALPHA.includes(c)) plain.push(ALPHA.indexOf(c));
  if (!plain.length) return '[error: no letters]';

  const nonceStr  = _toAlpha(crypto.getRandomValues(new Uint8Array(16)));
  const dk        = await _derive(key, nonceStr);
  const [SUB]     = _makeSub(dk.slice(0, 32));
  const ksMaster  = dk.slice(32, 64);
  const macKey    = dk.slice(64, 96);
  const spHdr     = _encNum(spaces.length, 2) + spaces.map(p => _encNum(p, 3)).join('');

  let state = [...plain];
  for (let rnd = 0; rnd < 3; rnd++) {
    const rndBuf = new Uint8Array(ksMaster.length + 1);
    rndBuf.set(ksMaster); rndBuf[ksMaster.length] = rnd;
    const rndSeed   = await _sha256(rndBuf);
    const keystream = await _ks(rndSeed, state.length);
    const out = []; let prev = 0;
    for (let i = 0; i < state.length; i++) {
      const enc = (SUB[state[i]] + keystream[i] + prev) % 26;
      prev = enc; out.push(enc);
    }
    state = _shuffle(out, 7 + rnd * 2);
  }

  const body    = state.map(v => ALPHA[v]).join('');
  const payload = nonceStr + spHdr + body;
  const tag     = _toAlpha((await _hmac(macKey, new TextEncoder().encode(payload))).slice(0, 10));

  return nonceStr + spHdr + tag + body;
}

// ── Decrypt ───────────────────────────────────────────────────────────────────
async function cipherDecrypt(text, key) {
  const clean = [...text.toUpperCase()].filter(c => ALPHA.includes(c));
  if (clean.length < 28) return '[error: message too short]';

  const nonceStr = clean.slice(0, 16).join('');
  const numSp    = _decNum(clean.slice(16, 18).join(''));
  const hdrEnd   = 18 + numSp * 3;
  const spaces   = Array.from({ length: numSp }, (_, i) =>
    _decNum(clean.slice(18 + i * 3, 21 + i * 3).join(''))
  );
  const spHdr  = clean.slice(16, hdrEnd).join('');
  const tagRcv = clean.slice(hdrEnd, hdrEnd + 10).join('');
  const body   = clean.slice(hdrEnd + 10).join('');

  const dk       = await _derive(key, nonceStr);
  const [, INV]  = _makeSub(dk.slice(0, 32));
  const ksMaster = dk.slice(32, 64);
  const macKey   = dk.slice(64, 96);

  const payload = nonceStr + spHdr + body;
  const tagExp  = _toAlpha((await _hmac(macKey, new TextEncoder().encode(payload))).slice(0, 10));
  if (tagRcv !== tagExp) return '[error: authentication failed — wrong key or tampered message]';

  let state = body.split('').map(c => ALPHA.indexOf(c));
  for (let rnd = 2; rnd >= 0; rnd--) {
    state = _shuffle(state, 7 + rnd * 2);
    const rndBuf = new Uint8Array(ksMaster.length + 1);
    rndBuf.set(ksMaster); rndBuf[ksMaster.length] = rnd;
    const rndSeed   = await _sha256(rndBuf);
    const keystream = await _ks(rndSeed, state.length);
    const out = []; let prev = 0;
    for (let i = 0; i < state.length; i++) {
      const dec = ((state[i] - keystream[i] - prev) % 26 + 26) % 26;
      out.push(INV[dec]); prev = state[i];
    }
    state = out;
  }

  const arr = state.map(v => ALPHA[v]);
  for (const pos of [...spaces].sort((a, b) => a - b)) arr.splice(pos, 0, ' ');
  return arr.join('');
}
