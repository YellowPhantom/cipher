'use strict';

// ── Element refs ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const keyInput      = $('key-input');
const toggleKeyBtn  = $('toggle-key');
const eyeShow       = $('eye-show');
const eyeHide       = $('eye-hide');
const tabEncrypt    = $('tab-encrypt');
const tabDecrypt    = $('tab-decrypt');
const inputText     = $('input-text');
const outputText    = $('output-text');
const processBtn    = $('process-btn');
const arrowIcon     = $('arrow-icon');
const spinnerIcon   = $('spinner-icon');
const copyBtn       = $('copy-btn');
const copyIcon      = $('copy-icon');
const checkIcon     = $('check-icon');
const inputLabel    = $('input-label');
const outputLabel   = $('output-label');
const inputCounter  = $('input-counter');
const outputCounter = $('output-counter');
const statusBar     = $('status-bar');

// ── State ─────────────────────────────────────────────────────────────────────
let mode       = 'encrypt';
let processing = false;

// ── Mode switching ────────────────────────────────────────────────────────────
function setMode(m) {
  mode = m;
  tabEncrypt.classList.toggle('active', m === 'encrypt');
  tabDecrypt.classList.toggle('active', m === 'decrypt');
  inputLabel.textContent  = m === 'encrypt' ? 'Plaintext'  : 'Ciphertext';
  outputLabel.textContent = m === 'encrypt' ? 'Ciphertext' : 'Plaintext';
  inputText.placeholder   = m === 'encrypt' ? 'Type your message here…' : 'Paste ciphertext here…';
  outputText.value = '';
  hideStatus();
  updateCounters();
}
tabEncrypt.addEventListener('click', () => setMode('encrypt'));
tabDecrypt.addEventListener('click', () => setMode('decrypt'));

// ── Key visibility toggle ─────────────────────────────────────────────────────
toggleKeyBtn.addEventListener('click', () => {
  const visible = keyInput.type === 'text';
  keyInput.type = visible ? 'password' : 'text';
  eyeShow.classList.toggle('hidden', !visible);
  eyeHide.classList.toggle('hidden', visible);
});

// ── Counters ──────────────────────────────────────────────────────────────────
function updateCounters() {
  inputCounter.textContent  = `${inputText.value.length} chars`;
  outputCounter.textContent = `${outputText.value.length} chars`;
}
inputText.addEventListener('input', updateCounters);

// ── Status bar ────────────────────────────────────────────────────────────────
function showStatus(msg, type = 'info') {
  statusBar.textContent = msg;
  statusBar.className = `status-bar ${type}`;
}
function hideStatus() {
  statusBar.className = 'status-bar hidden';
}

// ── Process ───────────────────────────────────────────────────────────────────
async function process() {
  if (processing) return;
  const text = inputText.value.trim();
  const key  = keyInput.value.trim() || 'YELLOWPHANTOM';
  if (!text) { showStatus('Please enter a message first.', 'error'); return; }

  processing = true;
  processBtn.disabled = true;
  arrowIcon.classList.add('hidden');
  spinnerIcon.classList.remove('hidden');
  hideStatus();

  try {
    const result = mode === 'encrypt'
      ? await cipherEncrypt(text, key)
      : await cipherDecrypt(text, key);

    if (result.startsWith('[error:')) {
      showStatus(result, 'error');
      outputText.value = '';
    } else {
      outputText.value = result;
      showStatus(
        mode === 'encrypt' ? '✓ Encrypted successfully' : '✓ Decrypted successfully',
        'success'
      );
    }
    updateCounters();
  } catch (err) {
    showStatus('[error: ' + err.message + ']', 'error');
  } finally {
    processing = false;
    processBtn.disabled = false;
    arrowIcon.classList.remove('hidden');
    spinnerIcon.classList.add('hidden');
  }
}

processBtn.addEventListener('click', process);
inputText.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') process();
});

// ── Copy to clipboard ─────────────────────────────────────────────────────────
let copyTimer;
copyBtn.addEventListener('click', async () => {
  const val = outputText.value;
  if (!val) return;
  try {
    await navigator.clipboard.writeText(val);
    copyBtn.classList.add('copied');
    copyIcon.classList.add('hidden');
    checkIcon.classList.remove('hidden');
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => {
      copyBtn.classList.remove('copied');
      copyIcon.classList.remove('hidden');
      checkIcon.classList.add('hidden');
    }, 2000);
  } catch {
    showStatus('Could not access clipboard — copy the text manually.', 'error');
  }
});
