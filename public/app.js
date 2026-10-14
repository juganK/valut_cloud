/**
 * Vault — Minimalist Split-Screen Client Controller
 * Robust client with safe API handling, Web Crypto AES-256, and instant unlocks.
 */

// ==========================================
// 1. Audio Feedback (Web Audio API)
// ==========================================
class SoundFX {
  constructor() {
    this.enabled = true;
    this.ctx = null;
  }

  init() {
    if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.ctx = new AudioCtx();
    }
  }

  playClick() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(600, this.ctx.currentTime);
    gain.gain.setValueAtTime(0.03, this.ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.04);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start();
    osc.stop(this.ctx.currentTime + 0.04);
  }

  playSuccess() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const now = this.ctx.currentTime;
    [523, 659].forEach((freq, i) => {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now + i * 0.06);
      gain.gain.setValueAtTime(0.04, now + i * 0.06);
      gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.06 + 0.14);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(now + i * 0.06);
      osc.stop(now + i * 0.06 + 0.15);
    });
  }

  playUnlock() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const now = this.ctx.currentTime;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(400, now);
    osc.frequency.exponentialRampToValueAtTime(750, now + 0.12);
    gain.gain.setValueAtTime(0.05, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.16);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start(now);
    osc.stop(now + 0.16);
  }

  playError() {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    const now = this.ctx.currentTime;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(140, now);
    gain.gain.setValueAtTime(0.05, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
    osc.connect(gain);
    gain.connect(this.ctx.destination);
    osc.start(now);
    osc.stop(now + 0.12);
  }
}

const sound = new SoundFX();

// ==========================================
// 2. Safe API Fetch Helper (Prevents Unexpected token 'T' JSON errors)
// ==========================================
async function apiCall(endpoint, options = {}) {
  try {
    const res = await fetch(endpoint, options);
    const contentType = res.headers.get('content-type') || '';
    let data = null;

    if (contentType.includes('application/json')) {
      try {
        data = await res.json();
      } catch (jsonErr) {
        throw new Error('Server returned malformed JSON.');
      }
    } else {
      const rawText = await res.text();
      const cleanSnippet = rawText.replace(/<[^>]*>/g, '').trim().slice(0, 80);
      throw new Error(cleanSnippet || `Server error (${res.status})`);
    }

    if (!res.ok) {
      const errorMsg = (data && data.error) ? data.error : `Request failed (${res.status})`;
      const err = new Error(errorMsg);
      err.data = data;
      err.status = res.status;
      throw err;
    }

    return data;
  } catch (err) {
    throw err;
  }
}

// ==========================================
// 3. Web Crypto (PBKDF2 + AES-GCM 256)
// ==========================================
const CryptoVault = {
  bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  },

  base64ToBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  async deriveKey(passphrase, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encrypt(plaintext, passphrase) {
    const enc = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const key = await this.deriveKey(passphrase, salt);
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      enc.encode(plaintext)
    );

    return {
      ciphertext: this.bufferToBase64(ciphertext),
      iv: this.bufferToBase64(iv),
      salt: this.bufferToBase64(salt)
    };
  },

  async decrypt(ciphertextBase64, passphrase, ivBase64, saltBase64) {
    const dec = new TextDecoder();
    const salt = this.base64ToBuffer(saltBase64);
    const iv = this.base64ToBuffer(ivBase64);
    const ciphertext = this.base64ToBuffer(ciphertextBase64);

    const key = await this.deriveKey(passphrase, salt);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    return dec.decode(decrypted);
  }
};

// ==========================================
// 4. Clean Markdown Renderer
// ==========================================
function renderMarkdown(md) {
  if (!md) return '';

  let text = md
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  text = text.replace(/```([\s\S]*?)```/g, (match, code) => `<pre><code>${code.trim()}</code></pre>`);
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  text = text.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  text = text.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  text = text.replace(/^# (.*$)/gim, '<h1>$1</h1>');
  text = text.replace(/^\> (.*$)/gim, '<blockquote>$1</blockquote>');
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  text = text.replace(/^\s*[-*]\s+(.*$)/gim, '<ul><li>$1</li></ul>');
  text = text.replace(/<\/ul>\s*<ul>/g, '');
  text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

  const paragraphs = text.split(/\n{2,}/);
  return paragraphs.map(p => {
    p = p.trim();
    if (!p) return '';
    if (p.startsWith('<h') || p.startsWith('<pre') || p.startsWith('<ul') || p.startsWith('<blockquote')) {
      return p;
    }
    return `<p>${p.replace(/\n/g, '<br>')}</p>`;
  }).join('\n');
}

// ==========================================
// 5. LocalStorage History
// ==========================================
const VaultHistory = {
  KEY: 'vault_minimal_history_v1',

  getAll() {
    try {
      const raw = localStorage.getItem(this.KEY);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  },

  add(item) {
    try {
      let list = this.getAll().filter(v => v.code !== item.code);
      list.unshift({
        code: item.code,
        title: item.title || 'Untitled Note',
        timestamp: Date.now()
      });
      if (list.length > 20) list = list.slice(0, 20);
      localStorage.setItem(this.KEY, JSON.stringify(list));
      renderHistory();
    } catch (e) {
      console.warn('History save error:', e);
    }
  },

  clear() {
    localStorage.removeItem(this.KEY);
    renderHistory();
  }
};

// ==========================================
// 6. DOM Elements Cache
// ==========================================
const el = {
  headerBrand: document.getElementById('header-brand'),
  headerQuickUnlockForm: document.getElementById('header-quick-unlock-form'),
  headerCodeInput: document.getElementById('header-code-input'),
  activeVaultsBadge: document.getElementById('active-vaults-badge'),
  btnToggleSound: document.getElementById('btn-toggle-sound'),
  soundOnSvg: document.getElementById('sound-on-svg'),
  soundOffSvg: document.getElementById('sound-off-svg'),

  workspaceSplit: document.getElementById('workspace-split'),
  viewerContainer: document.getElementById('viewer-container'),

  vaultTitle: document.getElementById('vault-title'),
  vaultContent: document.getElementById('vault-content'),
  btnTogglePreview: document.getElementById('btn-toggle-preview'),
  previewBtnLabel: document.getElementById('preview-btn-label'),
  editorPreviewPane: document.getElementById('editor-preview-pane'),
  btnClearText: document.getElementById('btn-clear-text'),
  statChars: document.getElementById('stat-chars'),
  statWords: document.getElementById('stat-words'),

  createForm: document.getElementById('create-vault-form'),
  vaultCustomCode: document.getElementById('vault-custom-code'),
  btnRegenCode: document.getElementById('btn-regen-code'),
  toggleE2EE: document.getElementById('toggle-e2ee'),
  toggleEnablePin: document.getElementById('toggle-enable-pin'),
  pinDrawer: document.getElementById('pin-input-drawer'),
  vaultPinInput: document.getElementById('vault-pin-input'),
  vaultExpiration: document.getElementById('vault-expiration'),
  toggleBurn: document.getElementById('toggle-burn'),
  toggleAllowEdits: document.getElementById('toggle-allow-edits'),
  btnCreateVault: document.getElementById('btn-create-vault'),

  historyMiniList: document.getElementById('history-mini-list'),
  historyEmptyState: document.getElementById('history-empty-state'),
  btnClearHistory: document.getElementById('btn-clear-history'),

  btnViewerBack: document.getElementById('btn-viewer-back'),
  viewerCodeText: document.getElementById('viewer-code-text'),
  viewerTitleText: document.getElementById('viewer-title-text'),
  viewerBurnBadge: document.getElementById('viewer-burn-badge'),
  viewerExpiryText: document.getElementById('viewer-expiry-text'),
  viewerViewsText: document.getElementById('viewer-views-text'),
  viewerBurnAlert: document.getElementById('viewer-burn-alert'),
  btnCopyUnlocked: document.getElementById('btn-copy-unlocked'),
  copyBtnLabel: document.getElementById('copy-btn-label'),
  btnDownloadUnlocked: document.getElementById('btn-download-unlocked'),
  btnShowQR: document.getElementById('btn-show-qr'),
  btnViewRaw: document.getElementById('btn-view-raw'),
  btnViewMarkdown: document.getElementById('btn-view-markdown'),
  btnEditUnlocked: document.getElementById('btn-edit-unlocked'),
  btnDestroyNow: document.getElementById('btn-destroy-now'),
  unlockedTextRaw: document.getElementById('unlocked-text-raw'),
  unlockedTextRendered: document.getElementById('unlocked-text-rendered'),
  unlockedEditContainer: document.getElementById('unlocked-edit-container'),
  editContentTextarea: document.getElementById('edit-content-textarea'),
  btnSaveEdit: document.getElementById('btn-save-edit'),
  btnCancelEdit: document.getElementById('btn-cancel-edit'),

  successDialog: document.getElementById('success-dialog'),
  modalCodeDisplay: document.getElementById('modal-code-display'),
  btnModalCopyCode: document.getElementById('btn-modal-copy-code'),
  modalCopyCodeLabel: document.getElementById('modal-copy-code-label'),
  modalShareLink: document.getElementById('modal-share-link'),
  btnModalCopyLink: document.getElementById('btn-modal-copy-link'),
  modalQrImg: document.getElementById('modal-qr-img'),
  btnModalOpenNow: document.getElementById('btn-modal-open-now'),
  btnModalClose: document.getElementById('btn-modal-close'),

  pinPromptDialog: document.getElementById('pin-prompt-dialog'),
  pinPromptForm: document.getElementById('pin-prompt-form'),
  pinPromptDesc: document.getElementById('pin-prompt-desc'),
  modalPinInput: document.getElementById('modal-pin-input'),
  btnModalSubmitPin: document.getElementById('btn-modal-submit-pin'),
  btnModalCancelPin: document.getElementById('btn-modal-cancel-pin'),

  qrDialog: document.getElementById('qr-dialog'),
  qrLargeImg: document.getElementById('qr-large-img'),
  qrCodePillText: document.getElementById('qr-code-pill-text'),
  qrDialogSubtitle: document.getElementById('qr-dialog-subtitle'),
  btnQrDialogClose: document.getElementById('btn-qr-dialog-close'),

  toastContainer: document.getElementById('toast-container')
};

// Global state
let currentVault = null;
let countdownTimer = null;
let isPreviewing = false;
let pendingPinCode = null;

// ==========================================
// 7. Toast Notifications
// ==========================================
function toast(message, type = 'info') {
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = message;
  el.toastContainer.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transform = 'translateY(4px)';
    t.style.transition = 'all 0.2s ease';
    setTimeout(() => t.remove(), 200);
  }, 3500);
}

// ==========================================
// 8. Navigation
// ==========================================
function showWorkspace() {
  sound.playClick();
  el.workspaceSplit.classList.remove('hidden');
  el.viewerContainer.classList.add('hidden');
  if (countdownTimer) clearInterval(countdownTimer);
}

function showViewer() {
  el.workspaceSplit.classList.add('hidden');
  el.viewerContainer.classList.remove('hidden');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

el.headerBrand.addEventListener('click', showWorkspace);
el.btnViewerBack.addEventListener('click', showWorkspace);

el.btnToggleSound.addEventListener('click', () => {
  sound.enabled = !sound.enabled;
  el.soundOnSvg.classList.toggle('hidden', !sound.enabled);
  el.soundOffSvg.classList.toggle('hidden', sound.enabled);
  toast(sound.enabled ? 'Audio feedback enabled' : 'Audio muted', 'info');
});

// ==========================================
// 9. Editor Stats & Preview
// ==========================================
function updateStats() {
  const val = el.vaultContent.value;
  el.statChars.textContent = val.length;
  el.statWords.textContent = val.trim() ? val.trim().split(/\s+/).length : 0;
}

el.vaultContent.addEventListener('input', () => {
  updateStats();
  if (isPreviewing) {
    el.editorPreviewPane.innerHTML = renderMarkdown(el.vaultContent.value);
  }
});

el.btnTogglePreview.addEventListener('click', () => {
  sound.playClick();
  isPreviewing = !isPreviewing;
  el.vaultContent.classList.toggle('hidden', isPreviewing);
  el.editorPreviewPane.classList.toggle('hidden', !isPreviewing);

  if (isPreviewing) {
    el.previewBtnLabel.textContent = 'Edit';
    el.editorPreviewPane.innerHTML = renderMarkdown(el.vaultContent.value || '*No content*');
  } else {
    el.previewBtnLabel.textContent = 'Preview';
  }
});

el.btnClearText.addEventListener('click', () => {
  if (el.vaultContent.value && confirm('Clear editor?')) {
    sound.playClick();
    el.vaultContent.value = '';
    updateStats();
    if (isPreviewing) el.editorPreviewPane.innerHTML = '*No content*';
  }
});

const TEMPLATES = {
  secret: `# Confidential Note
- **Date:** ${new Date().toLocaleDateString()}
- **Token:** \`sec_live_${Math.random().toString(36).substring(2, 12)}\`
- **Notice:** This note is protected. Do not share code publicly.`,

  code: `// Secure API Connector
async function queryVault(code) {
  const res = await fetch(\`/api/vaults/\${encodeURIComponent(code)}/meta\`);
  return res.json();
}`,

  creds: `### Staging Credentials
- **Host:** staging.internal.vault:8443
- **User:** admin-ops
- **Password:** Vault-Secret-${Math.floor(1000 + Math.random() * 9000)}`
};

document.querySelectorAll('.btn-chip').forEach(btn => {
  btn.addEventListener('click', () => {
    sound.playClick();
    const type = btn.getAttribute('data-sample');
    if (TEMPLATES[type]) {
      el.vaultContent.value = TEMPLATES[type];
      if (!el.vaultTitle.value) {
        el.vaultTitle.value = type === 'code' ? 'API Connector' : (type === 'creds' ? 'Staging Credentials' : 'Confidential Note');
      }
      updateStats();
      toast('Template loaded', 'info');
    }
  });
});

async function generateFreshCode() {
  try {
    const data = await apiCall('/api/generate-code');
    if (data && data.code) el.vaultCustomCode.value = data.code;
  } catch {
    el.vaultCustomCode.value = 'VAULT-' + Math.floor(1000 + Math.random() * 9000);
  }
}

el.btnRegenCode.addEventListener('click', () => {
  sound.playClick();
  generateFreshCode();
});

el.toggleEnablePin.addEventListener('change', (e) => {
  sound.playClick();
  el.pinDrawer.classList.toggle('hidden', !e.target.checked);
  if (e.target.checked) el.vaultPinInput.focus();
  else el.vaultPinInput.value = '';
});

// ==========================================
// 10. Submit Vault (Creation)
// ==========================================
async function submitVault() {
  const content = el.vaultContent.value.trim();
  if (!content) {
    sound.playError();
    toast('Text content cannot be empty.', 'error');
    el.vaultContent.focus();
    return;
  }

  let code = el.vaultCustomCode.value.trim().toUpperCase();
  const title = el.vaultTitle.value.trim();
  const hasPin = el.toggleEnablePin.checked;
  const pin = hasPin ? el.vaultPinInput.value.trim() : null;
  const useE2EE = el.toggleE2EE.checked;
  const expiresInMinutes = el.vaultExpiration.value;
  const burnAfterRead = el.toggleBurn.checked;
  const allowEdits = el.toggleAllowEdits.checked;

  if (hasPin && (!pin || pin.length < 3)) {
    sound.playError();
    toast('PIN must be at least 3 characters.', 'error');
    el.vaultPinInput.focus();
    return;
  }

  el.btnCreateVault.disabled = true;
  el.btnCreateVault.innerHTML = '<span>Encrypting & Storing...</span>';

  try {
    let payloadContent = content;
    let isEncrypted = false;
    let iv = null;
    let salt = null;

    if (useE2EE) {
      const secret = code + (pin ? `:${pin}` : '');
      const encrypted = await CryptoVault.encrypt(content, secret);
      payloadContent = encrypted.ciphertext;
      iv = encrypted.iv;
      salt = encrypted.salt;
      isEncrypted = true;
    }

    const data = await apiCall('/api/vaults', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        title,
        content: payloadContent,
        isEncrypted,
        iv,
        salt,
        pin,
        expiresInMinutes,
        burnAfterRead,
        allowEdits
      })
    });

    sound.playSuccess();
    toast('Vault created successfully!', 'success');

    VaultHistory.add({ code: data.code, title: data.title });

    el.modalCodeDisplay.textContent = data.code;
    const shareUrl = `${window.location.origin}/#code=${data.code}`;
    el.modalShareLink.value = shareUrl;

    try {
      const qrData = await apiCall(`/api/vaults/${encodeURIComponent(data.code)}/qr`);
      if (qrData && qrData.qr) el.modalQrImg.src = qrData.qr;
    } catch (e) {
      console.warn('QR error:', e);
    }

    el.successDialog.showModal();

    generateFreshCode();
    el.vaultContent.value = '';
    el.vaultTitle.value = '';
    updateStats();
    fetchStats();
  } catch (err) {
    sound.playError();
    toast(err.message, 'error');
  } finally {
    el.btnCreateVault.disabled = false;
    el.btnCreateVault.innerHTML = `
      <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
      <span>Create Protected Vault</span>
    `;
  }
}

el.createForm.addEventListener('submit', (e) => {
  e.preventDefault();
  submitVault();
});

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    if (!el.workspaceSplit.classList.contains('hidden')) {
      submitVault();
    }
  }
});

el.btnModalCopyCode.addEventListener('click', () => {
  sound.playClick();
  const code = el.modalCodeDisplay.textContent;
  navigator.clipboard.writeText(code).then(() => {
    el.modalCopyCodeLabel.textContent = 'COPIED!';
    setTimeout(() => { el.modalCopyCodeLabel.textContent = 'Copy Code'; }, 2000);
    toast(`Code "${code}" copied`, 'success');
  });
});

el.btnModalCopyLink.addEventListener('click', () => {
  sound.playClick();
  navigator.clipboard.writeText(el.modalShareLink.value).then(() => {
    toast('Direct link copied', 'success');
  });
});

el.btnModalOpenNow.addEventListener('click', () => {
  const code = el.modalCodeDisplay.textContent;
  el.successDialog.close();
  unlockCode(code);
});

el.btnModalClose.addEventListener('click', () => {
  sound.playClick();
  el.successDialog.close();
});

// ==========================================
// 11. Unlock Vault
// ==========================================
el.headerQuickUnlockForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const code = el.headerCodeInput.value.trim().toUpperCase();
  if (!code) {
    sound.playError();
    toast('Please enter a code to unlock', 'error');
    el.headerCodeInput.focus();
    return;
  }
  unlockCode(code);
});

async function unlockCode(code, providedPin = null) {
  if (!code || typeof code !== 'string' || !code.trim()) {
    toast('Please enter a valid vault code.', 'error');
    return;
  }
  code = code.trim().toUpperCase();

  try {
    // 1. Check meta first
    const metaData = await apiCall(`/api/vaults/${encodeURIComponent(code)}/meta`);

    if (metaData.hasPin && !providedPin) {
      pendingPinCode = code;
      el.pinPromptDesc.textContent = `Vault ${code} is PIN protected. Enter PIN below:`;
      el.modalPinInput.value = '';
      el.pinPromptDialog.showModal();
      el.modalPinInput.focus();
      return;
    }

    // 2. Perform Unlock Request
    let unlockData;
    try {
      unlockData = await apiCall(`/api/vaults/${encodeURIComponent(code)}/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: providedPin || undefined })
      });
    } catch (unlockErr) {
      if (unlockErr.data && unlockErr.data.requiresPin) {
        pendingPinCode = code;
        el.pinPromptDialog.showModal();
        el.modalPinInput.focus();
        return;
      }
      throw unlockErr;
    }

    const vault = unlockData.vault;
    let decryptedText = vault.content;

    // 3. Client Decryption if E2EE was used
    if (vault.isEncrypted) {
      try {
        const secret = code + (providedPin ? `:${providedPin}` : '');
        decryptedText = await CryptoVault.decrypt(vault.content, secret, vault.iv, vault.salt);
      } catch {
        throw new Error('Decryption failed. The code or PIN may be incorrect.');
      }
    }

    sound.playUnlock();
    toast('Vault unlocked!', 'success');

    currentVault = {
      ...vault,
      decryptedText,
      pin: providedPin
    };

    VaultHistory.add({ code: vault.code, title: vault.title });

    renderViewer(currentVault);
    showViewer();
  } catch (err) {
    sound.playError();
    toast(err.message, 'error');
  }
}

el.pinPromptForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const pin = el.modalPinInput.value.trim();
  if (!pin) return;
  el.pinPromptDialog.close();
  if (pendingPinCode) {
    unlockCode(pendingPinCode, pin);
  }
});

el.btnModalCancelPin.addEventListener('click', () => {
  el.pinPromptDialog.close();
  pendingPinCode = null;
});

function renderViewer(vault) {
  el.viewerCodeText.textContent = vault.code;
  el.viewerTitleText.textContent = vault.title || 'Untitled Note';
  el.viewerViewsText.textContent = `${vault.viewsCount} ${vault.viewsCount === 1 ? 'view' : 'views'}`;

  if (vault.burned) {
    el.viewerBurnBadge.classList.remove('hidden');
    el.viewerBurnAlert.classList.remove('hidden');
  } else {
    el.viewerBurnBadge.classList.add('hidden');
    el.viewerBurnAlert.classList.add('hidden');
  }

  el.unlockedTextRaw.textContent = vault.decryptedText;
  el.unlockedTextRendered.innerHTML = renderMarkdown(vault.decryptedText);

  el.unlockedTextRaw.classList.remove('hidden');
  el.unlockedTextRendered.classList.add('hidden');
  el.unlockedEditContainer.classList.add('hidden');
  el.btnViewRaw.classList.add('active');
  el.btnViewMarkdown.classList.remove('active');

  el.btnEditUnlocked.classList.toggle('hidden', !vault.allowEdits || Boolean(vault.burned));
  el.btnDestroyNow.classList.toggle('hidden', Boolean(vault.burned));

  if (countdownTimer) clearInterval(countdownTimer);
  if (!vault.expiresAt) {
    el.viewerExpiryText.textContent = 'Never Expires';
  } else {
    const updateCountdown = () => {
      const diff = vault.expiresAt - Date.now();
      if (diff <= 0) {
        clearInterval(countdownTimer);
        el.viewerExpiryText.textContent = 'Expired';
        toast('This vault has expired', 'error');
        return;
      }
      const m = Math.floor(diff / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      el.viewerExpiryText.textContent = `Expires: ${m}m ${s}s`;
    };
    updateCountdown();
    countdownTimer = setInterval(updateCountdown, 1000);
  }
}

// Viewer Actions
el.btnCopyUnlocked.addEventListener('click', () => {
  if (!currentVault) return;
  sound.playClick();
  navigator.clipboard.writeText(currentVault.decryptedText).then(() => {
    el.copyBtnLabel.textContent = 'Copied!';
    setTimeout(() => { el.copyBtnLabel.textContent = 'Copy Text'; }, 2000);
    toast('Text copied to clipboard', 'success');
  });
});

el.btnDownloadUnlocked.addEventListener('click', () => {
  if (!currentVault) return;
  sound.playClick();
  const text = currentVault.decryptedText;
  const isMd = text.startsWith('#') || text.includes('```');
  const filename = `${currentVault.code.toLowerCase()}.${isMd ? 'md' : 'txt'}`;
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast(`Downloaded ${filename}`, 'info');
});

el.btnShowQR.addEventListener('click', async () => {
  if (!currentVault) return;
  sound.playClick();
  try {
    const data = await apiCall(`/api/vaults/${encodeURIComponent(currentVault.code)}/qr`);
    if (data && data.qr) {
      el.qrLargeImg.src = data.qr;
      el.qrCodePillText.textContent = currentVault.code;
      el.qrDialogSubtitle.textContent = `Direct access code: ${currentVault.code}`;
      el.qrDialog.showModal();
    }
  } catch {
    toast('Could not generate QR', 'error');
  }
});

el.btnQrDialogClose.addEventListener('click', () => el.qrDialog.close());

el.btnViewRaw.addEventListener('click', () => {
  sound.playClick();
  el.btnViewRaw.classList.add('active');
  el.btnViewMarkdown.classList.remove('active');
  el.unlockedTextRaw.classList.remove('hidden');
  el.unlockedTextRendered.classList.add('hidden');
  el.unlockedEditContainer.classList.add('hidden');
});

el.btnViewMarkdown.addEventListener('click', () => {
  sound.playClick();
  el.btnViewMarkdown.classList.add('active');
  el.btnViewRaw.classList.remove('active');
  el.unlockedTextRaw.classList.add('hidden');
  el.unlockedTextRendered.classList.remove('hidden');
  el.unlockedEditContainer.classList.add('hidden');
});

el.btnEditUnlocked.addEventListener('click', () => {
  sound.playClick();
  const isEditing = !el.unlockedEditContainer.classList.contains('hidden');
  if (isEditing) {
    el.unlockedEditContainer.classList.add('hidden');
    el.unlockedTextRaw.classList.remove('hidden');
    el.btnViewRaw.classList.add('active');
    el.btnEditUnlocked.textContent = 'Edit';
  } else {
    el.editContentTextarea.value = currentVault.decryptedText;
    el.unlockedEditContainer.classList.remove('hidden');
    el.unlockedTextRaw.classList.add('hidden');
    el.unlockedTextRendered.classList.add('hidden');
    el.btnViewRaw.classList.remove('active');
    el.btnViewMarkdown.classList.remove('active');
    el.btnEditUnlocked.textContent = 'Cancel';
    el.editContentTextarea.focus();
  }
});

el.btnCancelEdit.addEventListener('click', () => {
  sound.playClick();
  el.unlockedEditContainer.classList.add('hidden');
  el.unlockedTextRaw.classList.remove('hidden');
  el.btnViewRaw.classList.add('active');
  el.btnEditUnlocked.textContent = 'Edit';
});

el.btnSaveEdit.addEventListener('click', async () => {
  if (!currentVault) return;
  const newContent = el.editContentTextarea.value.trim();
  if (!newContent) {
    toast('Content cannot be empty', 'error');
    return;
  }

  el.btnSaveEdit.disabled = true;
  el.btnSaveEdit.textContent = 'Saving...';

  try {
    let payload = newContent;
    let iv = null;
    let salt = null;

    if (currentVault.isEncrypted) {
      const secret = currentVault.code + (currentVault.pin ? `:${currentVault.pin}` : '');
      const encrypted = await CryptoVault.encrypt(newContent, secret);
      payload = encrypted.ciphertext;
      iv = encrypted.iv;
      salt = encrypted.salt;
    }

    await apiCall(`/api/vaults/${encodeURIComponent(currentVault.code)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: payload,
        pin: currentVault.pin,
        isEncrypted: currentVault.isEncrypted,
        iv,
        salt
      })
    });

    currentVault.decryptedText = newContent;
    el.unlockedTextRaw.textContent = newContent;
    el.unlockedTextRendered.innerHTML = renderMarkdown(newContent);

    el.unlockedEditContainer.classList.add('hidden');
    el.unlockedTextRaw.classList.remove('hidden');
    el.btnViewRaw.classList.add('active');
    el.btnEditUnlocked.textContent = 'Edit';

    sound.playSuccess();
    toast('Cloud changes saved', 'success');
  } catch (err) {
    sound.playError();
    toast(err.message, 'error');
  } finally {
    el.btnSaveEdit.disabled = false;
    el.btnSaveEdit.textContent = 'Save Changes';
  }
});

el.btnDestroyNow.addEventListener('click', async () => {
  if (!currentVault) return;
  if (!confirm(`Permanently delete vault ${currentVault.code}?`)) return;

  try {
    await apiCall(`/api/vaults/${encodeURIComponent(currentVault.code)}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin: currentVault.pin })
    });

    sound.playSuccess();
    toast(`Vault ${currentVault.code} deleted`, 'info');
    showWorkspace();
    currentVault = null;
    fetchStats();
    renderHistory();
  } catch (err) {
    sound.playError();
    toast(err.message, 'error');
  }
});

// ==========================================
// 12. History Mini List
// ==========================================
function renderHistory() {
  const list = VaultHistory.getAll();
  if (list.length === 0) {
    el.historyEmptyState.classList.remove('hidden');
    el.historyMiniList.innerHTML = '';
    el.historyMiniList.appendChild(el.historyEmptyState);
    return;
  }

  el.historyEmptyState.classList.add('hidden');
  el.historyMiniList.innerHTML = '';

  list.forEach(item => {
    const row = document.createElement('div');
    row.className = 'history-mini-item';
    row.innerHTML = `
      <span class="history-mini-code">${item.code}</span>
      <span class="history-mini-title">${item.title}</span>
    `;
    row.addEventListener('click', () => {
      sound.playClick();
      unlockCode(item.code);
    });
    el.historyMiniList.appendChild(row);
  });
}

el.btnClearHistory.addEventListener('click', () => {
  if (confirm('Clear local history?')) {
    sound.playClick();
    VaultHistory.clear();
    toast('History cleared', 'info');
  }
});

[el.successDialog, el.pinPromptDialog, el.qrDialog].forEach(dialog => {
  dialog.addEventListener('click', (e) => {
    const rect = dialog.getBoundingClientRect();
    const inDialog = (rect.top <= e.clientY && e.clientY <= rect.top + rect.height &&
      rect.left <= e.clientX && e.clientX <= rect.left + rect.width);
    if (!inDialog) dialog.close();
  });
});

// ==========================================
// 13. Deep Linking & Stats
// ==========================================
function checkDeepLink() {
  const hash = window.location.hash;
  const search = window.location.search;
  let code = null;

  const match = hash.match(/#code=([A-Za-z0-9_-]+)/i) || hash.match(/#vault=([A-Za-z0-9_-]+)/i);
  if (match) {
    code = match[1];
  } else {
    const params = new URLSearchParams(search);
    code = params.get('code') || params.get('vault');
  }

  if (code) {
    code = code.trim().toUpperCase();
    el.headerCodeInput.value = code;
    setTimeout(() => unlockCode(code), 300);
  }
}

async function fetchStats() {
  try {
    const data = await apiCall('/api/stats');
    if (data && data.activeVaults !== undefined) {
      el.activeVaultsBadge.textContent = `${data.activeVaults} active ${data.activeVaults === 1 ? 'vault' : 'vaults'}`;
    }
  } catch {
    el.activeVaultsBadge.textContent = 'Cloud Online';
  }
}

// Initial Boot
window.addEventListener('DOMContentLoaded', () => {
  generateFreshCode();
  updateStats();
  renderHistory();
  fetchStats();
  checkDeepLink();
  setInterval(fetchStats, 30000);
});
