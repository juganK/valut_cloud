const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();

// Determine environment & writable data path (Vercel serverless requires /tmp)
const isVercel = Boolean(process.env.VERCEL);
const DATA_DIR = isVercel ? '/tmp' : path.join(__dirname, '..', 'data');
const DB_FILE = path.join(DATA_DIR, 'vaults.json');

// Ensure data directory exists
try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
} catch (e) {
  console.warn('Data dir notice:', e.message);
}

// In-memory cache + file-backed storage
let vaults = {};

function loadVaults() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf-8');
      vaults = JSON.parse(raw);
    }
  } catch (err) {
    // If empty or corrupted, keep current in-memory cache
  }
  return vaults;
}

function saveVaults() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(vaults), 'utf-8');
  } catch (err) {
    console.warn('Persistence notice:', err.message);
  }
}

// Optional Vercel KV / Upstash Redis Support (For 100% persistent global serverless storage)
const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

async function kvGet(code) {
  if (!kvUrl || !kvToken) return null;
  try {
    const res = await fetch(`${kvUrl}/get/vault:${encodeURIComponent(code)}`, {
      headers: { Authorization: `Bearer ${kvToken}` }
    });
    const json = await res.json();
    if (json.result) {
      return typeof json.result === 'string' ? JSON.parse(json.result) : json.result;
    }
  } catch (e) {
    console.warn('KV Get notice:', e.message);
  }
  return null;
}

async function kvSet(code, vaultData, ttlSeconds = null) {
  if (!kvUrl || !kvToken) return false;
  try {
    let url = `${kvUrl}/set/vault:${encodeURIComponent(code)}/${encodeURIComponent(JSON.stringify(vaultData))}`;
    if (ttlSeconds && ttlSeconds > 0) {
      url += `?ex=${ttlSeconds}`;
    }
    await fetch(url, {
      headers: { Authorization: `Bearer ${kvToken}` }
    });
    return true;
  } catch (e) {
    console.warn('KV Set notice:', e.message);
    return false;
  }
}

async function kvDel(code) {
  if (!kvUrl || !kvToken) return false;
  try {
    await fetch(`${kvUrl}/del/vault:${encodeURIComponent(code)}`, {
      headers: { Authorization: `Bearer ${kvToken}` }
    });
    return true;
  } catch (e) {
    return false;
  }
}

// Unified Get Vault Helper (KV -> File -> Memory)
async function getVaultRecord(code) {
  code = (code || '').trim().toUpperCase();
  if (!code) return null;

  // 1. Try Vercel KV first if connected
  const remote = await kvGet(code);
  if (remote) return remote;

  // 2. Try Local / /tmp disk
  loadVaults();
  return vaults[code] || null;
}

// Unified Save Vault Helper
async function saveVaultRecord(code, record, ttlSeconds = null) {
  code = (code || '').trim().toUpperCase();
  vaults[code] = record;
  saveVaults();
  await kvSet(code, record, ttlSeconds);
}

// Unified Delete Vault Helper
async function deleteVaultRecord(code) {
  code = (code || '').trim().toUpperCase();
  delete vaults[code];
  saveVaults();
  await kvDel(code);
}

// Initial load
loadVaults();

// Helper for hashing PINs
function hashPin(pin, salt) {
  return crypto.pbkdf2Sync(pin, salt, 10000, 32, 'sha256').toString('hex');
}

function generateRandomCode() {
  const prefixes = ['VAULT', 'CIPHER', 'LOCK', 'SHIELD', 'DROP', 'NEXUS', 'GHOST'];
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
  const num = Math.floor(1000 + Math.random() * 9000);
  return `${prefix}-${num}`;
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// 1. Server Stats & Health
app.get('/api/stats', async (req, res) => {
  loadVaults();
  const activeCount = Object.keys(vaults).length;
  res.json({
    status: 'online',
    platform: isVercel ? 'vercel-serverless' : 'nodejs-local',
    kvEnabled: Boolean(kvUrl && kvToken),
    activeVaults: activeCount,
    uptime: Math.floor(process.uptime()),
    timestamp: Date.now()
  });
});

// 2. Generate Suggested Code
app.get('/api/generate-code', async (req, res) => {
  let code = generateRandomCode();
  let existing = await getVaultRecord(code);
  let attempts = 0;
  while (existing && attempts < 10) {
    code = generateRandomCode();
    existing = await getVaultRecord(code);
    attempts++;
  }
  res.json({ code });
});

// 3. Create a new Vault
app.post('/api/vaults', async (req, res) => {
  try {
    let {
      code,
      title,
      content,
      isEncrypted,
      iv,
      salt,
      pin,
      expiresInMinutes,
      burnAfterRead,
      allowEdits
    } = req.body;

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      return res.status(400).json({ error: 'Text content cannot be empty.' });
    }

    if (code && typeof code === 'string') {
      code = code.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
      if (code.length < 2 || code.length > 32) {
        return res.status(400).json({ error: 'Code must be between 2 and 32 characters.' });
      }
      const existing = await getVaultRecord(code);
      if (existing) {
        if (existing.expiresAt && existing.expiresAt <= Date.now()) {
          await deleteVaultRecord(code);
        } else {
          return res.status(409).json({ error: `The code "${code}" is already in use. Please pick another code.` });
        }
      }
    } else {
      code = generateRandomCode();
    }

    let pinHash = null;
    let pinSalt = null;
    if (pin && typeof pin === 'string' && pin.trim().length > 0) {
      pinSalt = crypto.randomBytes(16).toString('hex');
      pinHash = hashPin(pin.trim(), pinSalt);
    }

    let expiresAt = null;
    let ttlSeconds = null;
    const expMins = parseInt(expiresInMinutes, 10);
    if (!isNaN(expMins) && expMins > 0) {
      expiresAt = Date.now() + expMins * 60 * 1000;
      ttlSeconds = expMins * 60;
    }

    const newVault = {
      code,
      title: (title && typeof title === 'string') ? title.trim().slice(0, 100) : 'Untitled Vault',
      content,
      isEncrypted: Boolean(isEncrypted),
      iv: iv || null,
      salt: salt || null,
      hasPin: Boolean(pinHash),
      pinHash,
      pinSalt,
      createdAt: Date.now(),
      expiresAt,
      burnAfterRead: Boolean(burnAfterRead),
      allowEdits: Boolean(allowEdits),
      viewsCount: 0
    };

    await saveVaultRecord(code, newVault, ttlSeconds);

    return res.status(201).json({
      success: true,
      code,
      title: newVault.title,
      hasPin: newVault.hasPin,
      isEncrypted: newVault.isEncrypted,
      expiresAt,
      burnAfterRead: newVault.burnAfterRead,
      allowEdits: newVault.allowEdits,
      createdAt: newVault.createdAt
    });
  } catch (err) {
    console.error('Error creating vault:', err);
    res.status(500).json({ error: 'Internal server error while saving vault.' });
  }
});

// 4. Get Vault Metadata (Check existence without revealing text or burning)
app.get('/api/vaults/:code/meta', async (req, res) => {
  const code = (req.params.code || '').trim().toUpperCase();
  const vault = await getVaultRecord(code);

  if (!vault) {
    return res.status(404).json({ error: 'Vault not found or may have expired.' });
  }

  if (vault.expiresAt && vault.expiresAt <= Date.now()) {
    await deleteVaultRecord(code);
    return res.status(404).json({ error: 'This vault has expired and is no longer available.' });
  }

  res.json({
    exists: true,
    code: vault.code,
    title: vault.title,
    hasPin: vault.hasPin,
    isEncrypted: vault.isEncrypted,
    salt: vault.salt,
    iv: vault.iv,
    expiresAt: vault.expiresAt,
    burnAfterRead: vault.burnAfterRead,
    allowEdits: vault.allowEdits,
    viewsCount: vault.viewsCount,
    createdAt: vault.createdAt
  });
});

// 5. Unlock & Retrieve Vault Content
app.post('/api/vaults/:code/unlock', async (req, res) => {
  try {
    const code = (req.params.code || '').trim().toUpperCase();
    const vault = await getVaultRecord(code);

    if (!vault) {
      return res.status(404).json({ error: 'Vault not found, already burned, or expired.' });
    }

    if (vault.expiresAt && vault.expiresAt <= Date.now()) {
      await deleteVaultRecord(code);
      return res.status(404).json({ error: 'This vault has expired.' });
    }

    if (vault.hasPin) {
      const { pin } = req.body;
      if (!pin || typeof pin !== 'string') {
        return res.status(401).json({ error: 'PIN required to unlock this vault.', requiresPin: true });
      }

      const testHash = hashPin(pin.trim(), vault.pinSalt);
      if (testHash !== vault.pinHash) {
        return res.status(403).json({ error: 'Incorrect PIN. Access denied.' });
      }
    }

    vault.viewsCount = (vault.viewsCount || 0) + 1;
    const isBurned = vault.burnAfterRead;

    const payload = {
      code: vault.code,
      title: vault.title,
      content: vault.content,
      isEncrypted: vault.isEncrypted,
      iv: vault.iv,
      salt: vault.salt,
      allowEdits: vault.allowEdits,
      viewsCount: vault.viewsCount,
      expiresAt: vault.expiresAt,
      createdAt: vault.createdAt,
      burned: isBurned
    };

    if (isBurned) {
      await deleteVaultRecord(code);
    } else {
      let ttlSeconds = null;
      if (vault.expiresAt) {
        ttlSeconds = Math.max(1, Math.floor((vault.expiresAt - Date.now()) / 1000));
      }
      await saveVaultRecord(code, vault, ttlSeconds);
    }

    return res.json({
      success: true,
      vault: payload
    });
  } catch (err) {
    console.error('Error unlocking vault:', err);
    res.status(500).json({ error: 'Internal server error while unlocking vault.' });
  }
});

// 6. Update Vault (collaborative)
app.put('/api/vaults/:code', async (req, res) => {
  try {
    const code = (req.params.code || '').trim().toUpperCase();
    const vault = await getVaultRecord(code);

    if (!vault) {
      return res.status(404).json({ error: 'Vault not found.' });
    }

    if (!vault.allowEdits) {
      return res.status(403).json({ error: 'This vault is read-only.' });
    }

    if (vault.hasPin) {
      const { pin } = req.body;
      if (!pin || typeof pin !== 'string') {
        return res.status(401).json({ error: 'PIN required to edit this vault.' });
      }
      const testHash = hashPin(pin.trim(), vault.pinSalt);
      if (testHash !== vault.pinHash) {
        return res.status(403).json({ error: 'Incorrect PIN. Edit denied.' });
      }
    }

    const { content, title, isEncrypted, iv, salt } = req.body;
    if (!content || typeof content !== 'string') {
      return res.status(400).json({ error: 'Content cannot be empty.' });
    }

    vault.content = content;
    if (title) vault.title = title.trim().slice(0, 100);
    if (isEncrypted !== undefined) vault.isEncrypted = Boolean(isEncrypted);
    if (iv !== undefined) vault.iv = iv;
    if (salt !== undefined) vault.salt = salt;
    vault.updatedAt = Date.now();

    let ttlSeconds = null;
    if (vault.expiresAt) {
      ttlSeconds = Math.max(1, Math.floor((vault.expiresAt - Date.now()) / 1000));
    }
    await saveVaultRecord(code, vault, ttlSeconds);

    return res.json({
      success: true,
      message: 'Vault updated successfully.',
      updatedAt: vault.updatedAt
    });
  } catch (err) {
    console.error('Error updating vault:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 7. Delete Vault
app.delete('/api/vaults/:code', async (req, res) => {
  const code = (req.params.code || '').trim().toUpperCase();
  const vault = await getVaultRecord(code);

  if (!vault) {
    return res.status(404).json({ error: 'Vault not found.' });
  }

  if (vault.hasPin) {
    const { pin } = req.body;
    if (!pin || typeof pin !== 'string') {
      return res.status(401).json({ error: 'PIN required to delete this vault.' });
    }
    const testHash = hashPin(pin.trim(), vault.pinSalt);
    if (testHash !== vault.pinHash) {
      return res.status(403).json({ error: 'Incorrect PIN. Delete denied.' });
    }
  }

  await deleteVaultRecord(code);
  res.json({ success: true, message: `Vault ${code} deleted.` });
});

// 8. Generate QR Code
app.get('/api/vaults/:code/qr', async (req, res) => {
  try {
    const code = (req.params.code || '').trim().toUpperCase();
    const host = req.get('host');
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const url = `${protocol}://${host}/#code=${code}`;

    const qrDataUrl = await QRCode.toDataURL(url, {
      errorCorrectionLevel: 'M',
      margin: 2,
      color: {
        dark: '#ffffff',
        light: '#0a0d14'
      },
      width: 280
    });

    res.json({ success: true, qr: qrDataUrl, url, code });
  } catch (err) {
    console.error('Error generating QR:', err);
    res.status(500).json({ error: 'Failed to generate QR code.' });
  }
});

// Catch-all for /api routes - ALWAYS return JSON
app.use('/api', (req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.originalUrl}` });
});

// Serve frontend for non-API client routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  if (req.path && req.path.startsWith('/api')) {
    return res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
  }
  res.status(500).sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

module.exports = app;
