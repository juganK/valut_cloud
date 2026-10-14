const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'vaults.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory vaults store backed by atomic file writes
let vaults = {};

function loadVaults() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf-8');
      vaults = JSON.parse(raw);
    } else {
      vaults = {};
      saveVaults();
    }
  } catch (err) {
    console.error('Error loading vaults database, initializing fresh store:', err.message);
    vaults = {};
  }
}

function saveVaults() {
  try {
    const tempFile = `${DB_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tempFile, JSON.stringify(vaults, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Error persisting vaults to disk:', err.message);
  }
}

loadVaults();

// Clean up expired vaults every 30 seconds
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const code of Object.keys(vaults)) {
    if (vaults[code].expiresAt && vaults[code].expiresAt <= now) {
      delete vaults[code];
      changed = true;
    }
  }
  if (changed) {
    saveVaults();
  }
}, 30000);

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
app.use(express.static(path.join(__dirname, 'public')));

// API Routes

// 1. Server Stats & Health
app.get('/api/stats', (req, res) => {
  const activeCount = Object.keys(vaults).length;
  res.json({
    status: 'online',
    activeVaults: activeCount,
    uptime: Math.floor(process.uptime()),
    timestamp: Date.now()
  });
});

// 2. Generate Suggested Code
app.get('/api/generate-code', (req, res) => {
  let code = generateRandomCode();
  while (vaults[code]) {
    code = generateRandomCode();
  }
  res.json({ code });
});

// 3. Create a new Vault
app.post('/api/vaults', (req, res) => {
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

    // Process or sanitize code
    if (code && typeof code === 'string') {
      code = code.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
      if (code.length < 2 || code.length > 32) {
        return res.status(400).json({ error: 'Code must be between 2 and 32 characters (letters, numbers, hyphen, underscore).' });
      }
      if (vaults[code]) {
        // Check if existing vault is already expired
        if (vaults[code].expiresAt && vaults[code].expiresAt <= Date.now()) {
          delete vaults[code];
        } else {
          return res.status(409).json({ error: `The code "${code}" is already in use. Please choose another code or generate a random one.` });
        }
      }
    } else {
      code = generateRandomCode();
      while (vaults[code]) {
        code = generateRandomCode();
      }
    }

    // Process PIN protection
    let pinHash = null;
    let pinSalt = null;
    if (pin && typeof pin === 'string' && pin.trim().length > 0) {
      pinSalt = crypto.randomBytes(16).toString('hex');
      pinHash = hashPin(pin.trim(), pinSalt);
    }

    // Expiration calculation
    let expiresAt = null;
    const expMins = parseInt(expiresInMinutes, 10);
    if (!isNaN(expMins) && expMins > 0) {
      expiresAt = Date.now() + expMins * 60 * 1000;
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

    vaults[code] = newVault;
    saveVaults();

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

// 4. Get Vault Metadata (Check existence & security requirement without revealing text or burning)
app.get('/api/vaults/:code/meta', (req, res) => {
  const code = (req.params.code || '').trim().toUpperCase();
  const vault = vaults[code];

  if (!vault) {
    return res.status(404).json({ error: 'Vault not found or may have expired.' });
  }

  // Check expiration
  if (vault.expiresAt && vault.expiresAt <= Date.now()) {
    delete vaults[code];
    saveVaults();
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
app.post('/api/vaults/:code/unlock', (req, res) => {
  try {
    const code = (req.params.code || '').trim().toUpperCase();
    const vault = vaults[code];

    if (!vault) {
      return res.status(404).json({ error: 'Vault not found, already burned, or expired.' });
    }

    // Check expiration
    if (vault.expiresAt && vault.expiresAt <= Date.now()) {
      delete vaults[code];
      saveVaults();
      return res.status(404).json({ error: 'This vault has expired.' });
    }

    // Check PIN if required
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

    // Increment view count
    vault.viewsCount += 1;
    const isBurned = vault.burnAfterRead;

    // Snapshot payload
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

    // If burn after read is active, purge immediately after first successful retrieval!
    if (isBurned) {
      delete vaults[code];
    }

    saveVaults();

    return res.json({
      success: true,
      vault: payload
    });
  } catch (err) {
    console.error('Error unlocking vault:', err);
    res.status(500).json({ error: 'Internal server error while unlocking vault.' });
  }
});

// 6. Update Vault (for collaborative / editable text)
app.put('/api/vaults/:code', (req, res) => {
  try {
    const code = (req.params.code || '').trim().toUpperCase();
    const vault = vaults[code];

    if (!vault) {
      return res.status(404).json({ error: 'Vault not found.' });
    }

    if (!vault.allowEdits) {
      return res.status(403).json({ error: 'This vault is read-only and does not allow edits.' });
    }

    // Check PIN if required
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

    saveVaults();

    return res.json({
      success: true,
      message: 'Vault updated successfully.',
      updatedAt: vault.updatedAt
    });
  } catch (err) {
    console.error('Error updating vault:', err);
    res.status(500).json({ error: 'Internal server error while updating vault.' });
  }
});

// 7. Delete / Self-Destruct Vault
app.delete('/api/vaults/:code', (req, res) => {
  const code = (req.params.code || '').trim().toUpperCase();
  const vault = vaults[code];

  if (!vault) {
    return res.status(404).json({ error: 'Vault not found.' });
  }

  // Check PIN if required
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

  delete vaults[code];
  saveVaults();

  res.json({ success: true, message: `Vault ${code} has been permanently destroyed.` });
});

// 8. Generate QR Code image for easy mobile access
app.get('/api/vaults/:code/qr', async (req, res) => {
  try {
    const code = (req.params.code || '').trim().toUpperCase();
    const host = req.get('host');
    const protocol = req.protocol;
    const url = `${protocol}://${host}/#code=${code}`;

    const qrDataUrl = await QRCode.toDataURL(url, {
      errorCorrectionLevel: 'M',
      margin: 2,
      color: {
        dark: '#00f0ff',
        light: '#0a0d14'
      },
      width: 320
    });

    res.json({ success: true, qr: qrDataUrl, url, code });
  } catch (err) {
    console.error('Error generating QR:', err);
    res.status(500).json({ error: 'Failed to generate QR code.' });
  }
});

// Catch-all for any unhandled /api routes - ALWAYS return JSON
app.use('/api', (req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.originalUrl}` });
});

// Serve frontend for all non-API routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  if (req.path && req.path.startsWith('/api/')) {
    return res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
  }
  res.status(500).sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🔒 VaultDrop Cloud Text Server Running!`);
  console.log(`📍 Local:   http://localhost:${PORT}`);
  console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
  console.log(`===============================================`);
});
