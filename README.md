# CipherVault - Secure Cloud Text Sharing with Code Protection

A modern, high-security cloud text sharing web application. Store sensitive texts, code snippets, memos, or credentials with custom code protection, PIN locks, zero-knowledge client-side AES-256 encryption, and self-destructing burn-after-reading.

![CipherVault Preview](public/favicon.svg)

---

## ✨ Features

- **🔐 Code Protection**: Secure any text behind an auto-generated or custom access code (e.g., `VAULT-8491` or `MY-SECRET-2026`). Anyone with the code can view it.
- **🛡️ Two-Factor PIN Protection**: Optional secondary PIN/password for high-security notes.
- **⚡ Zero-Knowledge AES-256-GCM Encryption**: Text is encrypted right in the browser using the Web Crypto API before reaching the cloud. The server never sees the raw plaintext.
- **🔥 Burn After Reading**: Self-destructs the note permanently from cloud storage immediately after the first person reads it.
- **⏳ Auto Expiration**: Choose between 10 minutes, 1 hour, 24 hours, 7 days, or permanent storage. Expired vaults are purged automatically.
- **🤝 Collaborative Editing**: Optional toggle to allow anyone with the code to edit and update text collaboratively in real-time.
- **📱 Instant QR Code & Direct Links**: Generates instant QR codes for mobile phone camera scanning and one-click shareable URLs (`http://localhost:3000/#code=YOUR-CODE`).
- **📝 Markdown & Raw Syntax Viewer**: Full support for headers, code blocks, lists, quotes, character/word counters, and one-click file downloading (`.txt` / `.md`).
- **🎵 Synthesized Cyber Audio**: Web Audio API feedback for clicks, unlocks, errors, and success chimes (with mute toggle).
- **📂 Device History**: Keeps a local history of vaults you've created or visited on this browser.

---

## 🚀 Quick Start

### 1. Run the App
```powershell
cd C:\Users\jugan\.gemini\antigravity-ide\scratch\cloud-text-vault
npm start
```

### 2. Open in Your Browser
Visit [http://localhost:3000](http://localhost:3000)

To share across devices on your local Wi-Fi, open:
`http://<YOUR_LOCAL_IP>:3000` (e.g. `http://192.168.1.15:3000`)

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Server uptime and active vault counter |
| `GET` | `/api/generate-code` | Get an available random code suggestion |
| `POST` | `/api/vaults` | Create and store a new cloud vault |
| `GET` | `/api/vaults/:code/meta` | Check vault status, PIN requirement, expiration |
| `POST` | `/api/vaults/:code/unlock` | Validate PIN/code and retrieve text |
| `PUT` | `/api/vaults/:code` | Update an existing collaborative vault |
| `DELETE` | `/api/vaults/:code` | Manually destroy a vault from storage |
| `GET` | `/api/vaults/:code/qr` | Get PNG QR Code Data URL for mobile scanning |

---

## 📁 Project Structure

```
cloud-text-vault/
├── package.json         # Project metadata and dependencies
├── server.js            # Express API server with atomic persistence & cleanup
├── data/
│   └── vaults.json      # Persistent storage database
├── public/
│   ├── index.html       # Semantic HTML5 UI with tabs and modals
│   ├── style.css        # Obsidian / Cyberpunk Glassmorphism design system
│   ├── app.js           # Client Web Crypto, Audio synth, and UI controller
│   └── favicon.svg      # Cyber shield logo
└── README.md            # Documentation
```
