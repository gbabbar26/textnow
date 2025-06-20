# 🔐 TextNow: Secure Chat Application

A fully secure, real-time messaging system built using **AES-GCM**, **ECDSA**, and **ECDH**, designed as a course project for **Applied Cryptography @ NYU (Spring 2025)**. This project replicates the architecture of real-world encrypted platforms like Signal and WhatsApp — with authentication, replay protection, and GUI-based communication.

> [Final Report]>(./report/TextNow_Final_Report.docx)**


---

## Features

- ✅ AES-GCM for confidentiality + integrity
- ✅ ECDH for secure key exchange (perfect forward secrecy)
- ✅ ECDSA for digital signatures and authentication
- ✅ Nonce + Timestamp for replay protection
- ✅ GUI chat window using Tkinter
- ✅ Message logging & forensic verification
- ✅ Offline verification tools (CLI + GUI)

---

## 🛠 Components

| File | Purpose |
|------|---------|
| `client.py` | Chat client (sender side) |
| `server.py` | Message relay server |
| `chat_gui.py` | GUI interface for client |
| `crypto_utils.py` | Key gen, sign, encrypt/decrypt |
| `verify_payload.py` | CLI tool for message validation |
| `verify_payload_gui.py` | GUI for offline payload verification |
| `payloads/` | JSON logs for all messages |
| `keys/` | Private/public key storage |

---

## 🛡️ Security Design

| Security Goal | Protocol |
|---------------|----------|
| Confidentiality | AES-256-GCM |
| Authenticity | ECDSA (Digital Signature) |
| Integrity | GCM tag + Signature |
| Replay Protection | Nonce + Timestamp tracking |
| Key Exchange | ECDH with ephemeral keys |

---

## 📷 Screenshots (Optional)

_Include screenshots of GUI, terminal output, or signature validation here._

---

## 🧪 Attack Simulations & Defense

- **Eavesdropping** → blocked (ciphertext only, AES key unknown)
- **Tampering** → blocked (signature fails)
- **Spoofing** → blocked (wrong public key)
- **Replay Attacks** → blocked (duplicate nonce:timestamp)

---

## 🚀 How to Run

1. Install requirements
```bash
pip install cryptography pyqt5 pyzbar qrcode
```

2. Launch Server
   ```bash
   python server.py```
4. Run Clients
```bash
python chat_gui.py
```
5. Validate message payloads
```bash
python verify_payload.py
```
