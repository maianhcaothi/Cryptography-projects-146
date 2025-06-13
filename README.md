# Cryptography-projects-146
# 🔐 AES File Encryption/Decryption Tool (GUI)

A simple, secure, and user-friendly tool for encrypting and decrypting files using **AES-128 in EAX mode**. This project features a **Tkinter GUI** and includes safe **key management** with automatic storage in a dedicated folder.

---

## 🚀 Features

- **🔒 AES-128 Encryption**  
  Strong encryption using AES with a 128-bit key length.

- **🛡️ EAX Mode**  
  Provides both confidentiality (encryption) and integrity (tamper detection) via authentication tag.

- **🔑 Key Management**
  - Generate a **random 128-bit key**.
  - Or enter a **custom 32-character hexadecimal key**.
  - Keys are saved automatically in the `Key/` folder.
  - Used key must be present for decryption.

- **📂 File Handling**
  - Encrypts any file and appends `.aes` extension.
  - Decrypts `.aes` file back to original (or adds `.decrypted` if needed).
  - Optionally deletes the original file for enhanced security.

- **🖥️ Intuitive GUI**
  - Built with Python’s `tkinter`.
  - No command-line interaction required.

---

## 🧰 Requirements

- Python 3.x
- [`pycryptodomex`](https://pypi.org/project/pycryptodomex/)

### 📦 Installation

```bash
pip install pycryptodomex

Cryptography-projects-146/
├── main_gui.py             # The GUI application.
├── aes_file_encryption.py  # Core encryption/decryption logic.
└── Key/                    # Folder to store encryption keys (created automatically).
cd path/to/Cryptography-projects-146
python main_gui.py
