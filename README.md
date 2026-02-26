# 🍪 Chrome v20 Cookie Decryptor

🔧 Troubleshooting: MAC Check Failed
If the script returns ValueError: MAC check failed, Google has likely rotated the Master Keys.
To fix this, update the aes_key and chacha20_key variables in main.py with the hex strings corresponding to your current Chrome version.

⚖️ Disclaimer
This project is for educational and authorized security auditing purposes only. The author assumes no liability for misuse. Accessing data from a browser without explicit permission is illegal.
A specialized digital forensics tool designed to extract and decrypt Google Chrome cookies protected by the **v20 App-Bound Encryption** (introduced in Chrome 127+). This tool automates the multi-stage decryption process by leveraging local service elevation.

## 🛡️ Features
- **App-Bound Bypass**: Handles the transition from `SYSTEM` context to `User` context automatically.
- **Algorithm Support**: Fully supports both **AES-GCM** and **ChaCha20-Poly1305** (including Flag 204) encryption paths.
- **Dual Export**: Saves decrypted cookies in both **JSON** and **Netscape (txt)** formats.
- **Profile Discovery**: Automatically scans all Chrome user profiles (Default, Profile 1, etc.).

## 🏗️ Technical Architecture
Chrome's v20 encryption adds a layer that requires the `SYSTEM` account to initiate decryption. This tool works by:
1. Locating the `app_bound_encrypted_key` in the `Local State` file.
2. Using `pypsexec` to execute a helper process (`decrypt_key.exe`) under the Windows **SYSTEM** account.
3. Passing the result back to the user context for final AES/ChaCha decryption.
4. Parsing the SQLite `Cookies` database to output plaintext session data.



## 🚀 Getting Started

### Prerequisites
- **Windows OS** (Admin privileges required).
- **Python 3.10+**
- `decrypt_key.exe` must be present in the root directory (compile `decrypt_key.py` first).

### Installation
1. **Clone the repository**:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/chrome-v20-cookie-decryptor.git](https://github.com/YOUR_USERNAME/chrome-v20-cookie-decryptor.git)
   cd chrome-v20-cookie-decryptor

