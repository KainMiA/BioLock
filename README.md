# BioLock: A Prototype for Secure Distribution Storage of Biological Data

BioLock is a prototype end-to-end encrypted file storage system designed for sensitive biomedical data. It implements a "split-encrypt-distribute" paradigm by dividing files into multiple encrypted slices and generating a separate index file, ensuring that only the data owner can fully restore the original data. Built with Streamlit, BioLock provides an intuitive web interface, supports streaming upload of large files, user authentication, password reset, and file integrity verification. BioLock aims to offer researchers, clinicians, and patients a lightweight, secure, and easy-to-use data protection tool.

## ✨ Features

End-to-End Encryption: Each data slice is independently encrypted with AES-256-GCM, guaranteeing confidentiality and integrity.
Chunked Storage: Large files are split into adjustable slices (1–500 MB) and processed in a streaming fashion, making it memory-friendly.
User Authentication: bcrypt password hashing + PBKDF2 key derivation (100,000 iterations) with password reset capability.
Flexible Key Management: Users can either use a password-derived key or provide a custom key, decoupling the encryption key from the password.
Integrity Verification: Each slice stores a SHA-256 hash; restoration automatically verifies these hashes to detect tampering.
Large File Support: Streaming upload/download handles files far exceeding available RAM (tested with 137 GB single-cell sequencing data).
User-Friendly Interface: Built with Streamlit, featuring a dashboard, file manager, key manager, settings, and light/dark theme toggle.
Open & Transparent: Fully open-source code with auditable cryptographic logic, meeting academic reproducibility requirements.

## 📦 Technology Stack

Backend: Python 3.8+
Cryptography: cryptography (AES-GCM, PBKDF2), bcrypt
Web Framework: Streamlit
Data Persistence: Local file system (JSON indexes + encrypted slices)

## 🚀 Quick Start

### Installation
1. Clone the repository
```
git clone https://github.com/
cd biolock
```
2. Create a virtual environment
```
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```
3. Install dependencies
```
pip install -r requirements.txt
```
### Run
```
streamlit run main.py
```
After launching, open http://localhost:8501 in your browser to start using BioLock.

## 📖 User Guide

1. Registration & Login
* First-time users need to register (username, email, password).
* After login, the system automatically derives an encryption key from your password and stores it in the session.
  
2. Store Files
* Go to the Store Files page.
* Choose upload mode: Standard Upload (≤200 MB) or Large File Upload (streaming, any size).
* Select a file and adjust the slice size (default recommended based on file size).
* Choose encryption method:
  
  Use my password: encrypt with the key derived from your login password.
  
  Custom key: enter or generate a new key (recommended for different files).
  
* Click "Store File" and wait for completion. The system will display a file ID and encryption status.

3. Restore Files
* Go to the Restore Files page and select a file from the list.
* Specify the output directory; if the file is encrypted, provide the decryption key (password-derived or custom).
* Click "Restore File" and wait. The restored file will be saved to the specified path.

4. Key Management
* On the Keys page, you can view your current password-derived key or generate new custom keys (copy/download supported).

5. Settings
* On the Settings page, you can update your profile or change your password.



