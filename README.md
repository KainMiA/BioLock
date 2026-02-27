# BioLock
BioLock: A Prototype for Secure Distribution Storage of Biological Data

* https://img.shields.io/badge/License-Apache%25202.0-blue.svg
* https://img.shields.io/badge/python-3.8+-blue.svg
* https://img.shields.io/badge/Streamlit-1.28+-red.svg
* https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg

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

## 📖 User Guide

1. Registration & Login
* First-time users need to register (username, email, password).
* After login, the system automatically derives an encryption key from your password and stores it in the session.
  
2. Store Files
* Go to the Store Files page.
*Choose upload mode: Standard Upload (≤200 MB) or Large File Upload (streaming, any size).
* Select a file and adjust the slice size (default recommended based on file size).
* Choose encryption method:
** Use my password: encrypt with the key derived from your login password.
** Custom key: enter or generate a new key (recommended for different files).
* Click "Store File" and wait for completion. The system will display a file ID and encryption status.

3. Restore Files
* Go to the Restore Files page and select a file from the list.
* Specify the output directory; if the file is encrypted, provide the decryption key (password-derived or custom).
* Click "Restore File" and wait. The restored file will be saved to the specified path.

4. Key Management
* On the Keys page, you can view your current password-derived key or generate new custom keys (copy/download supported).

5. Settings
* On the Settings page, you can update your profile or change your password.


📊 Performance Benchmarks

We tested BioLock with synthetic data of various sizes and a real single-cell transcriptome sequencing dataset (137 GB). Results are summarized below:

File Size	Operation	Time (s)	Peak Memory (MB)
1 MB	Encrypt	0.52	98.0
Decrypt	0.89	97.8
10 MB	Encrypt	0.81	112.3
Decrypt	1.02	105.6
100 MB	Encrypt	4.35	204.8
Decrypt	4.62	123.5
1 GB	Encrypt	50.89	400.7
Decrypt	34.90	459.3
10 GB	Encrypt	681.81	3,092.5
Decrypt	395.53	2,222.1
137 GB	Encrypt	7,608.8	3,102.7
Decrypt	4,817.5	2,601.0
| Test environment: Intel Xeon Gold 6230 @ 2.1GHz, 64 GB RAM, SSD storage. Encryption/decryption used streaming mode; memory usage remained far below file size.
