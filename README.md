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
