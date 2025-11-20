# 🔐 Secure File Storage System (AES-GCM) — Web Application

A modern Flask-based web application that securely **encrypts and decrypts files** using **AES-256 GCM** with **PBKDF2-HMAC-SHA256** key derivation.  
This project demonstrates how real-world secure storage systems protect user files before storing or transferring them.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Backend-black.svg)
![Crypto](https://img.shields.io/badge/Cryptography-AES--GCM-green.svg)
![Status](https://img.shields.io/badge/Project%20Status-Active-brightgreen.svg)

---

## 📌 Overview

This project provides a **web interface** for encrypting and decrypting files using strong cryptographic standards.  
It uses:

- **AES-256-GCM** → for encryption + integrity  
- **PBKDF2-HMAC-SHA256** → for deriving strong keys from passwords  
- **Flask** → backend processing  
- **HTML/CSS/JS** → responsive UI  

### 🔐 Features
- Encrypt any file (PDF, DOCX, JPG, TXT, etc.)
- Decrypt encrypted `.enc` files back to original
- Automatically generates `.meta.json` containing:
  - Salt  
  - IV (nonce)  
  - Timestamp  
  - Metadata needed for decryption
- Modern and simple web-based UI
- Safe key handling using PBKDF2-HMAC-SHA256
- AES-GCM provides tamper detection (authentication tag)
- No data is stored permanently — everything remains local

---

### **1️⃣ Encryption**
- User uploads a file  
- Enters a password  
- System derives a 256-bit AES key  
- The file is encrypted using **AES-GCM**  
- Two files are created:

