# Secure Password Manager

A local, encrypted password manager written in Python. Securely stores your passwords in a local SQLite database using AES-256 encryption.

## Features

- **AES-256 Encryption**: Uses `cryptography` library's Fernet (symmetrical encryption).
- **Secure Key Derivation**: Master password is hashed using PBKDF2HMAC-SHA256 with 390,000 iterations.
- **Local Storage**: All data is stored in `vault.db`.
- **Session Management**: Auto-locks after 5 minutes of inactivity.
- **Zero-Knowledge**: Master password is never stored sequentially.
- **Offline**: No external APIs or cloud dependencies.

## Installation

### 1. Set up Environment
It is recommended to use a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

### 1. Initialize the Vault
First, you must create the vault and set a master password.
```bash
python main.py init
```

### 2. Add an Entry
```bash
python main.py add --service "gmail" --username "user@example.com"
```
You will be prompted to enter the password (hidden input).

### 3. Generate a Password
```bash
python main.py generate --length 20
```
Prints a secure random password to the console.

### 4. List Entries
```bash
python main.py list
```

### 4. Retrieve Password
```bash
python main.py get --service "gmail"
```
This requires authentication (master password or active session).

### 5. Delete an Entry
```bash
python main.py delete --service "gmail"
```

## Security Disclaimer

This tool is designed for educational and personal use. While it implements industry-standard algorithms (AES-256, PBKDF2), no software is invulnerable. Use at your own risk.

## Project Structure

```
secure-password-manager/
├── password_manager/   # Core logic
├── tests/             # Unit tests
├── main.py            # Entry point
└── vault.db           # Encrypted database (created on init)
```
