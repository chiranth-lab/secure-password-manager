import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from . import config

def generate_salt() -> bytes:
    """Generates a random 16-byte salt."""
    return os.urandom(config.SALT_SIZE)

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a key from the master password using PBKDF2HMAC."""
    if isinstance(master_password, str):
        master_password = master_password.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=config.PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password))

def create_fernet(master_password: str, salt: bytes) -> Fernet:
    """Creates a Fernet instance from the master password and salt."""
    key = derive_key(master_password, salt)
    return Fernet(key)

def encrypt(fernet: Fernet, plaintext: str) -> bytes:
    """Encrypts plaintext string to bytes."""
    return fernet.encrypt(plaintext.encode('utf-8'))

def decrypt(fernet: Fernet, token: bytes) -> str:
    """Decrypts token bytes to plaintext string."""
    return fernet.decrypt(token).decode('utf-8')
