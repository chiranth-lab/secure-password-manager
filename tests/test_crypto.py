import base64
from password_manager import crypto

def test_generate_salt():
    salt = crypto.generate_salt()
    assert len(salt) == 16
    assert isinstance(salt, bytes)

def test_derive_key():
    salt = b'salt' * 4
    key = crypto.derive_key("password", salt)
    assert isinstance(key, bytes)
    # Base64 encoded length for 32 bytes is 44
    assert len(key) == 44

def test_encrypt_decrypt():
    salt = crypto.generate_salt()
    f = crypto.create_fernet("master", salt)
    
    plaintext = "secret data"
    token = crypto.encrypt(f, plaintext)
    
    assert token != plaintext
    assert isinstance(token, bytes)
    
    decrypted = crypto.decrypt(f, token)
    assert decrypted == plaintext
