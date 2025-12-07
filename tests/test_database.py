import os
import pytest
from password_manager import database, config, models

TEST_DB = "test_vault.db"

@pytest.fixture
def db():
    # Setup
    original_db = config.DB_NAME
    config.DB_NAME = TEST_DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    
    database.init_db()
    database.set_meta(b'testsalt')
    
    yield
    
    # Teardown
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    config.DB_NAME = original_db

def test_meta(db):
    meta = database.get_meta()
    assert meta is not None
    assert meta.salt == b'testsalt'

def test_crud_entry(db):
    entry = models.Entry(
        id=None,
        service="google",
        username="me",
        password_encrypted=b"encrypted_pw",
        notes_encrypted=b"encrypted_notes"
    )
    
    # Add
    database.add_entry(entry)
    
    # Get
    retrieved = database.get_entry("google")
    assert retrieved is not None
    assert retrieved.service == "google"
    assert retrieved.username == "me"
    assert retrieved.password_encrypted == b"encrypted_pw"
    
    # List
    entries = database.list_entries()
    assert "google" in entries
    
    # Delete
    assert database.delete_entry("google") is True
    assert database.get_entry("google") is None
    assert database.delete_entry("google") is False
