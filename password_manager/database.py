import sqlite3
import os
import datetime
from typing import Optional, List
from . import config
from .models import VaultMeta, Entry

def get_connection():
    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Vault metadata table (stores global salt)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY,
            salt BLOB NOT NULL,
            iterations INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    # Entries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted BLOB NOT NULL,
            notes_encrypted BLOB,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

    # Secure the database file permissions
    try:
        os.chmod(config.DB_NAME, 0o600)
    except OSError:
        pass

def set_meta(salt: bytes):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO vault_meta (salt, iterations, created_at) VALUES (?, ?, ?)",
        (salt, config.PBKDF2_ITERATIONS, now)
    )
    conn.commit()
    conn.close()

def get_meta() -> Optional[VaultMeta]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vault_meta ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return VaultMeta(
            id=row['id'],
            salt=row['salt'],
            iterations=row['iterations'],
            created_at=row['created_at']
        )
    return None

def add_entry(entry: Entry):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    cursor.execute(
        """
        INSERT INTO entries (service, username, password_encrypted, notes_encrypted, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (entry.service, entry.username, entry.password_encrypted, entry.notes_encrypted, now, now)
    )
    conn.commit()
    conn.close()

def get_entry(service: str) -> Optional[Entry]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM entries WHERE service = ?", (service,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return Entry(
            id=row['id'],
            service=row['service'],
            username=row['username'],
            password_encrypted=row['password_encrypted'],
            notes_encrypted=row['notes_encrypted'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )
    return None

def list_entries() -> List[str]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM entries")
    rows = cursor.fetchall()
    conn.close()
    return [row['service'] for row in rows]

def delete_entry(service: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM entries WHERE service = ?", (service,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0
