from dataclasses import dataclass
from typing import Optional

@dataclass
class VaultMeta:
    id: int
    salt: bytes
    iterations: int
    created_at: str

@dataclass
class Entry:
    id: Optional[int]
    service: str
    username: str
    password_encrypted: bytes
    notes_encrypted: Optional[bytes]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
