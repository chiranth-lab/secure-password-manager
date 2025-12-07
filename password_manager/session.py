import os
import json
import time
import stat
from typing import Optional
from . import config

def _get_session_path():
    return config.SESSION_FILE

def save_session(key: bytes):
    """Saves the derived key and current timestamp to the session file."""
    # Key is expected to be bytes (base64 encoded key from derive_key)
    payload = {
        "timestamp": time.time(),
        "key": key.decode('utf-8')
    }
    path = _get_session_path()
    
    try:
        # Create file with restrictive permissions (600)
        # We open with 'w' and then chmod, or use os.open for atomic perms.
        # Simple chmod 600 after creation is sufficient for this scope.
        with open(path, 'w') as f:
            json.dump(payload, f)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        print(f"Warning: Could not save session: {e}")

def load_session() -> Optional[bytes]:
    """Loads the derived key if the session is valid (not expired)."""
    path = _get_session_path()
    if not os.path.exists(path):
        return None
        
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            
        timestamp = data.get("timestamp", 0)
        key_str = data.get("key")
        
        if not key_str:
            return None

        # Check for expiry
        if time.time() - timestamp > config.SESSION_TIMEOUT_SECONDS:
            clear_session()
            return None
            
        # Refresh session timestamp (sliding window)
        key_bytes = key_str.encode('utf-8')
        save_session(key_bytes)
        
        return key_bytes
    except (json.JSONDecodeError, OSError, ValueError):
        clear_session()
        return None

def clear_session():
    """Removes the session file."""
    path = _get_session_path()
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
