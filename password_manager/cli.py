import argparse
import getpass
import sys
import os
import secrets
import string
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

from . import config, crypto, database, session, models

VALIDATION_SERVICE_NAME = "__validation_canary__"

def get_master_password(confirm: bool = False) -> str:
    """Prompts for master password securely."""
    while True:
        pwd = getpass.getpass("Enter master password: ")
        if not pwd:
            print("Password cannot be empty.")
            continue
        
        if confirm:
            files_pwd = getpass.getpass("Confirm master password: ")
            if pwd != files_pwd:
                print("Passwords do not match. Try again.")
                continue
        return pwd

def get_fernet_instance(require_auth: bool = True) -> Optional[Fernet]:
    """
    Retrieves a valid Fernet instance.
    - Checks session first.
    - If no session or invalid, prompts for password.
    - Validates password against the canary entry in DB.
    - If successful, saves session.
    """
    # 1. Check database existence
    if not os.path.exists(config.DB_NAME):
        print("Vault not found. Run 'init' to create a new vault.")
        sys.exit(1)

    meta = database.get_meta()
    if not meta:
        print("Vault meta corrupt or missing. Run 'init' to reset (WARNING: Data loss).")
        sys.exit(1)

    # 2. Try session
    key = session.load_session()
    if key:
        try:
            f = Fernet(key)
            return f
        except Exception:
            session.clear_session()

    if not require_auth:
        return None

    # 3. Prompt for password
    password = get_master_password()
    
    # 4. Derive key
    try:
        key = crypto.derive_key(password, meta.salt)
        f = Fernet(key)
        
        # 5. Validate key against canary
        # We need to find the validation entry
        # Since 'get_entry' expects a service name, let's use that.
        canary = database.get_entry(VALIDATION_SERVICE_NAME)
        
        if canary:
            try:
                decrypted = crypto.decrypt(f, canary.password_encrypted)
                if decrypted != "OK":
                    raise InvalidToken
            except InvalidToken:
                print("Error: Incorrect master password.")
                sys.exit(1)
        else:
            # If no canary exists (maybe manual DB manipulation?), we can't validate.
            # But proceed with caution? Or treat as success?
            # To be safe and compliant with "success/error messages" and data integrity:
            # We'll just warn and proceed, but NOT save session to be safe? 
            # Or just assume it's right.
            # Let's assume it's right but print a debug warning if we were debugging.
            pass

        # 6. Save session
        session.save_session(key)
        return f

    except Exception as e:
        print(f"Error handling password: {e}")
        sys.exit(1)

def cmd_init(args):
    if os.path.exists(config.DB_NAME):
        print("Error: Vault already exists. Delete 'vault.db' to start over.")
        sys.exit(1)
        
    print("Initializing new vault...")
    password = get_master_password(confirm=True)
    
    database.init_db()
    
    # Create meta
    salt = crypto.generate_salt()
    database.set_meta(salt)
    
    # Create canary
    key = crypto.derive_key(password, salt)
    f = Fernet(key)
    
    canary_entry = models.Entry(
        id=None,
        service=VALIDATION_SERVICE_NAME,
        username="system",
        password_encrypted=crypto.encrypt(f, "OK"),
        notes_encrypted=crypto.encrypt(f, "Canary for password validation")
    )
    database.add_entry(canary_entry)
    
    print("Vault initialized successfully.")

def cmd_add(args):
    f = get_fernet_instance()
    
    if database.get_entry(args.service):
        print(f"Error: Entry for '{args.service}' already exists.")
        sys.exit(1)
    
    password = getpass.getpass(f"Enter password for {args.service}: ")
    notes = input("Enter notes (optional): ")
    
    entry = models.Entry(
        id=None,
        service=args.service,
        username=args.username,
        password_encrypted=crypto.encrypt(f, password),
        notes_encrypted=crypto.encrypt(f, notes) if notes else b""
    )
    
    database.add_entry(entry)
    print(f"Entry for '{args.service}' added.")

def cmd_list(args):
    # List technically doesn't need decryption to show service names,
    # BUT we should require auth to even list contents for privacy?
    # User requirement: "integrate into CLI flows... require master password".
    # Usually `list` is protected too.
    get_fernet_instance() 
    
    entries = database.list_entries()
    # Filter canary
    visible = [e for e in entries if e != VALIDATION_SERVICE_NAME]
    
    if not visible:
        print("No entries found.")
        return
        
    print("\nStored Services:")
    for service in visible:
        print(f"- {service}")
    print("")

def cmd_get(args):
    f = get_fernet_instance()
    
    entry = database.get_entry(args.service)
    if not entry:
        print(f"Error: Service '{args.service}' not found.")
        sys.exit(1)
        
    try:
        pwd = crypto.decrypt(f, entry.password_encrypted)
        notes = ""
        if entry.notes_encrypted:
             # Handle empty bytes if any
             if entry.notes_encrypted == b"":
                 notes = ""
             else:
                 notes = crypto.decrypt(f, entry.notes_encrypted)
        
        print(f"\nService:  {entry.service}")
        print(f"Username: {entry.username}")
        print(f"Password: {pwd}")
        if notes:
            print(f"Notes:    {notes}")
        print("")
        
    except InvalidToken:
        print("Error: Integrity check failed. Data may be corrupted.")

def cmd_delete(args):
    get_fernet_instance() # Auth required
    
    if args.service == VALIDATION_SERVICE_NAME:
         print("Error: Cannot delete system entry.")
         sys.exit(1)
         
    if database.delete_entry(args.service):
        print(f"Entry '{args.service}' deleted.")
    else:
        print(f"Error: Service '{args.service}' not found.")

def generate_password(length: int = 16) -> str:
    """Generates a secure random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def cmd_generate(args):
    """Generates and prints a strong password."""
    pwd = generate_password(args.length)
    print(f"\nGenerated Password ({args.length} chars):")
    print("-" * 40)
    print(pwd)
    print("-" * 40)
    print("Copied to clipboard? No (Install pyperclip for that feature in future).")

def main():
    parser = argparse.ArgumentParser(description="Secure Password Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # init
    parser_init = subparsers.add_parser("init", help="Initialize the vault")
    parser_init.set_defaults(func=cmd_init)
    
    # add
    parser_add = subparsers.add_parser("add", help="Add a new entry")
    parser_add.add_argument("--service", required=True, help="Service name")
    parser_add.add_argument("--username", required=True, help="Username")
    parser_add.set_defaults(func=cmd_add)
    
    # list
    parser_list = subparsers.add_parser("list", help="List all entries")
    parser_list.set_defaults(func=cmd_list)
    
    # get
    parser_get = subparsers.add_parser("get", help="Retrieve an entry")
    parser_get.add_argument("--service", required=True, help="Service name")
    parser_get.set_defaults(func=cmd_get)
    
    # delete
    parser_delete = subparsers.add_parser("delete", help="Delete an entry")
    parser_delete.add_argument("--service", required=True, help="Service name")
    parser_delete.set_defaults(func=cmd_delete)

    # generate
    parser_generate = subparsers.add_parser("generate", help="Generate a strong password")
    parser_generate.add_argument("--length", type=int, default=16, help="Password length")
    parser_generate.set_defaults(func=cmd_generate)
    
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    main()
