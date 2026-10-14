# CWE-798: Safe — getpass.getpass() prompts for the password interactively
# The password is read from the terminal at runtime and never appears
# in source code, logs, or environment variables.

import getpass
import hashlib
import hmac


def prompt_for_password(prompt="Enter password: "):
    """
    Prompt the user for a password without echoing it to the terminal.
    SAFE: password is read at runtime, never embedded in source.
    """
    password = getpass.getpass(prompt)
    if not password:
        raise ValueError("Password must not be empty")
    return password


def authenticate_user(username):
    """Prompt for password and verify against a stored hash."""
    password = prompt_for_password(f"Password for {username}: ")

    # In a real app: look up stored_hash from DB by username
    stored_hash = None  # would come from the database

    if stored_hash is None:
        print("User not found")
        return False

    entered_hash = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(entered_hash, stored_hash)


def get_encryption_key():
    """Read an encryption passphrase interactively."""
    passphrase = getpass.getpass("Enter encryption passphrase: ")
    # Derive a key from the passphrase — PBKDF2 with salt
    salt = b"static-salt-replace-with-random"
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000)
    return key


if __name__ == "__main__":
    try:
        pw = prompt_for_password()
        print(f"Got password of length {len(pw)}")
    except (KeyboardInterrupt, ValueError) as exc:
        print(f"\nCancelled: {exc}")
