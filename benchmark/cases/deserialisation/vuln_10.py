# CWE-502: Insecure Deserialisation — shelve.open() with user-controlled path
# Vulnerability: shelve uses pickle internally; opening an attacker-supplied
# path lets them control the pickled data that gets loaded.

import shelve
import os


def load_user_data(username):
    """
    Load persistent user data from a shelve database.
    VULNERABLE: username is used directly to build the shelve path;
                an attacker who controls the shelve file controls pickled content.
    """
    db_path = f"/var/data/users/{username}"
    # VULNERABLE: shelve.open() on user-controlled path; shelve uses pickle
    with shelve.open(db_path) as db:
        return dict(db)


def read_session(session_path):
    """Read a session from a shelve database at the given path."""
    # VULNERABLE: session_path is user-supplied; shelve unpickles on load
    with shelve.open(session_path) as db:
        session = db.get("session_data", {})
    return session


def get_config(config_name):
    """Load a named configuration shelf."""
    path = os.path.join("/etc/myapp/shelves", config_name)
    # VULNERABLE: config_name could be "../../attacker/evil"
    with shelve.open(path) as shelf:
        return dict(shelf)


if __name__ == "__main__":
    # Benign round-trip (write then read)
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix="") as tmp:
        tmp_path = tmp.name

    with shelve.open(tmp_path) as db:
        db["key"] = {"value": 42}

    with shelve.open(tmp_path) as db:
        print(f"Loaded: {dict(db)}")

    os.unlink(tmp_path)
