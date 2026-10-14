# CWE-502: Insecure Deserialisation — pickle.load() from a user-supplied file path
# Vulnerability: opening a file named by the user and pickling it is RCE

import pickle
import os


UPLOAD_DIR = "/var/www/uploads"


def load_model(model_filename):
    """
    Load an ML model from the uploads directory.
    VULNERABLE: model_filename from user input; pickle.load() on the opened file
                deserialises attacker-controlled content.
    """
    filepath = os.path.join(UPLOAD_DIR, model_filename)
    # VULNERABLE: pickle.load() on an attacker-supplied file
    with open(filepath, "rb") as f:
        model = pickle.load(f)
    return model


def restore_checkpoint(path):
    """Restore a training checkpoint from disk."""
    # VULNERABLE: path is user-controlled
    with open(path, "rb") as f:
        checkpoint = pickle.load(f)
    return checkpoint


def import_dataset(file_path):
    """Import a dataset serialised with pickle."""
    # VULNERABLE: file_path is user-supplied
    with open(file_path, "rb") as fh:
        return pickle.load(fh)


if __name__ == "__main__":
    import io
    # Benign round-trip
    buf = io.BytesIO()
    pickle.dump({"weights": [0.1, 0.2, 0.3]}, buf)
    buf.seek(0)
    data = pickle.load(buf)
    print(f"Loaded: {data}")
