# CWE-22: Path Traversal — shutil.copy() with user-controlled destination
# Vulnerability: destination path is user-supplied; attacker can overwrite
# arbitrary files anywhere on the filesystem.

import shutil
import os


UPLOAD_DIR = "/var/www/uploads"
BACKUP_DIR = "/var/backups/app"


def save_upload(src_temp_path, dest_filename):
    """Move an uploaded file to the uploads directory — dest_filename injectable."""
    dest = os.path.join(UPLOAD_DIR, dest_filename)
    # VULNERABLE: dest_filename = "../../etc/cron.d/backdoor" overwrites cron config
    shutil.copy(src_temp_path, dest)
    return dest


def backup_file(filename, backup_name):
    """Back up a file with a user-supplied backup name."""
    src = os.path.join(UPLOAD_DIR, filename)
    dst = os.path.join(BACKUP_DIR, backup_name)
    # VULNERABLE: backup_name could contain "../" to escape BACKUP_DIR
    shutil.copy2(src, dst)
    return dst


def restore_backup(backup_path, restore_to):
    """Restore a backup to a user-chosen path."""
    # VULNERABLE: both paths are user-controlled
    shutil.copy(backup_path, restore_to)


if __name__ == "__main__":
    # Attacker writes a backdoor to /etc/cron.d
    try:
        save_upload("/tmp/payload.sh", "../../etc/cron.d/backdoor")
    except OSError as exc:
        print(f"Copy failed: {exc}")
