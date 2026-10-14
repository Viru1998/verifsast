# CWE-78: Safe — os.system() called with a fully hardcoded string
# No user input reaches os.system(); every argument is a compile-time literal.

import os


def clear_temp_files():
    """Delete known temp files — hardcoded paths only."""
    # SAFE: the path is a literal; no variable interpolation
    return os.system("rm -f /tmp/app_cache_*.tmp")


def sync_filesystem():
    """Flush filesystem buffers to disk."""
    # SAFE: literal command
    return os.system("sync")


def reload_sysctl():
    """Reload kernel parameters — hardcoded sysctl command."""
    # SAFE: fixed command, no user data
    return os.system("sysctl -p /etc/sysctl.conf")


def rotate_logs():
    """Force immediate log rotation."""
    # SAFE: hardcoded
    return os.system("logrotate --force /etc/logrotate.conf")


if __name__ == "__main__":
    rc = clear_temp_files()
    print(f"Temp cleanup exited with {rc}")
    rc = sync_filesystem()
    print(f"Sync exited with {rc}")
