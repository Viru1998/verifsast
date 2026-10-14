# CWE-78: OS Command Injection via subprocess.call(shell=True)
# Vulnerability: shell=True with a string built from user input

import subprocess


def run_backup(backup_dir):
    """Run a backup script for the given directory — vulnerable."""
    # VULNERABLE: shell=True + string construction = injection
    cmd = "tar czf /backups/backup.tar.gz " + backup_dir
    subprocess.call(cmd, shell=True)


def convert_image(input_file, output_file):
    """Convert an image using ImageMagick — shell=True with user paths."""
    # VULNERABLE: both paths are user-controlled
    cmd = "convert " + input_file + " " + output_file
    ret = subprocess.call(cmd, shell=True)
    return ret


def send_notification(email, message):
    """Send an email notification — vulnerable to header injection via shell."""
    # VULNERABLE: email and message go into a shell command
    cmd = 'echo "' + message + '" | mail -s "Alert" ' + email
    subprocess.call(cmd, shell=True)


if __name__ == "__main__":
    # Attacker: backup_dir = "/tmp/; cat /etc/shadow > /tmp/out.txt"
    run_backup("/tmp/; cat /etc/shadow > /tmp/out.txt")
