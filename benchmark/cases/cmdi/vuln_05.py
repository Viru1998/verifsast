# CWE-78: OS Command Injection via subprocess.Popen(shell=True) with formatted string
# Vulnerability: Popen with shell=True and a format()-built command string

import subprocess


def generate_thumbnail(input_path, output_path, width, height):
    """Generate a thumbnail — Popen + shell=True + .format()."""
    # VULNERABLE: all four args are user-controlled, .format() builds the command
    cmd = "ffmpeg -i {inp} -vf scale={w}:{h} {out}".format(
        inp=input_path, w=width, h=height, out=output_path
    )
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return proc.returncode, stdout, stderr


def run_user_script(script_name, arg):
    """Execute a user-chosen script — Popen with f-string."""
    # VULNERABLE: script_name and arg from user input
    cmd = f"/opt/scripts/{script_name}.sh {arg}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    return out.decode()


if __name__ == "__main__":
    # Attacker: input_path = "in.mp4; rm -rf /home/user"
    rc, out, err = generate_thumbnail("in.mp4; rm -rf /home/user", "out.jpg", 100, 100)
    print(rc)
