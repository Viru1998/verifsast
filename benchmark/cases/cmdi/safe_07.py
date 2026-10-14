# CWE-78: Safe — subprocess.run() with shell=False explicitly stated
# shell=False (the default) ensures the OS exec() is called directly,
# bypassing the shell interpreter entirely.

import subprocess


def run_linter(filepath):
    """Run flake8 linter on a file — shell=False, list args."""
    # SAFE: shell=False + list args; filepath cannot inject shell commands
    result = subprocess.run(
        ["flake8", "--max-line-length=100", filepath],
        capture_output=True,
        text=True,
        shell=False,   # explicit, to make intent clear
        timeout=30,
    )
    return result.stdout, result.returncode


def run_tests(test_path, verbose=False):
    """Run pytest on a path — safe invocation."""
    args = ["pytest", test_path]
    if verbose:
        args.append("-v")

    # SAFE: explicit shell=False
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        shell=False,
        timeout=120,
    )
    return result.stdout, result.returncode


def hash_file(filepath):
    """Compute SHA-256 of a file — safe subprocess call."""
    result = subprocess.run(
        ["sha256sum", filepath],
        capture_output=True,
        text=True,
        shell=False,
    )
    if result.returncode == 0:
        return result.stdout.split()[0]
    return None


if __name__ == "__main__":
    output, code = run_linter("app.py")
    print(f"Linter exit {code}:\n{output}")
