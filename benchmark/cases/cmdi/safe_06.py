# CWE-78: Safe — command selected from a whitelist dict
# User input selects a key; the actual command is fully defined in the whitelist
# so the user never controls any part of the shell command string.

import subprocess

# Only these commands may be invoked; keys are user-supplied, values are safe
ALLOWED_COMMANDS = {
    "uptime":    ["uptime"],
    "disk":      ["df", "-h", "/"],
    "memory":    ["free", "-h"],
    "processes": ["ps", "aux", "--sort=-%cpu"],
    "whoami":    ["whoami"],
}


def run_diagnostic(command_name):
    """
    Run a diagnostic command chosen by the user.
    The user supplies only the key; the actual command is always from the whitelist.
    """
    if command_name not in ALLOWED_COMMANDS:
        raise ValueError(
            f"Unknown command {command_name!r}. "
            f"Allowed: {sorted(ALLOWED_COMMANDS)}"
        )

    # SAFE: the command list comes entirely from the whitelist, not from user input
    result = subprocess.run(
        ALLOWED_COMMANDS[command_name],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


if __name__ == "__main__":
    for name in ("uptime", "disk", "memory"):
        print(f"--- {name} ---")
        print(run_diagnostic(name))

    try:
        run_diagnostic("; cat /etc/passwd")
    except ValueError as exc:
        print(f"Blocked: {exc}")
