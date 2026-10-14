# CWE-78: Code Injection via exec()
# Vulnerability: exec() runs arbitrary Python code supplied by the user

import sys


def run_plugin(plugin_code):
    """Execute a user-supplied plugin — completely unrestricted."""
    # VULNERABLE: exec() with user-controlled code string
    exec(plugin_code)


def load_and_run(code_str, context=None):
    """Load code from a string and run it in an optional namespace."""
    namespace = context or {}
    # VULNERABLE: no sandboxing, no validation
    exec(code_str, namespace)
    return namespace


def apply_transform(data, transform_code):
    """Apply a user-defined transform to data."""
    local_vars = {"data": data, "result": None}
    # VULNERABLE: transform_code is user-provided
    exec(transform_code, {}, local_vars)
    return local_vars.get("result")


if __name__ == "__main__":
    # Benign
    run_plugin("print('hello from plugin')")

    # Malicious: exfiltrate environment variables
    try:
        run_plugin("import os; print(os.environ)")
    except Exception as exc:
        print(f"Error: {exc}")

    transform_result = apply_transform([1, 2, 3], "result = [x * 2 for x in data]")
    print(transform_result)
