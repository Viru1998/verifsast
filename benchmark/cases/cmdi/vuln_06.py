# CWE-78: Code Injection via eval()
# Vulnerability: eval() executes arbitrary Python code from user input

import sys


def calculate(expression):
    """Evaluate a mathematical expression from user input — exploitable."""
    # VULNERABLE: eval() will execute any Python expression, not just math
    result = eval(expression)
    return result


def apply_filter(data, filter_expr):
    """Filter a list using a user-supplied expression."""
    # VULNERABLE: filter_expr could be "__import__('os').system('id')"
    return [item for item in data if eval(filter_expr)]


def dynamic_config(key, value_expr):
    """Set a config value by evaluating a Python expression."""
    config = {}
    # VULNERABLE: value_expr is arbitrary Python
    config[key] = eval(value_expr)
    return config


if __name__ == "__main__":
    # Benign usage
    print(calculate("2 + 2"))

    # Malicious input — executes OS command
    try:
        calculate("__import__('os').system('id')")
    except Exception as exc:
        print(f"Error: {exc}")

    # Reading /etc/passwd via eval
    try:
        calculate("open('/etc/passwd').read()")
    except Exception as exc:
        print(f"Error: {exc}")
