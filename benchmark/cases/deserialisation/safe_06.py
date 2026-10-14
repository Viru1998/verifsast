# CWE-502: Safe — ast.literal_eval() for safe evaluation of simple types
# ast.literal_eval() only evaluates Python literals (str, int, float,
# complex, tuple, list, dict, set, bool, None); it cannot execute code.

import ast


def parse_literal(user_input: str):
    """
    Safely parse a Python literal from user input.
    SAFE: ast.literal_eval() raises ValueError/SyntaxError for non-literals;
          it cannot call functions or import modules.
    """
    try:
        value = ast.literal_eval(user_input)
    except (ValueError, SyntaxError) as exc:
        raise ValueError(f"Input is not a valid Python literal: {exc}") from exc
    return value


def parse_list_input(raw: str):
    """Parse a list from user input — safe alternative to eval()."""
    value = parse_literal(raw)
    if not isinstance(value, list):
        raise TypeError(f"Expected a list, got {type(value).__name__}")
    return value


def parse_dict_input(raw: str):
    """Parse a dict from user input."""
    value = parse_literal(raw)
    if not isinstance(value, dict):
        raise TypeError(f"Expected a dict, got {type(value).__name__}")
    return value


if __name__ == "__main__":
    print(parse_list_input("[1, 2, 3]"))
    print(parse_dict_input("{'key': 'value', 'num': 42}"))

    # Malicious input is blocked
    for attack in [
        "__import__('os').system('id')",
        "open('/etc/passwd').read()",
        "[x for x in ().__class__.__base__.__subclasses__()]",
    ]:
        try:
            parse_literal(attack)
        except (ValueError, TypeError) as exc:
            print(f"Blocked: {exc}")
