# CWE-502: Insecure Deserialisation — jsonpickle.decode() on user input
# Vulnerability: jsonpickle can reconstruct arbitrary Python objects
# including those with dangerous __reduce__ methods.

try:
    import jsonpickle

    def load_object(user_json: str):
        """
        Deserialise a Python object from a JSON+pickle string.
        VULNERABLE: jsonpickle.decode() can instantiate arbitrary Python classes.
        """
        # VULNERABLE: jsonpickle.decode on untrusted input
        obj = jsonpickle.decode(user_json)
        return obj

    def restore_from_api(json_body: str):
        """Restore an object received from an API client."""
        # VULNERABLE: external data decoded by jsonpickle
        return jsonpickle.decode(json_body)

    def load_config_object(config_json: str):
        """Load a configuration object serialised with jsonpickle."""
        # VULNERABLE: config from user-supplied string
        config = jsonpickle.decode(config_json)
        return config

except ImportError:
    def load_object(user_json):           # type: ignore
        raise ImportError("jsonpickle required: pip install jsonpickle")
    def restore_from_api(json_body):      # type: ignore
        raise ImportError("jsonpickle required")
    def load_config_object(config_json):  # type: ignore
        raise ImportError("jsonpickle required")


if __name__ == "__main__":
    try:
        import jsonpickle
        data = {"name": "Alice", "role": "admin"}
        encoded = jsonpickle.encode(data)
        decoded = load_object(encoded)
        print(f"Decoded: {decoded}")
    except ImportError as exc:
        print(exc)
