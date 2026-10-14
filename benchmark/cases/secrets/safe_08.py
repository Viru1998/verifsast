# CWE-798: Safe — keyring.get_password() stores secrets in the OS keychain
# The secret is never written to source code; it is retrieved from the
# system credential store (macOS Keychain, Windows Credential Locker, etc.).

import sys

try:
    import keyring

    def get_api_key():
        """Retrieve the API key from the OS keychain."""
        # SAFE: secret is in the OS keychain, not in source
        secret = keyring.get_password("myapp", "api_key")
        if secret is None:
            raise EnvironmentError(
                "API key not found in keychain. "
                "Run: python -c \"import keyring; keyring.set_password('myapp', 'api_key', '<your-key>')\""
            )
        return secret

    def get_db_password(service="myapp-db", username="appuser"):
        """Retrieve a DB password from the OS keychain."""
        pw = keyring.get_password(service, username)
        if pw is None:
            raise EnvironmentError(f"No password found for {service}/{username}")
        return pw

    def store_api_key(new_key):
        """Store (or update) the API key in the keychain."""
        keyring.set_password("myapp", "api_key", new_key)
        print("API key stored in keychain")

except ImportError:
    def get_api_key():   # type: ignore
        raise ImportError("keyring package is required: pip install keyring")

    def get_db_password(service="myapp-db", username="appuser"):  # type: ignore
        raise ImportError("keyring package is required: pip install keyring")

    def store_api_key(new_key):  # type: ignore
        raise ImportError("keyring package is required: pip install keyring")


if __name__ == "__main__":
    try:
        key = get_api_key()
        print(f"API key retrieved ({len(key)} chars)")
    except (EnvironmentError, ImportError) as exc:
        print(exc)
