# CWE-798: Safe — password passed as a function parameter with no default
# There is no hardcoded password; the caller is responsible for supplying
# the credential from a secure source (env var, secrets manager, etc.).

import hashlib
import hmac


def connect_to_db(host, port, dbname, user, password):
    """
    Connect to a database.
    SAFE: password is a parameter — the caller must supply it.
          There is no hardcoded default; if not provided the call fails.
    """
    # In a real implementation: return psycopg2.connect(...)
    print(f"Connecting to {host}:{port}/{dbname} as {user}")
    return {"host": host, "port": port, "db": dbname, "user": user}


def send_email(smtp_host, smtp_port, username, password, to, subject, body):
    """
    Send an email.
    SAFE: SMTP password is a required parameter with no default.
    """
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = username
    msg["To"]      = to
    with smtplib.SMTP(smtp_host, smtp_port) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)


def sign_payload(payload: bytes, secret: bytes) -> bytes:
    """
    HMAC-sign a payload.
    SAFE: secret must be passed in — no hardcoded value.
    """
    return hmac.new(secret, payload, hashlib.sha256).digest()


if __name__ == "__main__":
    import os
    pw = os.environ.get("DB_PASSWORD", "")
    conn = connect_to_db("localhost", 5432, "app", "appuser", pw)
    print(conn)
