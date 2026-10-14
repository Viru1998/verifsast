# CWE-798: Hardcoded SMTP password in a configuration dict
# Vulnerability: email credentials stored as plain-text literals

import smtplib
from email.mime.text import MIMEText


# VULNERABLE: SMTP credentials are hardcoded constants
EMAIL_CONFIG = {
    "host":     "smtp.gmail.com",
    "port":     587,
    "username": "alerts@example.com",
    "password": "MyEmailPass123!",   # VULNERABLE
    "use_tls":  True,
}


def send_email(to_address, subject, body):
    """Send an email using the hardcoded SMTP credentials."""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = EMAIL_CONFIG["username"]
    msg["To"]      = to_address

    with smtplib.SMTP(EMAIL_CONFIG["host"], EMAIL_CONFIG["port"]) as smtp:
        if EMAIL_CONFIG["use_tls"]:
            smtp.starttls()
        # VULNERABLE: password comes from hardcoded config dict
        smtp.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
        smtp.send_message(msg)


def send_alert(message):
    """Send an alert email to the ops team."""
    send_email("ops@example.com", "Application Alert", message)


if __name__ == "__main__":
    print(f"SMTP config: {EMAIL_CONFIG['host']}:{EMAIL_CONFIG['port']}")
    print(f"Password: {EMAIL_CONFIG['password']}")
