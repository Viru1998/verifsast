# CWE-798: Hardcoded AWS secret access key
# Vulnerability: AWS credentials embedded in source code

import hmac
import hashlib
import base64


# VULNERABLE: real-format AWS credentials hardcoded
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_DEFAULT_REGION    = "us-east-1"


def sign_request(string_to_sign):
    """Produce an HMAC-SHA256 signature for an AWS request."""
    # Uses the hardcoded secret key
    key = AWS_SECRET_ACCESS_KEY.encode("utf-8")
    msg = string_to_sign.encode("utf-8")
    return base64.b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode()


def get_aws_config():
    """Return the AWS configuration dict — leaks credentials."""
    return {
        "aws_access_key_id":     AWS_ACCESS_KEY_ID,
        "aws_secret_access_key": AWS_SECRET_ACCESS_KEY,  # VULNERABLE
        "region_name":           AWS_DEFAULT_REGION,
    }


if __name__ == "__main__":
    config = get_aws_config()
    print(f"Access key: {config['aws_access_key_id']}")
    print(f"Secret key: {config['aws_secret_access_key'][:8]}...")
