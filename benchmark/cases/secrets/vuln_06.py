# CWE-798: Hardcoded Stripe live secret key
# Vulnerability: a real-format Stripe production API key in source code

import urllib.request
import urllib.parse
import json


# VULNERABLE: Stripe live key hardcoded — "sk_live_" prefix is flagged by secrets scanners
STRIPE_SECRET_KEY = "sk_live_abcdefghijklmnop"
STRIPE_API_BASE   = "https://api.stripe.com/v1"


def stripe_request(method, endpoint, data=None):
    """Make a request to the Stripe API using the hardcoded key."""
    url = f"{STRIPE_API_BASE}/{endpoint}"
    encoded = urllib.parse.urlencode(data or {}).encode("utf-8") if data else None

    import base64
    token = base64.b64encode(f"{STRIPE_SECRET_KEY}:".encode()).decode()
    req = urllib.request.Request(
        url,
        data=encoded,
        method=method,
        headers={"Authorization": f"Basic {token}"},  # VULNERABLE
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def create_charge(amount_cents, currency, customer_id):
    """Create a Stripe charge — uses hardcoded live key."""
    return stripe_request("POST", "charges", {
        "amount":   amount_cents,
        "currency": currency,
        "customer": customer_id,
    })


def list_customers():
    """List Stripe customers."""
    return stripe_request("GET", "customers")


if __name__ == "__main__":
    print(f"Stripe key starts with: {STRIPE_SECRET_KEY[:12]}...")
