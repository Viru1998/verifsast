# CWE-78: OS Command Injection — Flask route passes request.args to subprocess.run(shell=True)
# Vulnerability: HTTP query parameter flows into a shell command

import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/ping")
def ping():
    """Ping an IP address supplied by the user — injectable."""
    host = request.args.get("host", "127.0.0.1")

    # VULNERABLE: host from HTTP query param goes into shell command
    result = subprocess.run(
        f"ping -c 2 {host}", shell=True, capture_output=True, text=True, timeout=10
    )
    return jsonify({"stdout": result.stdout, "returncode": result.returncode})


@app.route("/convert")
def convert():
    """Convert a file format — both filename and format are injectable."""
    filename = request.args.get("file", "")
    fmt = request.args.get("format", "pdf")

    # VULNERABLE: both HTTP params go into the command string
    cmd = f"libreoffice --headless --convert-to {fmt} {filename}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return jsonify({"output": result.stdout, "error": result.stderr})


@app.route("/whois")
def whois():
    domain = request.args.get("domain", "")
    # VULNERABLE: domain from query string
    out = subprocess.run(
        "whois " + domain, shell=True, capture_output=True, text=True
    )
    return jsonify({"result": out.stdout})


if __name__ == "__main__":
    app.run(debug=True)
