# CWE-22: Path Traversal — Flask send_file() with request.args path
# Vulnerability: file path comes directly from an HTTP query parameter

import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

UPLOAD_DIR = "/var/www/uploads"


@app.route("/download")
def download():
    """Serve a file by name from the uploads directory — vulnerable."""
    # VULNERABLE: 'file' param goes directly to send_file without sanitisation
    filename = request.args.get("file", "")
    if not filename:
        abort(400)

    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)


@app.route("/static-serve")
def static_serve():
    """Another endpoint that reads a file from user input."""
    path = request.args.get("path", "")
    # VULNERABLE: attacker can request /static-serve?path=../../etc/passwd
    full_path = UPLOAD_DIR + "/" + path
    try:
        with open(full_path, "rb") as f:
            return f.read()
    except OSError:
        abort(404)


if __name__ == "__main__":
    app.run(debug=True)
