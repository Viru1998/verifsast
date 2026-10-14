# CWE-22: Safe — Flask with werkzeug.utils.safe_join()
# safe_join() raises NotFound/BadRequest if the path would escape the base dir.

import os
from flask import Flask, send_file, abort
from werkzeug.utils import safe_join

app = Flask(__name__)

UPLOAD_DIR = "/var/www/uploads"


@app.route("/download/<path:filename>")
def download(filename):
    """
    Serve an uploaded file.
    SAFE: werkzeug.utils.safe_join() raises an exception (NotFound) if
          filename would escape UPLOAD_DIR.
    """
    try:
        # safe_join raises werkzeug.exceptions.NotFound if path escapes base
        safe_path = safe_join(UPLOAD_DIR, filename)
    except Exception:
        abort(404)

    if not os.path.isfile(safe_path):
        abort(404)

    return send_file(safe_path)


@app.route("/preview/<path:filename>")
def preview(filename):
    """Preview a text file — also uses safe_join."""
    try:
        safe_path = safe_join(UPLOAD_DIR, filename)
    except Exception:
        abort(400)

    if not safe_path.endswith(".txt"):
        abort(403)

    try:
        with open(safe_path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        abort(404)


if __name__ == "__main__":
    app.run(debug=False)
