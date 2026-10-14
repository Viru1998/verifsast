from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def run_semgrep(target: Path) -> list[dict[str, Any]]:
    cmd = [
        "semgrep",
        "--json",
        "--config", "p/python",
        "--config", "p/secrets",
        "--no-git-ignore",
        str(target),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # semgrep exits 0 (no findings) or 1 (findings found); anything else is an error
    if result.returncode not in (0, 1):
        raise RuntimeError(f"semgrep exited {result.returncode}: {result.stderr.strip()}")
    if not result.stdout.strip():
        return []
    data = json.loads(result.stdout)
    return data.get("results", [])
