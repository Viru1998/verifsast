from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def run_bandit(target: Path) -> list[dict[str, Any]]:
    cmd = [
        "bandit",
        "-r",
        "-f", "json",
        "-q",
        str(target),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # bandit exits 0 (no issues) or 1 (issues found); anything else is an error
    if result.returncode not in (0, 1):
        raise RuntimeError(f"bandit exited {result.returncode}: {result.stderr.strip()}")
    if not result.stdout.strip():
        return []
    data = json.loads(result.stdout)
    return data.get("results", [])
