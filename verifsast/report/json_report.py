from __future__ import annotations

import json

from ..models import Finding


def render(findings: list[Finding]) -> str:
    return json.dumps([f.model_dump() for f in findings], indent=2)
