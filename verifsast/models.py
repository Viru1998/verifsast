from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerdictLabel(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    FALSE_POSITIVE = "FalsePositive"


class Finding(BaseModel):
    file: str
    line: int
    rule_id: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    message: str
    snippet: Optional[str] = None
    source: str  # "semgrep" | "bandit"


class Verdict(BaseModel):
    finding: Finding
    label: VerdictLabel
    confidence: float  # 0.0–1.0
    reason: str
    fix: Optional[str] = None
