from __future__ import annotations

from ..models import Finding, Severity

_SEMGREP_SEV: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}

_BANDIT_SEV: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def from_semgrep(results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_raw = meta.get("cwe", [])
        if isinstance(cwe_raw, list):
            cwe = cwe_raw[0] if cwe_raw else None
        else:
            cwe = cwe_raw or None
        owasp_raw = meta.get("owasp", [])
        if isinstance(owasp_raw, list):
            owasp = owasp_raw[0] if owasp_raw else None
        else:
            owasp = owasp_raw or None
        findings.append(Finding(
            file=r["path"],
            line=r["start"]["line"],
            rule_id=r["check_id"],
            cwe=cwe,
            owasp=owasp,
            severity=_SEMGREP_SEV.get(extra.get("severity", ""), Severity.MEDIUM),
            message=extra.get("message", "").strip(),
            snippet=extra.get("lines", "").strip() or None,
            source="semgrep",
        ))
    return findings


def from_bandit(results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        cwe_info = r.get("issue_cwe", {})
        cwe = f"CWE-{cwe_info['id']}" if cwe_info and "id" in cwe_info else None
        findings.append(Finding(
            file=r["filename"],
            line=r["line_number"],
            rule_id=r["test_id"],
            cwe=cwe,
            owasp=None,
            severity=_BANDIT_SEV.get(r.get("issue_severity", ""), Severity.MEDIUM),
            message=r.get("issue_text", "").strip(),
            snippet=r.get("code", "").strip() or None,
            source="bandit",
        ))
    return findings
