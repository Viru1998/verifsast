from verifsast.models import Finding, Severity, Verdict, VerdictLabel


def test_finding_defaults():
    f = Finding(file="foo.py", line=1, rule_id="B101", message="assert used", source="bandit")
    assert f.source == "bandit"
    assert f.severity == Severity.MEDIUM


def test_finding_roundtrip():
    f = Finding(
        file="app.py",
        line=42,
        rule_id="CWE-89",
        cwe="CWE-89",
        owasp="A05",
        severity=Severity.HIGH,
        message="SQL injection",
        snippet="cursor.execute(query % user_input)",
        source="semgrep",
    )
    data = f.model_dump()
    f2 = Finding(**data)
    assert f == f2


def test_verdict():
    f = Finding(file="x.py", line=1, rule_id="B301", message="pickle", source="bandit")
    v = Verdict(finding=f, label=VerdictLabel.CONFIRMED, confidence=0.9, reason="no sanitiser")
    assert v.label == VerdictLabel.CONFIRMED
