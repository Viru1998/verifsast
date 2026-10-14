# VerifSAST

> Static analysis that verifies before it reports.

Semgrep and Bandit find candidate vulnerabilities — VerifSAST checks whether they are real before surfacing them. It traces whether untrusted input actually reaches the dangerous call, classifies each finding as **Confirmed**, **Likely**, or **False Positive**, and maps it to OWASP Top 10 and CWE.

## Why

Security scanners are noisy. Developers drown in false positives, start ignoring alerts, and real vulnerabilities slip through. VerifSAST applies a "verify before you report" principle: deterministic AST tracing handles the clear cases, and the Claude API handles the ambiguous ones.

## Vulnerability classes (v1)

| Class | CWE | OWASP 2025 |
|---|---|---|
| SQL injection | CWE-89 | A05 Injection |
| OS command injection | CWE-78 | A05 Injection |
| Path traversal | CWE-22 | A01 Broken Access Control |
| Hardcoded secrets | CWE-798 | A04 Cryptographic Failures |
| Insecure deserialisation | CWE-502 | A08 Software/Data Integrity |

## Installation

Requires Python 3.11+, [Semgrep](https://semgrep.dev/docs/getting-started/), and [Bandit](https://bandit.readthedocs.io/).

```bash
pip install semgrep bandit
pip install -e .
```

For LLM verification (optional):

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=sk-...
```

## Usage

```bash
# Rich table (default)
verifsast scan path/to/project

# JSON — pipe-friendly, stderr stays clean
verifsast scan path/to/project --format json

# Skip one scanner
verifsast scan path/to/project --no-semgrep
verifsast scan path/to/project --no-bandit
```

Exit code `0` = no findings, `1` = findings present (suitable for CI gates).

## Architecture

```
repo/ ──► 1. Scan ──► 2. Trace ──► 3. Verify ──► 4. Report
          Semgrep      Python ast    rules first,    JSON · SARIF
          Bandit       source→sink   LLM for         · Markdown
                       data flow     hard cases      (PR comment)
```

| Step | Status |
|---|---|
| Scan — Semgrep + Bandit runners, normalised `Finding` model | ✅ v0.1 |
| Benchmark — labelled cases, precision/recall vs baseline | 🔜 |
| Trace — AST source-to-sink + sanitiser detection | 🔜 |
| Verify — deterministic rules + optional LLM for ambiguous cases | 🔜 |
| Report — SARIF, GitHub PR comments | 🔜 |

## Tech stack

Python 3.11+, Semgrep, Bandit, `ast`, Pydantic v2, Typer, Rich, Anthropic Claude API (optional), pytest, GitHub Actions, Docker.

## Limitations (v1)

- Python only.
- Intra-file tracing only — cross-module taint is out of scope.
- LLM verification requires an Anthropic API key; the tool works without one using rules only.
