# VerifSAST: a static analysis scanner that verifies before it reports

## The pitch

Static analysis tools such as Semgrep and Bandit are good at finding *candidate* security flaws in source code, but they are noisy. Developers drown in false positives, start ignoring the alerts, and real vulnerabilities slip through.

**VerifSAST** runs established scanners over a Python codebase, then verifies each finding before it is reported. It traces whether untrusted input actually reaches the dangerous call, classifies each finding as **Confirmed**, **Likely** or **False positive** with a written reason, maps it to OWASP Top 10 and CWE, and suggests a fix. Success is measured, not claimed. The project includes a labelled benchmark and reports precision and recall against plain Semgrep and Bandit.

It applies the same "verify before you report" principle as my AI vulnerability scanning agent, moved from runtime testing (DAST) to source code (SAST).

## Who it is for

- Developers and small teams who want security feedback on pull requests without alert fatigue.
- Me, as a portfolio project for application security, product security and security engineering roles.

## Scope (v1: keep it small and finished)

**Language:** Python only.

**Five vulnerability classes:**

| Class | CWE | OWASP 2025 |
|---|---|---|
| SQL injection | CWE-89 | A05 Injection |
| OS command injection | CWE-78 | A05 Injection |
| Path traversal | CWE-22 | A01 Broken Access Control |
| Hardcoded secrets | CWE-798 | A04 Cryptographic Failures |
| Insecure deserialisation (pickle, yaml.load) | CWE-502 | A08 Software or Data Integrity Failures |

**Out of scope for v1:** other languages, auto-fixing code, a web UI beyond a simple demo.

## Architecture

```
repo/ ──► 1. Scan ──► 2. Trace ──► 3. Verify ──► 4. Report
          Semgrep      Python ast    rules first,    JSON + SARIF
          Bandit       source→sink   LLM for         + Markdown
                       data flow     hard cases      (PR comment)
```

1. **Scan:** run Semgrep (`p/python`, `p/secrets`) and Bandit and normalise their output into one `Finding` model (file, line, rule, CWE, severity, snippet).
2. **Trace:** use Python's `ast` to check whether the sink is reachable from a source (request args, `input()`, environment, files) within the same function or module, and whether a sanitiser is in between (parameterised query, `shlex.quote`, `os.path.realpath` plus prefix check).
3. **Verify:** deterministic rules decide the clear cases. Only ambiguous ones go to the Claude API with the code context, and it must return structured JSON (verdict, confidence, reason, fix). Every LLM call is logged for auditability. The tool must still run without an API key, using rules only.
4. **Report:** CLI table, JSON, SARIF 2.1.0 (GitHub code scanning reads this) and a Markdown summary for pull request comments.

## Benchmark (this is what makes the project credible)

- Build `benchmark/` with small vulnerable and safe Python snippets for each class, at least 10 true and 10 false cases each, labelled in `labels.yaml`.
- Optionally add known vulnerable apps (for example deliberately vulnerable Flask apps) as a realistic test.
- `make bench` outputs precision, recall and F1 for: Semgrep alone, Bandit alone, and VerifSAST.
- Headline result for the CV and README: *"Reduced false positives by X% versus Semgrep at Y% recall on a labelled benchmark."*

## Tech stack

Python 3.11+, Semgrep, Bandit, `ast`, Pydantic, Typer (CLI), Anthropic Claude API (optional), pytest, GitHub Actions, Docker. Optional: Streamlit demo.

## Repository layout

```
verifsast/
  verifsast/
    cli.py            # typer entry point: verifsast scan <path>
    models.py         # Finding, Verdict (pydantic)
    scanners/         # semgrep.py, bandit.py, normalise.py
    trace/            # ast_flow.py, sources_sinks.py, sanitisers.py
    verify/           # rules.py, llm.py (optional), prompts/
    report/           # json.py, sarif.py, markdown.py
  benchmark/          # cases/, labels.yaml, run_bench.py
  tests/
  .github/workflows/  # ci.yml (tests), self-scan.yml (scan this repo on PRs)
  Dockerfile
  README.md
```

## Milestones

1. **Skeleton:** CLI, `Finding` model, Semgrep + Bandit runners, normalised JSON output, CI with pytest.
2. **Benchmark:** labelled cases for all five classes, plus a baseline score for Semgrep and Bandit alone.
3. **Trace and rules:** AST source-to-sink tracing and sanitiser detection, with benchmark scores compared.
4. **LLM verification:** for ambiguous cases only, with structured output, logging and an offline fallback.
5. **Reporting:** SARIF output, a GitHub Action that comments on pull requests, and a README with results.
6. **Polish:** Docker image, demo GIF, and a write up of the results and limitations.

## Engineering rules

- Detection only. Never execute scanned code.
- Pin scanner versions so results are reproducible.
- Tests for every tracer and rule, and the benchmark runs in CI.
- Honest README: state the limitations (single language, intra-file tracing only in v1).
