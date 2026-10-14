#!/usr/bin/env python3
"""
run_bench.py — VerifSAST benchmark runner

Evaluates Semgrep and Bandit against the benchmark cases and prints
precision / recall / F1 tables (overall and per vulnerability class).

Usage:
    python benchmark/run_bench.py

Requirements:
    pip install semgrep bandit pyyaml rich
"""

import json
import pathlib
import subprocess
import sys

import yaml
from rich.console import Console
from rich.table import Table

BENCH_DIR   = pathlib.Path(__file__).parent
CASES_DIR   = BENCH_DIR / "cases"
LABELS_FILE = BENCH_DIR / "labels.yaml"

console = Console()


# ── helpers ──────────────────────────────────────────────────────────────────

def load_labels():
    """Return the list of case dicts from labels.yaml."""
    with LABELS_FILE.open() as f:
        data = yaml.safe_load(f)
    return data["cases"]


def resolve_case_paths(cases):
    """
    Return two sets of absolute path strings:
      - vulnerable_files
      - safe_files
    """
    vuln, safe = set(), set()
    for c in cases:
        abs_path = str((BENCH_DIR / c["file"]).resolve())
        if c["label"] == "vulnerable":
            vuln.add(abs_path)
        else:
            safe.add(abs_path)
    return vuln, safe


# ── runner: Semgrep ──────────────────────────────────────────────────────────

def run_semgrep():
    """
    Run Semgrep over the cases directory.
    Returns a set of absolute file paths that Semgrep flagged.
    """
    console.print("[bold cyan]Running Semgrep…[/bold cyan]")
    cmd = [
        "semgrep",
        "--json",
        "--config", "p/python",
        "--config", "p/secrets",
        str(CASES_DIR),
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        console.print("[red]semgrep not found — skipping Semgrep.[/red]")
        return set()
    except subprocess.TimeoutExpired:
        console.print("[red]Semgrep timed out after 5 minutes.[/red]")
        return set()

    flagged = set()
    try:
        output = json.loads(result.stdout)
        for finding in output.get("results", []):
            path = str(pathlib.Path(finding["path"]).resolve())
            flagged.add(path)
    except json.JSONDecodeError:
        console.print("[yellow]Warning: Semgrep returned non-JSON output.[/yellow]")
        if result.stderr:
            console.print(result.stderr[:500])

    console.print(f"  Semgrep flagged [bold]{len(flagged)}[/bold] file(s)")
    return flagged


# ── runner: Bandit ───────────────────────────────────────────────────────────

def run_bandit():
    """
    Run Bandit over the cases directory.
    Returns a set of absolute file paths that Bandit flagged with
    severity MEDIUM or HIGH (at any confidence level).
    """
    console.print("[bold cyan]Running Bandit…[/bold cyan]")
    cmd = [
        "bandit",
        "-r",
        "-f", "json",
        "-q",
        "--severity-level", "medium",
        str(CASES_DIR),
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        console.print("[red]bandit not found — skipping Bandit.[/red]")
        return set()
    except subprocess.TimeoutExpired:
        console.print("[red]Bandit timed out.[/red]")
        return set()

    flagged = set()
    # Bandit exits with code 1 if it finds issues — that is normal
    raw = result.stdout or result.stderr
    try:
        output = json.loads(raw)
        for issue in output.get("results", []):
            path = str(pathlib.Path(issue["filename"]).resolve())
            flagged.add(path)
    except json.JSONDecodeError:
        # Try stdout then stderr separately
        for stream in (result.stdout, result.stderr):
            if stream:
                try:
                    output = json.loads(stream)
                    for issue in output.get("results", []):
                        path = str(pathlib.Path(issue["filename"]).resolve())
                        flagged.add(path)
                    break
                except json.JSONDecodeError:
                    pass
        else:
            console.print("[yellow]Warning: Bandit returned non-JSON output.[/yellow]")

    console.print(f"  Bandit flagged [bold]{len(flagged)}[/bold] file(s)")
    return flagged


# ── metrics ──────────────────────────────────────────────────────────────────

def compute_metrics(flagged, vuln_files, safe_files):
    """
    Compute TP, FP, FN, TN, precision, recall, F1.
    """
    tp = len(flagged & vuln_files)
    fp = len(flagged & safe_files)
    fn = len(vuln_files - flagged)
    tn = len(safe_files - flagged)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                precision=precision, recall=recall, f1=f1)


# ── table rendering ──────────────────────────────────────────────────────────

def fmt(value):
    """Format a float as a 4-decimal string, or an int as-is."""
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def print_overall_table(results):
    """Print the top-level scanner comparison table."""
    table = Table(
        title="[bold]Overall Scanner Metrics[/bold]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Scanner",   style="cyan",  no_wrap=True)
    table.add_column("Precision", justify="right")
    table.add_column("Recall",    justify="right")
    table.add_column("F1",        justify="right")
    table.add_column("TP",        justify="right")
    table.add_column("FP",        justify="right")
    table.add_column("FN",        justify="right")
    table.add_column("TN",        justify="right")

    for name, m in results.items():
        table.add_row(
            name,
            fmt(m["precision"]),
            fmt(m["recall"]),
            fmt(m["f1"]),
            fmt(m["tp"]),
            fmt(m["fp"]),
            fmt(m["fn"]),
            fmt(m["tn"]),
        )
    console.print(table)


def print_per_class_table(semgrep_flagged, bandit_flagged, cases):
    """Print per-vulnerability-class breakdowns for each scanner."""
    # Group cases by class
    classes = {}
    for c in cases:
        cls = c["class"]
        if cls not in classes:
            classes[cls] = {"vuln": set(), "safe": set()}
        abs_path = str((BENCH_DIR / c["file"]).resolve())
        if c["label"] == "vulnerable":
            classes[cls]["vuln"].add(abs_path)
        else:
            classes[cls]["safe"].add(abs_path)

    for scanner_name, flagged in [("Semgrep", semgrep_flagged), ("Bandit", bandit_flagged)]:
        table = Table(
            title=f"[bold]{scanner_name} — Per-Class Breakdown[/bold]",
            show_header=True,
            header_style="bold blue",
        )
        table.add_column("Class",     style="green", no_wrap=True)
        table.add_column("Precision", justify="right")
        table.add_column("Recall",    justify="right")
        table.add_column("F1",        justify="right")
        table.add_column("TP",        justify="right")
        table.add_column("FP",        justify="right")
        table.add_column("FN",        justify="right")
        table.add_column("TN",        justify="right")

        for cls in sorted(classes):
            vuln = classes[cls]["vuln"]
            safe = classes[cls]["safe"]
            m = compute_metrics(flagged, vuln, safe)
            table.add_row(
                cls,
                fmt(m["precision"]),
                fmt(m["recall"]),
                fmt(m["f1"]),
                fmt(m["tp"]),
                fmt(m["fp"]),
                fmt(m["fn"]),
                fmt(m["tn"]),
            )
        console.print(table)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    console.rule("[bold yellow]VerifSAST Benchmark[/bold yellow]")
    console.print(f"Cases directory : [dim]{CASES_DIR}[/dim]")
    console.print(f"Labels file     : [dim]{LABELS_FILE}[/dim]\n")

    # 1. Load labels
    cases = load_labels()
    vuln_files, safe_files = resolve_case_paths(cases)
    console.print(
        f"Loaded [bold]{len(cases)}[/bold] cases "
        f"([green]{len(vuln_files)} vulnerable[/green], "
        f"[blue]{len(safe_files)} safe[/blue])\n"
    )

    # 2. Run scanners
    semgrep_flagged = run_semgrep()
    bandit_flagged  = run_bandit()
    combined        = semgrep_flagged | bandit_flagged
    console.print()

    # 3. Compute metrics
    results = {
        "Semgrep":  compute_metrics(semgrep_flagged, vuln_files, safe_files),
        "Bandit":   compute_metrics(bandit_flagged,  vuln_files, safe_files),
        "Combined": compute_metrics(combined,         vuln_files, safe_files),
    }

    # 4. Print overall table
    print_overall_table(results)
    console.print()

    # 5. Print per-class breakdown
    print_per_class_table(semgrep_flagged, bandit_flagged, cases)

    console.rule("[bold yellow]Done[/bold yellow]")
    sys.exit(0)


if __name__ == "__main__":
    main()
