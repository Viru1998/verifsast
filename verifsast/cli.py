from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .models import Finding
from .report.json_report import render as json_render
from .scanners.bandit import run_bandit
from .scanners.normalise import from_bandit, from_semgrep
from .scanners.semgrep import run_semgrep

app = typer.Typer(
    help="VerifSAST — static analysis that verifies before it reports.",
    no_args_is_help=True,
)

_FORMATS = ("table", "json", "sarif", "markdown")

# Status/log messages always go to stderr so they never pollute --format json output.
_err = Console(stderr=True)
_out = Console()


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, help="File or directory to scan."),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table | json | sarif | markdown"),
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Skip Semgrep."),
    no_bandit: bool = typer.Option(False, "--no-bandit", help="Skip Bandit."),
) -> None:
    """Scan a Python codebase for security vulnerabilities."""
    if format not in _FORMATS:
        _err.print(f"[red]Unknown format '{format}'. Choose from: {', '.join(_FORMATS)}[/red]")
        raise typer.Exit(2)

    findings: list[Finding] = []

    if not no_semgrep:
        with _err.status("[bold green]Running Semgrep…"):
            try:
                raw = run_semgrep(path)
                findings.extend(from_semgrep(raw))
                _err.log(f"Semgrep: {len(raw)} raw finding(s)")
            except FileNotFoundError:
                _err.log("[yellow]Semgrep not found — skipping (install with: pip install semgrep)[/yellow]")
            except Exception as exc:
                _err.log(f"[yellow]Semgrep error: {exc}[/yellow]")

    if not no_bandit:
        with _err.status("[bold green]Running Bandit…"):
            try:
                raw = run_bandit(path)
                findings.extend(from_bandit(raw))
                _err.log(f"Bandit: {len(raw)} raw finding(s)")
            except FileNotFoundError:
                _err.log("[yellow]Bandit not found — skipping (install with: pip install bandit)[/yellow]")
            except Exception as exc:
                _err.log(f"[yellow]Bandit error: {exc}[/yellow]")

    if format == "json":
        typer.echo(json_render(findings))
    elif format == "table":
        _print_table(findings)
    else:
        _err.print(f"[red]Format '{format}' is not yet implemented.[/red]")
        raise typer.Exit(2)

    raise typer.Exit(1 if findings else 0)


def _print_table(findings: list[Finding]) -> None:
    if not findings:
        _out.print("[green]No findings.[/green]")
        return

    _SEV_COLOR = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    table = Table(title=f"{len(findings)} Finding(s)", show_lines=True)
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("File", overflow="fold")
    table.add_column("Line", justify="right", no_wrap=True)
    table.add_column("Rule", overflow="fold")
    table.add_column("Message", overflow="fold")

    for f in findings:
        color = _SEV_COLOR.get(f.severity.value, "white")
        table.add_row(
            f.source,
            f"[{color}]{f.severity.value}[/{color}]",
            f.file,
            str(f.line),
            f.rule_id,
            f.message,
        )

    _out.print(table)
