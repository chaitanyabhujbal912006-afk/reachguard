"""ReachGuard CLI Entry Point.

End-to-end workflow:
  1. Auto-detect and parse the dependency file (requirements.txt / pyproject.toml / Pipfile.lock).
  2. Query OSV.dev for known vulnerabilities (with a Rich progress bar).
  3. Build the PyCG call graph automatically from --src, OR load a pre-built one.
  4. Detect entry points (main blocks, route handlers).
  5. Check reachability of each vulnerable function.
  6. Render a ranked Rich table sorted: REACHABLE > UNKNOWN > UNREACHABLE.
  7. Optionally write machine-readable JSON via --output-json.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

from reachguard_core.deps import parse_deps
from reachguard_core.osv import query_cves, extract_fixed_version
from reachguard_core.entrypoints import find_entry_points
from reachguard_core.reachability import (
    ReachabilityStatus,
    check_reachability_details,
)
from reachguard_core.sarif import write_sarif_output

app = typer.Typer(
    help="ReachGuard — Reachability-aware dependency vulnerability scanner",
    no_args_is_help=True,
)
console = Console()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RANK = {
    ReachabilityStatus.REACHABLE:   0,
    ReachabilityStatus.UNKNOWN:     1,
    ReachabilityStatus.UNREACHABLE: 2,
}

_STATUS_RICH = {
    ReachabilityStatus.REACHABLE:   "[bold red]REACHABLE[/bold red]",
    ReachabilityStatus.UNKNOWN:     "[yellow]unknown[/yellow]",
    ReachabilityStatus.UNREACHABLE: "[dim green]unreachable[/dim green]",
}

_SEVERITY_STYLE = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[dim]LOW[/dim]",
}


# ---------------------------------------------------------------------------
# A4 — auto-invoke PyCG
# ---------------------------------------------------------------------------

def _build_call_graph(src_path: str) -> dict:
    """Run PyCG against *src_path* and return the resulting call graph dict.

    Invokes ``python -m pycg --package <src_path> -o <tmp.json>``.
    Returns an empty dict (silently) if PyCG is not installed or fails.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pycg", "--package", src_path, "-o", tmp_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            console.print(
                f"[yellow]PyCG warning:[/yellow] {result.stderr.strip()[:200] or 'non-zero exit'}"
            )
        with open(tmp_path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        console.print("[yellow]PyCG not found — install with: pip install pycg[/yellow]")
        return {}
    except subprocess.TimeoutExpired:
        console.print("[yellow]PyCG timed out after 120 s — skipping call graph.[/yellow]")
        return {}
    except Exception as exc:
        console.print(f"[yellow]PyCG error:[/yellow] {exc}")
        return {}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _load_call_graph(call_graph_path: str | None) -> dict:
    """Return a PyCG call graph dict loaded from *call_graph_path*, or {}."""
    if not call_graph_path or not Path(call_graph_path).exists():
        return {}
    try:
        with open(call_graph_path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        console.print(f"[yellow]Warning: could not load call graph: {exc}[/yellow]")
        return {}


# ---------------------------------------------------------------------------
# Severity helper (B5)
# ---------------------------------------------------------------------------

def _get_severity(vuln: dict) -> str:
    """Extract the highest severity label from an OSV advisory dict."""
    # CVSS v3 severity from database_specific (GHSA advisories)
    for affected in vuln.get("affected", []):
        sev = affected.get("database_specific", {}).get("severity", "")
        if sev:
            return sev.upper()
    # Top-level database_specific
    sev = vuln.get("database_specific", {}).get("severity", "")
    if sev:
        return sev.upper()
    # CVSS v3 score -> map to label
    for sev_entry in vuln.get("severity", []):
        score_str = sev_entry.get("score", "")
        try:
            score = float(score_str.split(":")[-1] if ":" in score_str else score_str)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        except ValueError:
            pass
    return "-"


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

Finding = tuple[str, str, str, str, ReachabilityStatus, str, list[str] | None, str | None]
# (package_name, version, cve_id, summary, status, severity, call_path, fixed_version)


def scan(
    requirements_path: str,
    src_path: str | None = None,
    call_graph_path: str | None = None,
) -> list[Finding]:
    """Run a full ReachGuard scan and return the findings list.

    Args:
        requirements_path: Path to requirements.txt / pyproject.toml / Pipfile.lock.
        src_path: Optional path to repo source directory.  If provided and
            *call_graph_path* is not, PyCG is invoked automatically (A4).
        call_graph_path: Optional path to a pre-built PyCG call graph JSON.

    Returns:
        List of ``(name, version, cve_id, summary, status, severity)`` tuples
        sorted by reachability rank (most dangerous first).
    """
    # 1. Parse dependencies ------------------------------------------------
    deps = parse_deps(requirements_path)
    console.print(
        f"\n[bold blue]ReachGuard[/bold blue] scanning "
        f"[cyan]{requirements_path}[/cyan] — "
        f"[bold]{len(deps)}[/bold] pinned dependencies\n"
    )

    # 2. Build / load call graph & detect entry points ---------------------
    call_graph: dict = {}

    if call_graph_path:
        call_graph = _load_call_graph(call_graph_path)
        console.print(f"[blue]Loaded call graph:[/blue] {call_graph_path} "
                      f"({len(call_graph)} nodes)\n")
    elif src_path and Path(src_path).is_dir():
        console.print(f"[blue]Building call graph via PyCG …[/blue] ({src_path})\n")
        call_graph = _build_call_graph(src_path)
        if call_graph:
            console.print(f"[blue]Call graph built:[/blue] {len(call_graph)} nodes\n")

    entry_points: list[str] = []
    if src_path and Path(src_path).is_dir():
        entry_points = find_entry_points(src_path)
        console.print(f"[blue]Entry points detected:[/blue] {len(entry_points)}\n")

    have_graph = bool(call_graph)
    if not have_graph:
        console.print(
            "[yellow]No call graph available — all CVEs will be marked UNKNOWN.[/yellow]\n"
            "[dim]Tip: pass --src <dir> to auto-build one, or --call-graph <file>.[/dim]\n"
        )

    # 3. Query OSV & check reachability with progress bar (B2) ------------
    findings: list[Finding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying OSV.dev…", total=len(deps))

        for name, version in deps:
            progress.update(task, description=f"[cyan]{name}=={version}[/cyan]")
            vulns = query_cves(name, version)

            for vuln in vulns:
                cve_id        = vuln.get("id", "UNKNOWN")
                summary       = (vuln.get("summary") or "No summary provided")[:90]
                severity      = _get_severity(vuln)
                fixed_version = extract_fixed_version(vuln)

                if have_graph:
                    status, call_path = check_reachability_details(call_graph, entry_points, vuln)
                else:
                    status, call_path = ReachabilityStatus.UNKNOWN, None

                findings.append((name, version, cve_id, summary, status, severity, call_path, fixed_version))

            progress.advance(task)

    # 4. Sort: REACHABLE first, UNKNOWN second, UNREACHABLE last ----------
    findings.sort(key=lambda row: _RANK[row[4]])
    return findings


# ---------------------------------------------------------------------------
# Rich report (B5: severity column)
# ---------------------------------------------------------------------------

def print_report(findings: list[Finding], suggest_fixes: bool = False) -> None:
    """Render findings as a colour-coded Rich table."""
    table = Table(
        title="ReachGuard Scan Results",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Package",   style="cyan",  no_wrap=True, min_width=18)
    table.add_column("CVE / ID",  style="bold",  no_wrap=True, min_width=18)
    table.add_column("Severity",  no_wrap=True,  min_width=8)
    table.add_column("Status",    no_wrap=True,  min_width=16)
    table.add_column("Summary",   style="white")

    for name, version, cve_id, summary, status, severity, call_path, fixed_version in findings:
        sev_text = _SEVERITY_STYLE.get(severity, severity)

        # If REACHABLE and call path exists, append call chain trace to summary
        display_summary = summary
        if status == ReachabilityStatus.REACHABLE and call_path:
            # Format path neatly: e.g. "cli.py::main -> Flask.run -> safe_join"
            short_nodes = []
            for node in call_path:
                short_nodes.append(node.rsplit(".", 1)[-1] if "." in node else node)
            chain_str = " -> ".join(short_nodes)
            display_summary += f"\n[dim red]--> Path: {chain_str}[/dim red]"

        # Append remediation patch suggestion if requested or fixed_version available
        if suggest_fixes and fixed_version:
            display_summary += f"\n[bold green]--> Fix: pip install {name}>={fixed_version}[/bold green]"

        table.add_row(
            f"{name}=={version}",
            cve_id,
            sev_text,
            _STATUS_RICH[status],
            display_summary,
        )

    console.print(table)

    reachable_n   = sum(1 for _, _, _, _, s, _, _, _ in findings if s == ReachabilityStatus.REACHABLE)
    unknown_n     = sum(1 for _, _, _, _, s, _, _, _ in findings if s == ReachabilityStatus.UNKNOWN)
    unreachable_n = sum(1 for _, _, _, _, s, _, _, _ in findings if s == ReachabilityStatus.UNREACHABLE)
    critical_n    = sum(1 for _, _, _, _, _, sev, _, _ in findings if sev == "CRITICAL")

    console.print(
        f"\n[bold]Summary:[/bold]  "
        f"[bold red]{reachable_n} reachable[/bold red]  |  "
        f"[yellow]{unknown_n} unknown[/yellow]  |  "
        f"[green]{unreachable_n} unreachable[/green]  |  "
        f"[red]{critical_n} critical severity[/red]  "
        f"[dim](total CVEs: {len(findings)})[/dim]"
    )

    if reachable_n:
        console.print(
            "\n[bold red]! Action required:[/bold red] "
            f"{reachable_n} CVE(s) are reachable from your code -- patch or mitigate these first."
        )


# ---------------------------------------------------------------------------
# JSON output (B3)
# ---------------------------------------------------------------------------

def write_json_output(findings: list[Finding], path: str) -> None:
    """Write findings as structured JSON to *path*."""
    records = [
        {
            "package":       name,
            "version":       version,
            "cve_id":        cve_id,
            "summary":       summary,
            "status":        status.value,
            "severity":      severity,
            "call_path":     call_path,
            "fixed_version": fixed_version,
            "suggested_fix": f"pip install {name}>={fixed_version}" if fixed_version else None,
        }
        for name, version, cve_id, summary, status, severity, call_path, fixed_version in findings
    ]
    out = {
        "total":       len(findings),
        "reachable":   sum(1 for r in records if r["status"] == "REACHABLE"),
        "unknown":     sum(1 for r in records if r["status"] == "UNKNOWN"),
        "unreachable": sum(1 for r in records if r["status"] == "UNREACHABLE"),
        "findings":    records,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    console.print(f"\n[dim]JSON report written to:[/dim] [cyan]{path}[/cyan]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.command()
def main_cmd(
    requirements_path: str = typer.Argument(
        ...,
        help="Path to requirements.txt, pyproject.toml, or Pipfile.lock.",
    ),
    src: str = typer.Option(
        None,
        "--src", "-s",
        help="Source directory. PyCG call graph is built automatically if --call-graph not given.",
    ),
    call_graph: str = typer.Option(
        None,
        "--call-graph", "-g",
        help="Path to a pre-built PyCG call graph JSON (skips auto-build).",
    ),
    output_json: str = typer.Option(
        None,
        "--output-json", "-o",
        help="Write findings as JSON to this file (for CI integration).",
    ),
    fail_on_reachable: bool = typer.Option(
        False,
        "--fail-on-reachable",
        help="Exit with code 1 if any REACHABLE CVEs are found (useful in CI).",
    ),
    suggest_fixes: bool = typer.Option(
        False,
        "--suggest-fixes",
        help="Display recommended pip upgrade patch commands for vulnerabilities.",
    ),
    output_sarif: str = typer.Option(
        None,
        "--output-sarif",
        help="Write findings in SARIF v2.1.0 format (for GitHub Security Code Scanning tab).",
    ),
) -> None:
    """Scan dependencies for CVEs and rank by reachability."""
    findings = scan(requirements_path, src_path=src, call_graph_path=call_graph)

    if findings:
        print_report(findings, suggest_fixes=suggest_fixes)
        if output_json:
            write_json_output(findings, output_json)
        if output_sarif:
            write_sarif_output(findings, output_sarif, requirements_path=requirements_path)
            console.print(f"\n[dim]SARIF report written to:[/dim] [cyan]{output_sarif}[/cyan]")
        if fail_on_reachable:
            n = sum(1 for _, _, _, _, s, _, _, _ in findings if s == ReachabilityStatus.REACHABLE)
            if n:
                raise typer.Exit(code=1)
    else:
        console.print("[bold green]No vulnerabilities found.[/bold green]")


if __name__ == "__main__":
    app()
