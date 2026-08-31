"""ReachGuard CLI Entry Point.

End-to-end workflow:
  1. Auto-detect and parse the dependency file (requirements.txt / pyproject.toml / Pipfile.lock).
  2. Query OSV.dev for known vulnerabilities (with a Rich progress bar, caching, and retries).
  3. Build the PyCG call graph automatically from --src, OR load a pre-built one.
  4. Run import-based pre-filter: packages never imported in source → UNREACHABLE immediately.
  5. Detect entry points (main blocks, route handlers, uvicorn.run etc.).
  6. Check reachability of each vulnerable function via BFS.
  7. Render a ranked Rich table sorted: REACHABLE > UNKNOWN > UNREACHABLE.
  8. Optionally write JSON / SARIF / HTML / CycloneDX SBOM output files.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import typer
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from reachguard_core import __version__
from reachguard_core.cache import OsvCache
from reachguard_core.deps import find_dependency_file, parse_deps
from reachguard_core.diff import GitDiffScanner
from reachguard_core.entrypoints import find_entry_points
from reachguard_core.epss import calculate_risk_score, fetch_epss_scores
from reachguard_core.html_report import write_html_report
from reachguard_core.import_scanner import ImportScanner
from reachguard_core.logger import configure_logging, get_logger
from reachguard_core.osv import extract_fixed_version, query_cves_batch
from reachguard_core.policy import load_policy
from reachguard_core.reachability import (
    ReachabilityStatus,
    check_reachability_details,
)
from reachguard_core.sarif import write_sarif_output
from reachguard_core.sbom import write_sbom_output

app = typer.Typer(
    help="ReachGuard 🛡️ — Refined. Secure. Connected. Reachability-aware dependency vulnerability scanner",
    no_args_is_help=False,
)
console = Console()

log = get_logger(__name__)

# ── Severity ordering ────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "-": 4}

_RANK = {
    ReachabilityStatus.REACHABLE:   0,
    ReachabilityStatus.UNKNOWN:     1,
    ReachabilityStatus.UNREACHABLE: 2,
}

_STATUS_RICH = {
    ReachabilityStatus.REACHABLE:   "[bold red]🚨 REACHABLE[/bold red]",
    ReachabilityStatus.UNKNOWN:     "[yellow]❓ unknown[/yellow]",
    ReachabilityStatus.UNREACHABLE: "[dim green]🛡️ unreachable[/dim green]",
}

_SEVERITY_STYLE = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[dim]LOW[/dim]",
}

# Minimum severity enum for filtering
_SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ── Terminal Banner ───────────────────────────────────────────────────────────

def print_banner() -> None:
    """Render the official ReachGuard ASCII terminal header banner."""
    ascii_art = (
        "█▀█ █▀▀ █▀█ █▀▀ █  █ █▀█ █  █ █▀█ █▀█ █▀▄\n"
        "█▀▄ █▀▀ █▀█ █  █ █▀█ █ █ █  █ █▀█ █▀▄ █▄▀\n"
        "▀ ▀ ▀▀▀ ▀ ▀ ▀▀▀  ▀ ▀ ▀▀▀ ▀▀▀▀ ▀ ▀ ▀ ▀ ▀▀ "
    )
    banner_text = Text()
    banner_text.append("🛡️  ", style="bold red")
    banner_text.append("R E A C H G U A R D\n", style="bold cyan")
    banner_text.append(ascii_art + "\n\n", style="bold blue")
    banner_text.append("Refined. Secure. Connected.\n", style="bold white")
    banner_text.append("Reachability-Aware Dependency Vulnerability Scanner  ", style="dim white")
    banner_text.append(f"v{__version__}", style="bold cyan")

    panel = Panel(
        Align.center(banner_text),
        border_style="bright_blue",
        padding=(1, 3),
        title="[bold cyan]🛡️ ReachGuard Security[/bold cyan]",
        subtitle="[dim]https://github.com/chaitanyabhujbal912006-afk/reachguard[/dim]",
    )
    console.print(panel)



# ── PyCG auto-detection ───────────────────────────────────────────────────────

def _find_pycg_cmd(src_path: str) -> list[str] | None:
    """Locate executable command list for PyCG across python interpreters and venvs."""
    # 1. Active sys.executable
    try:
        res = subprocess.run(
            [sys.executable, "-m", "pycg", "--help"],
            capture_output=True, text=True, timeout=5,
        )
        if res.returncode == 0:
            return [sys.executable, "-m", "pycg"]
    except Exception:
        pass

    # 2. Local virtual environments in cwd or src_path
    candidates = [
        Path.cwd() / "venv" / "Scripts" / "python.exe",
        Path.cwd() / "venv" / "bin" / "python",
        Path.cwd() / ".venv" / "Scripts" / "python.exe",
        Path.cwd() / ".venv" / "bin" / "python",
        Path(src_path) / "venv" / "Scripts" / "python.exe",
        Path(src_path) / "venv" / "bin" / "python",
        Path(src_path) / ".venv" / "Scripts" / "python.exe",
        Path(src_path) / ".venv" / "bin" / "python",
    ]
    for venv_py in candidates:
        if venv_py.is_file():
            try:
                res = subprocess.run(
                    [str(venv_py), "-m", "pycg", "--help"],
                    capture_output=True, text=True, timeout=5,
                )
                if res.returncode == 0:
                    return [str(venv_py), "-m", "pycg"]
            except Exception:
                pass

    # 3. System PATH pycg executable
    import shutil
    pycg_bin = shutil.which("pycg")
    if pycg_bin:
        return [pycg_bin]

    return None


def _build_call_graph(src_path: str) -> dict:
    """Run PyCG against *src_path* and return the resulting call graph dict.

    Returns an empty dict (silently) if PyCG is not installed or fails.
    """
    pycg_cmd = _find_pycg_cmd(src_path)
    if not pycg_cmd:
        console.print("[yellow]PyCG not found — install with: pip install pycg[/yellow]")
        log.warning("PyCG not found — call graph unavailable.")
        return {}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        cmd = pycg_cmd + ["--package", src_path, "-o", tmp_path]
        log.debug("Running PyCG: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            msg = result.stderr.strip()[:200] or "non-zero exit"
            console.print(f"[yellow]PyCG warning:[/yellow] {msg}")
            log.warning("PyCG non-zero exit: %s", msg)
        try:
            with open(tmp_path, encoding="utf-8") as fh:
                graph = json.load(fh)
            log.debug("PyCG call graph: %d nodes", len(graph))
            return graph
        except (FileNotFoundError, json.JSONDecodeError) as parse_exc:
            console.print(
                f"[yellow]PyCG output unreadable ({parse_exc.__class__.__name__}) — "
                "skipping call graph.[/yellow]"
            )
            log.warning("PyCG output unreadable: %s", parse_exc)
            return {}
    except FileNotFoundError:
        console.print("[yellow]PyCG not found — install with: pip install pycg[/yellow]")
        return {}
    except subprocess.TimeoutExpired:
        console.print("[yellow]PyCG timed out after 120 s — skipping call graph.[/yellow]")
        log.warning("PyCG timed out after 120s")
        return {}
    except Exception as exc:
        console.print(f"[yellow]PyCG error:[/yellow] {exc}")
        log.warning("PyCG error: %s", exc)
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
            graph = json.load(fh)
        log.debug("Loaded call graph from %s (%d nodes)", call_graph_path, len(graph))
        return graph
    except Exception as exc:
        console.print(f"[yellow]Warning: could not load call graph: {exc}[/yellow]")
        log.warning("Could not load call graph %s: %s", call_graph_path, exc)
        return {}


# ── Severity helper ───────────────────────────────────────────────────────────

def _get_severity(vuln: dict) -> str:
    """Extract the highest severity label from an OSV advisory dict."""
    for affected in vuln.get("affected", []):
        sev = affected.get("database_specific", {}).get("severity", "")
        if sev:
            return sev.upper()
    sev = vuln.get("database_specific", {}).get("severity", "")
    if sev:
        return sev.upper()
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


# ── Core scan logic ───────────────────────────────────────────────────────────

Finding = tuple[str, str, str, str, ReachabilityStatus, str, list[str] | None, str | None]
# (package_name, version, cve_id, summary, status, severity, call_path, fixed_version)


def scan(
    requirements_path: str | None = None,
    src_path: str | None = None,
    call_graph_path: str | None = None,
    config_path: str | None = None,
    min_severity: str | None = None,
    only_reachable: bool = False,
    timeout: int = 10,
    cache: OsvCache | None = None,
    max_workers: int = 10,
    verbose: bool = False,
) -> list[Finding]:
    """Run a full ReachGuard scan and return the findings list.

    Args:
        requirements_path: Path to requirements file, pyproject.toml, lockfile,
            or project directory. Defaults to auto-discovering in current directory.
        src_path:       Source directory. PyCG + import scanner used if provided.
        call_graph_path: Path to a pre-built PyCG call graph JSON.
        config_path:    Path to policy file (.reachguardignore / reachguard.toml).
        min_severity:   Minimum severity to report (LOW/MEDIUM/HIGH/CRITICAL).
        only_reachable: If True, suppress UNKNOWN and UNREACHABLE findings.
        timeout:        OSV HTTP request timeout in seconds.
        cache:          OsvCache instance (None to skip caching).
        max_workers:    Max concurrent OSV HTTP threads.
        verbose:        Whether to print extra diagnostic info.

    Returns:
        List of Finding tuples sorted by reachability rank (most dangerous first).
    """
    # ── Auto-discover dependency file ────────────────────────────────────────
    try:
        dep_file, _dep_fmt = find_dependency_file(requirements_path)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Could not find dependency file — {exc}")
        log.error("Dependency file discovery failed: %s", exc, exc_info=True)
        raise typer.Exit(code=2)

    if src_path is None:
        if requirements_path and Path(requirements_path).is_dir():
            src_path = requirements_path
        elif dep_file:
            src_path = str(dep_file.parent)
        else:
            src_path = "."

    # ── Parse dependencies ───────────────────────────────────────────────────
    try:
        deps = parse_deps(requirements_path)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] Failed to parse dependencies — {exc}")
        log.error("Dependency parsing failed: %s", exc, exc_info=True)
        raise typer.Exit(code=2)

    # Warn on duplicate packages
    seen_pkgs: dict[str, str] = {}
    for name, ver in deps:
        if name in seen_pkgs and seen_pkgs[name] != ver:
            console.print(
                f"[yellow]Warning:[/yellow] Duplicate package '{name}' "
                f"(versions {seen_pkgs[name]} and {ver}) — using {ver}"
            )
        seen_pkgs[name] = ver

    target_display = str(dep_file) if dep_file else (requirements_path or "active environment")

    console.print(
        f"\n[bold blue]ReachGuard[/bold blue] [dim]v{__version__}[/dim] scanning "
        f"[cyan]{target_display}[/cyan] — "
        f"[bold]{len(deps)}[/bold] dependencies\n"
    )

    policy = load_policy(config_path)

    # ── Build / load call graph & detect entry points ────────────────────────
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
    import_scanner: ImportScanner | None = None

    if src_path and Path(src_path).is_dir():
        entry_points = find_entry_points(src_path)
        console.print(f"[blue]Entry points detected:[/blue] {len(entry_points)}\n")
        # Always build the import scanner — it's fast (AST-only) and reduces false UNKNOWNs
        import_scanner = ImportScanner(src_path)
        imported_pkgs = import_scanner.scan()
        log.debug("Import scanner found %d imported packages", len(imported_pkgs))
        if verbose:
            console.print(
                f"[dim]Import scanner:[/dim] {len(imported_pkgs)} packages imported in source\n"
            )

    have_graph = bool(call_graph)
    if not have_graph:
        msg = "[yellow]No call graph available"
        if import_scanner:
            msg += " — using import-based pre-filter to detect UNREACHABLE packages"
        else:
            msg += " — all CVEs will be marked UNKNOWN"
        msg += ".[/yellow]"
        console.print(msg + "\n")
        if not import_scanner:
            console.print(
                "[dim]Tip: pass --src <dir> to auto-build one, or --call-graph <file>.[/dim]\n"
            )

    # ── Severity filter threshold ────────────────────────────────────────────
    min_sev_idx = _SEVERITY_LEVELS.index(min_severity.upper()) if min_severity else 0

    # ── Query OSV & check reachability with progress bar ─────────────────────
    findings: list[Finding] = []
    ignored_count = 0
    filtered_sev_count = 0
    done_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying OSV.dev …", total=len(deps))

        def _advance():
            nonlocal done_count
            done_count += 1
            progress.update(task, advance=1, description=f"Querying OSV.dev [{done_count}/{len(deps)}] …")

        batch_results = query_cves_batch(
            deps,
            max_workers=max_workers,
            callback=_advance,
            timeout=timeout,
            cache=cache,
        )

        for (name, version), vulns in batch_results.items():
            for vuln in vulns:
                cve_id        = vuln.get("id", "UNKNOWN")
                summary       = (vuln.get("summary") or "No summary provided")[:90]
                severity      = _get_severity(vuln)
                fixed_version = extract_fixed_version(vuln)

                # Policy suppression
                is_suppressed, reason = policy.is_ignored(cve_id, name)
                if is_suppressed:
                    ignored_count += 1
                    log.debug("Suppressed %s for %s==%s: %s", cve_id, name, version, reason)
                    continue

                # Minimum severity filter
                sev_idx = _SEVERITY_LEVELS.index(severity) if severity in _SEVERITY_LEVELS else 4
                if sev_idx < min_sev_idx:
                    filtered_sev_count += 1
                    continue

                # Reachability check
                if have_graph:
                    status, call_path = check_reachability_details(
                        call_graph, entry_points, vuln,
                        import_scanner=import_scanner, package_name=name,
                    )
                elif import_scanner:
                    # No call graph but have import scanner — use it as sole signal
                    status, call_path = check_reachability_details(
                        {}, [], vuln,
                        import_scanner=import_scanner, package_name=name,
                    )
                else:
                    status, call_path = ReachabilityStatus.UNKNOWN, None

                # --only-reachable filter
                if only_reachable and status != ReachabilityStatus.REACHABLE:
                    continue

                findings.append((name, version, cve_id, summary, status, severity, call_path, fixed_version))
                log.debug("Finding: %s==%s %s [%s][%s]", name, version, cve_id, severity, status.value)

    # ── Cache stats ──────────────────────────────────────────────────────────
    if cache and verbose:
        stats = cache.stats()
        console.print(
            f"[dim]Cache: {stats['hits']} hits / {stats['misses']} misses "
            f"({stats['hit_rate']:.0%} hit rate)[/dim]\n"
        )

    if ignored_count:
        console.print(
            f"[dim]Policy suppression:[/dim] [yellow]{ignored_count} "
            "vulnerability rule(s) ignored by policy.[/yellow]\n"
        )
    if filtered_sev_count:
        console.print(
            f"[dim]Severity filter:[/dim] {filtered_sev_count} finding(s) below "
            f"--min-severity threshold hidden.\n"
        )

    # ── Sort: REACHABLE first, then by severity ───────────────────────────────
    findings.sort(key=lambda row: (
        _RANK[row[4]],
        _SEVERITY_ORDER.get(row[5], 4),
    ))
    return findings


# ── Rich report ───────────────────────────────────────────────────────────────

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

        display_summary = summary
        if status == ReachabilityStatus.REACHABLE and call_path:
            short_nodes = [
                node.rsplit(".", 1)[-1] if "." in node else node
                for node in call_path
            ]
            display_summary += f"\n[dim red]--> Path: {' -> '.join(short_nodes)}[/dim red]"

        if suggest_fixes and fixed_version:
            display_summary += (
                f"\n[bold green]--> Fix: pip install {name}>={fixed_version}[/bold green]"
            )

        table.add_row(
            f"{name}=={version}",
            cve_id,
            sev_text,
            _STATUS_RICH[status],
            display_summary,
        )

    console.print(table)

    reachable_n   = sum(1 for *_, s, _, _, _ in findings if s == ReachabilityStatus.REACHABLE)
    unknown_n     = sum(1 for *_, s, _, _, _ in findings if s == ReachabilityStatus.UNKNOWN)
    unreachable_n = sum(1 for *_, s, _, _, _ in findings if s == ReachabilityStatus.UNREACHABLE)
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


# ── JSON output ───────────────────────────────────────────────────────────────

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
        "reachguard_version": __version__,
        "total":              len(findings),
        "reachable":          sum(1 for r in records if r["status"] == "REACHABLE"),
        "unknown":            sum(1 for r in records if r["status"] == "UNKNOWN"),
        "unreachable":        sum(1 for r in records if r["status"] == "UNREACHABLE"),
        "findings":           records,
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        console.print(f"\n[dim]JSON report written to:[/dim] [cyan]{path}[/cyan]")
    except OSError as exc:
        console.print(f"[bold red]Error writing JSON output:[/bold red] {exc}")
        log.error("Failed to write JSON output to %s: %s", path, exc)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ReachGuard [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()


@app.command()
def main_cmd(
    requirements_path: str = typer.Argument(
        None,
        help="Path to requirements file, pyproject.toml, lockfile, or project directory (defaults to current directory).",
    ),
    src: str = typer.Option(
        None,
        "--src", "-s",
        help="Source directory. PyCG call graph and import scanner run automatically.",
    ),
    call_graph: str = typer.Option(
        None,
        "--call-graph", "-g",
        help="Path to a pre-built PyCG call graph JSON (skips auto-build).",
    ),
    output_json: str = typer.Option(
        None,
        "--output-json", "-o",
        help="Write findings as JSON to this file.",
    ),
    fail_on_reachable: bool = typer.Option(
        False,
        "--fail-on-reachable",
        help="Exit code 1 if any REACHABLE CVEs found (useful in CI).",
    ),
    exit_code_mode: str = typer.Option(
        "reachable",
        "--exit-code",
        help="Exit code strategy: 'none' (always 0), 'any' (1 on any CVE), 'reachable' (1 on REACHABLE only).",
    ),
    suggest_fixes: bool = typer.Option(
        False,
        "--suggest-fixes",
        help="Display recommended pip upgrade commands for vulnerabilities.",
    ),
    output_sarif: str = typer.Option(
        None,
        "--output-sarif",
        help="Write findings in SARIF v2.1.0 format (GitHub Code Scanning).",
    ),
    output_html: str = typer.Option(
        None,
        "--output-html",
        help="Write an interactive HTML dashboard report.",
    ),
    output_sbom: str = typer.Option(
        None,
        "--output-sbom",
        help="Write CycloneDX v1.5 JSON SBOM.",
    ),
    config: str = typer.Option(
        None,
        "--config", "-c",
        help="Policy suppression config file (.reachguardignore / reachguard.toml).",
    ),
    min_severity: str = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL.",
    ),
    only_reachable: bool = typer.Option(
        False,
        "--only-reachable",
        help="Show only REACHABLE findings (hides UNKNOWN and UNREACHABLE).",
    ),
    timeout: int = typer.Option(
        10,
        "--timeout",
        help="OSV HTTP request timeout in seconds (default: 10).",
    ),
    max_workers: int = typer.Option(
        10,
        "--max-workers",
        help="Max concurrent OSV HTTP worker threads (default: 10).",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable disk-based OSV response cache.",
    ),
    cache_dir: str = typer.Option(
        None,
        "--cache-dir",
        help="Custom cache directory path (default: ~/.cache/reachguard/).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Print debug info: raw API responses, cache stats, import scanner details.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Suppress all output except errors (CI-friendly).",
    ),
    log_file: str = typer.Option(
        None,
        "--log-file",
        help="Write structured log output to this file.",
    ),
    log_format: str = typer.Option(
        "plain",
        "--log-format",
        help="Log format: 'plain' (default) or 'json' (for SIEM/Splunk).",
    ),
    epss: bool = typer.Option(
        False,
        "--epss",
        help="Fetch EPSS exploit probability scores from first.org API and display risk rating.",
    ),
    diff: str = typer.Option(
        None,
        "--diff",
        help="Git base reference branch (e.g. 'main') for PR incremental reachability scanning.",
    ),
    version: bool = typer.Option(
        False,
        "--version", "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print ReachGuard version and exit.",
    ),
) -> None:
    """Scan dependencies for CVEs and rank by reachability."""
    # ── Configure logging ────────────────────────────────────────────────────
    configure_logging(
        verbose=verbose,
        quiet=quiet,
        log_file=log_file,
        log_format=log_format,
    )

    if not quiet:
        print_banner()

    # ── Validate min_severity option ─────────────────────────────────────────
    if min_severity and min_severity.upper() not in _SEVERITY_LEVELS:
        console.print(
            f"[bold red]Error:[/bold red] --min-severity must be one of "
            f"{', '.join(_SEVERITY_LEVELS)}. Got: '{min_severity}'"
        )
        raise typer.Exit(code=2)

    # ── CI mode: disable Rich markup if running in CI ─────────────────────────
    ci_mode = os.environ.get("CI", "").lower() in {"true", "1", "yes"}
    if ci_mode:
        log.debug("CI mode detected — Rich markup suppressed in some outputs")

    # ── Build OSV cache ───────────────────────────────────────────────────────
    cache: OsvCache | None = None
    if not no_cache:
        cache = OsvCache(cache_dir=cache_dir, enabled=True)

    dep_file, _ = find_dependency_file(requirements_path)
    target_path_str = str(dep_file) if dep_file else (requirements_path or "requirements.txt")

    # ── Run scan ──────────────────────────────────────────────────────────────
    try:
        findings = scan(
            requirements_path,
            src_path=src,
            call_graph_path=call_graph,
            config_path=config,
            min_severity=min_severity,
            only_reachable=only_reachable,
            timeout=timeout,
            cache=cache,
            max_workers=max_workers,
            verbose=verbose,
        )

        # ── Git diff filtering (--diff main) ──────────────────────────────────
        if diff and findings:
            console.print(f"[blue]Filtering findings against git diff ({diff}…HEAD)…[/blue]\n")
            diff_scanner = GitDiffScanner(base_ref=diff, cwd=src or ".")
            findings = diff_scanner.filter_findings_by_diff(findings)

        # ── EPSS exploit probability scores (--epss) ──────────────────────────
        if epss and findings:
            cve_ids = [row[2] for row in findings]
            epss_map = fetch_epss_scores(cve_ids)
            if epss_map:
                console.print(f"[blue]EPSS scores loaded:[/blue] {len(epss_map)} CVE(s) rated\n")
                # Append EPSS risk score to findings in verbose/terminal output
                for i, row in enumerate(findings):
                    cve = row[2]
                    e_score = epss_map.get(cve, 0.0)
                    r_score = calculate_risk_score(row[4], row[5], e_score)
                    log.debug("EPSS score for %s: epss=%.4f, composite_risk=%.3f", cve, e_score, r_score)

    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[bold red]ReachGuard error:[/bold red] {exc}")
        log.error("Unhandled scan error: %s", exc, exc_info=verbose)
        raise typer.Exit(code=2)

    if not quiet:
        if findings:
            print_report(findings, suggest_fixes=suggest_fixes)
        else:
            console.print("[bold green]✓ No vulnerabilities found.[/bold green]")

    # ── Output files ──────────────────────────────────────────────────────────
    if findings:
        if output_json:
            write_json_output(findings, output_json)
        if output_sarif:
            try:
                write_sarif_output(findings, output_sarif, requirements_path=target_path_str)
                if not quiet:
                    console.print(f"\n[dim]SARIF report written to:[/dim] [cyan]{output_sarif}[/cyan]")
            except OSError as exc:
                console.print(f"[bold red]Error writing SARIF:[/bold red] {exc}")
        if output_html:
            try:
                write_html_report(findings, output_html, requirements_path=target_path_str)
                if not quiet:
                    console.print(f"\n[dim]HTML report written to:[/dim] [cyan]{output_html}[/cyan]")
            except OSError as exc:
                console.print(f"[bold red]Error writing HTML report:[/bold red] {exc}")
        if output_sbom:
            try:
                deps = parse_deps(requirements_path)
                write_sbom_output(findings, deps, output_sbom, requirements_path=target_path_str)
                if not quiet:
                    console.print(f"\n[dim]CycloneDX SBOM written to:[/dim] [cyan]{output_sbom}[/cyan]")
            except OSError as exc:
                console.print(f"[bold red]Error writing SBOM:[/bold red] {exc}")

    # ── Exit code logic ───────────────────────────────────────────────────────
    exit_mode = exit_code_mode.lower()
    if fail_on_reachable:
        exit_mode = "reachable"   # legacy flag takes effect

    if exit_mode == "any" and findings:
        raise typer.Exit(code=1)
    elif exit_mode in ("reachable", ""):
        n_reachable = sum(
            1 for _, _, _, _, s, _, _, _ in findings
            if s == ReachabilityStatus.REACHABLE
        )
        if n_reachable:
            raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
