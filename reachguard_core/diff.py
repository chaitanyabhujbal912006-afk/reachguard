"""Git diff PR incremental scanning for ReachGuard.

Extracts modified files and modified functions from `git diff <base_branch>`
and filters scan findings to highlight vulnerabilities whose reachability path
passes through code modified in the current branch / PR.

Usage:
    diff_scanner = GitDiffScanner(base_ref="main")
    modified_files = diff_scanner.get_modified_files()
    modified_funcs = diff_scanner.get_modified_functions()
"""

import ast
import subprocess
from pathlib import Path

from reachguard_core.logger import get_logger

log = get_logger(__name__)


class GitDiffScanner:
    """Scans git diff output against a base reference branch."""

    def __init__(self, base_ref: str = "main", cwd: str | Path | None = None) -> None:
        self.base_ref = base_ref
        self.cwd = str(cwd) if cwd else "."

    def get_modified_files(self) -> set[str]:
        """Return set of file paths modified between HEAD and base_ref."""
        try:
            cmd = ["git", "diff", "--name-only", f"{self.base_ref}...HEAD"]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=self.cwd, timeout=10)
            if res.returncode != 0:
                # Fallback to direct diff
                cmd = ["git", "diff", "--name-only", self.base_ref]
                res = subprocess.run(cmd, capture_output=True, text=True, cwd=self.cwd, timeout=10)

            if res.returncode != 0:
                log.warning("git diff failed: %s", res.stderr)
                return set()

            files = {line.strip() for line in res.stdout.splitlines() if line.strip().endswith(".py")}
            log.debug("GitDiffScanner: found %d modified .py files against %s", len(files), self.base_ref)
            return files
        except Exception as exc:
            log.warning("GitDiffScanner error: %s", exc)
            return set()

    def get_modified_functions(self) -> set[str]:
        """Return set of function names modified in the diff."""
        mod_files = self.get_modified_files()
        if not mod_files:
            return set()

        funcs: set[str] = set()
        for filepath in mod_files:
            full_path = Path(self.cwd) / filepath
            if not full_path.exists():
                continue
            try:
                source = full_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(full_path))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        funcs.add(node.name)
            except Exception as exc:
                log.debug("Skipping AST parse for %s: %s", filepath, exc)

        log.debug("GitDiffScanner: extracted %d candidate modified functions", len(funcs))
        return funcs

    def filter_findings_by_diff(
        self,
        findings: list[tuple],
        modified_funcs: set[str] | None = None,
    ) -> list[tuple]:
        """Filter/annotate findings so only those touching modified code are highlighted."""
        if modified_funcs is None:
            modified_funcs = self.get_modified_functions()

        if not modified_funcs:
            log.debug("No modified functions found in git diff — returning all findings")
            return findings

        pr_findings = []
        for finding in findings:
            # Finding structure: (name, version, cve_id, summary, status, severity, call_path, fixed_version)
            call_path = finding[6]
            if call_path:
                # Check if any node in call_path mentions a modified function
                touches_diff = any(
                    any(m_func in node for node in call_path)
                    for m_func in modified_funcs
                )
                if touches_diff:
                    pr_findings.append(finding)
            else:
                pr_findings.append(finding)

        log.debug("Filtered findings: %d pass through git diff changes", len(pr_findings))
        return pr_findings
