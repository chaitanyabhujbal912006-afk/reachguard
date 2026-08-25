"""Tests for GitDiffScanner module."""

from reachguard_core.diff import GitDiffScanner
from reachguard_core.reachability import ReachabilityStatus


def test_diff_scanner_initialization():
    scanner = GitDiffScanner(base_ref="main")
    assert scanner.base_ref == "main"


def test_filter_findings_by_diff_empty():
    scanner = GitDiffScanner(base_ref="main")
    findings = [
        ("flask", "2.3.2", "CVE-2023-1", "Summary", ReachabilityStatus.REACHABLE, "HIGH", ["main -> test"], None)
    ]
    # No modified functions → returns all findings
    filtered = scanner.filter_findings_by_diff(findings, modified_funcs=set())
    assert len(filtered) == 1


def test_filter_findings_by_diff_matching():
    scanner = GitDiffScanner(base_ref="main")
    findings = [
        ("flask", "2.3.2", "CVE-2023-1", "Summary", ReachabilityStatus.REACHABLE, "HIGH", ["app.py::download -> flask.dispatch"], None),
        ("jinja2", "3.1.2", "CVE-2023-2", "Summary 2", ReachabilityStatus.REACHABLE, "LOW", ["other.py::foo -> jinja2.render"], None),
    ]
    # Highlight only findings touching modified function 'download'
    filtered = scanner.filter_findings_by_diff(findings, modified_funcs={"download"})
    assert len(filtered) == 1
    assert filtered[0][0] == "flask"
