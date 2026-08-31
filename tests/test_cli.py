"""Unit and integration tests for ReachGuard CLI and logging."""

import logging
from pathlib import Path

from typer.testing import CliRunner

from reachguard_core.cli import _get_severity, app, print_report, write_json_output
from reachguard_core.logger import _JSONFormatter, _PlainFormatter, configure_logging, get_logger
from reachguard_core.reachability import ReachabilityStatus

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "ReachGuard" in result.output


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ReachGuard" in result.output


def test_severity_extraction_cvss():
    vuln_critical = {
        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H:9.8"}]
    }
    assert _get_severity(vuln_critical) == "CRITICAL"

    vuln_high = {
        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N:7.5"}]
    }
    assert _get_severity(vuln_high) == "HIGH"

    vuln_med = {
        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N:5.3"}]
    }
    assert _get_severity(vuln_med) == "MEDIUM"

    vuln_low = {
        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N:2.1"}]
    }
    assert _get_severity(vuln_low) == "LOW"


def test_severity_extraction_database_specific():
    vuln = {
        "database_specific": {"severity": "HIGH"}
    }
    assert _get_severity(vuln) == "HIGH"


def test_print_report_rendering(capsys):
    findings = [
        ("flask", "2.3.2", "CVE-2023-1", "Test summary", ReachabilityStatus.REACHABLE, "HIGH", ["main -> test"], "2.3.3"),
        ("jinja2", "3.1.2", "CVE-2023-2", "Test summary 2", ReachabilityStatus.UNREACHABLE, "LOW", None, None),
    ]
    print_report(findings, suggest_fixes=True)
    # Output rendered via rich console


def test_write_json_output(tmp_path: Path):
    out_file = tmp_path / "out.json"
    findings = [
        ("flask", "2.3.2", "CVE-2023-1", "Test summary", ReachabilityStatus.REACHABLE, "HIGH", ["main -> test"], "2.3.3"),
    ]
    write_json_output(findings, str(out_file))
    assert out_file.exists()


def test_logger_formatters():
    configure_logging(verbose=True, log_format="json")
    log = get_logger("test")
    log.info("test info message")

    plain_fmt = _PlainFormatter()
    record = logging.LogRecord("test", logging.INFO, "path.py", 10, "hello %s", ("world",), None)
    formatted = plain_fmt.format(record)
    assert "INFO " in formatted
    assert "hello world" in formatted

    json_fmt = _JSONFormatter()
    json_formatted = json_fmt.format(record)
    assert '"message": "hello world"' in json_formatted


def test_cli_invalid_severity():
    result = runner.invoke(app, ["--min-severity", "INVALID_SEV"])
    assert result.exit_code == 2
    assert "Error:" in result.output


def test_print_banner_rendering():
    from reachguard_core.cli import print_banner
    # Ensure print_banner executes without error
    print_banner()


def test_cli_quiet_suppresses_banner(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.5\n", encoding="utf-8")
    result = runner.invoke(app, [str(req_file), "--quiet", "--no-cache"])
    assert "🛡️ ReachGuard Security" not in result.output


