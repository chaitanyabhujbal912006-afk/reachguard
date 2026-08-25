"""Full regression test suite for ReachGuard.

Supports both pytest auto-discovery (via test_* functions) and direct script execution:
    python tests/test_suite.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(str(PROJECT_ROOT))

from reachguard_core.deps import (
    parse_deps,
    _normalise_name,
    find_dependency_file,
    parse_requirements,
    parse_poetry_lock,
    parse_uv_lock,
    parse_pdm_lock,
)
from reachguard_core.entrypoints import find_entry_points
from reachguard_core.reachability import (
    ReachabilityStatus,
    _cg_key_name_forms,
    _is_noise_target,
    _node_matches_target,
    _seed_from_entry_points,
    _target_name_forms,
    extract_vulnerable_functions,
    find_reachability_path,
    check_reachability_details,
    is_reachable,
)
import reachguard_core.cli as m

failures = []


def chk(label, result, expected):
    ok = result == expected
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        print(f"         got={result!r}  expected={expected!r}")
        failures.append(label)
    assert ok, f"Test failure: {label} (got {result!r}, expected {expected!r})"
    return ok


def test_b1_dependency_parsers():
    """B1: Dependency parsers."""
    print("=== B1: Dependency parsers ===")
    test_reqs = PROJECT_ROOT.parent / "test-target" / "examples" / "celery" / "requirements.txt"
    if test_reqs.exists():
        deps = parse_deps(str(test_reqs))
        chk("requirements.txt parses > 10 packages", len(deps) > 10, True)
        chk("flask 2.3.2 found in deps", ("flask", "2.3.2") in deps, True)

    chk("_normalise_name PyYAML", _normalise_name("PyYAML"), "pyyaml")
    chk("_normalise_name Flask_Login", _normalise_name("Flask_Login"), "flask-login")
    chk("_normalise_name my.pkg", _normalise_name("my.pkg"), "my-pkg")

    # Pipfile.lock synthetic test
    fake_piplock = {
        "default": {
            "requests": {"version": "==2.28.0"},
            "flask": {"version": "==2.3.2"},
        },
        "develop": {
            "pytest": {"version": "==7.4.0"},
        },
    }
    tmp_lock = PROJECT_ROOT / "Pipfile.lock"
    with open(tmp_lock, "w") as f:
        json.dump(fake_piplock, f)
    pl_deps = parse_deps(str(tmp_lock))
    if tmp_lock.exists():
        os.unlink(tmp_lock)

    chk("Pipfile.lock parses 3 packages", len(pl_deps), 3)
    chk("Pipfile.lock requests found", ("requests", "2.28.0") in pl_deps, True)


def test_a3_noise_filter():
    """A3: Noise filter."""
    print("=== A3: Noise filter ===")
    noise_cases = [
        ("str.format", True),
        ("int.to_bytes", True),
        ("dict.update", True),
        ("xmlattr", True),
        ("tojson", True),
        ("safe_join", False),
        ("full_load", False),
        ("yaml.load", False),
        ("click.edit", False),
        ("send_from_directory", False),
    ]
    for name, expect in noise_cases:
        chk(f"_is_noise_target({name!r})", _is_noise_target(name), expect)

    # Jinja2 str.format filtering
    jinja_vuln = {
        "id": "GHSA-cpwx-vrp4-4pq7",
        "details": "The |attr filter allows attackers via str.format method to escape the sandbox.",
        "affected": [],
    }
    targets = extract_vulnerable_functions(jinja_vuln)
    chk("str.format filtered from jinja advisory", "str.format" not in targets, True)
    chk("xmlattr filtered from advisory", "xmlattr" not in targets, True)


def test_a2_suffix_matching():
    """A2: Suffix-anchored matching."""
    print("=== A2: Suffix-anchored matching ===")
    SEP = os.sep
    a2_cases = [
        ("werkzeug.safe_join", "safe_join", True),
        (f"src{SEP}app.upload", "load", False),
        (f"src{SEP}app.reload", "load", False),
        ("yaml.full_load", "load", False),
        ("click.edit", "edit", True),
        (f"src{SEP}app.Flask.__call__", "safe_join", False),
    ]
    for key, target, expected in a2_cases:
        chk(f"_node_matches_target({key!r},{target!r})", _node_matches_target(key, target), expected)


def test_a1_entry_points():
    """A1: Entry-point seeding."""
    print("=== A1: Entry-point seeding ===")
    SEP = os.sep
    cg_file = PROJECT_ROOT / "callgraph.json"
    if cg_file.exists():
        with open(cg_file) as f:
            cg = json.load(f)
        user_count = sum(1 for k in cg if SEP in k)

        s1 = _seed_from_entry_points(cg, [f"../test-target/src{SEP}flask{SEP}cli.py::__main__"])
        chk("__main__ seeds all user-code keys", len(s1), user_count)

        s2 = _seed_from_entry_points(cg, ["some/random/app.py::nonexistent_xyz"])
        chk("unknown EP falls back to all keys", len(s2), len(cg))

        s3 = _seed_from_entry_points(cg, ["some/path/app.py::run"])
        chk("EP=run matches >= 1 CG key by basename", len(s3) > 0, True)


def test_end_to_end_reachability():
    """End-to-end reachability & Call Trace."""
    print("=== End-to-end reachability & Call Trace ===")
    SEP = os.sep
    cg_file = PROJECT_ROOT / "callgraph.json"
    if cg_file.exists():
        with open(cg_file) as f:
            cg = json.load(f)

        test_src = PROJECT_ROOT.parent / "test-target" / "src"
        if test_src.exists():
            eps = find_entry_points(str(test_src))
            r1 = is_reachable(cg, eps, "full_dispatch_request")
            chk("full_dispatch_request reachable from __main__", r1, True)

            path = find_reachability_path(cg, eps, "full_dispatch_request")
            chk("find_reachability_path returns non-empty list", isinstance(path, list) and len(path) > 0, True)

        r2 = is_reachable(cg, eps if test_src.exists() else [], "invented_func_xyz_999")
        chk("invented function NOT reachable", r2, False)

        p_inv = find_reachability_path(cg, eps if test_src.exists() else [], "invented_func_xyz_999")
        chk("invented function path returns None", p_inv, None)

        cg_fake = {f"src{SEP}mod.upload": [], f"src{SEP}mod.reload": []}
        r3 = is_reachable(cg_fake, ["app.py::__main__"], "load")
        chk("load does NOT false-match upload/reload", r3, False)


def test_severity_and_patch_extraction():
    """B5 & Auto-remediation: Severity & Patch extraction."""
    print("=== B5 & Auto-remediation: Severity & Patch extraction ===")
    chk("sev from database_specific", m._get_severity({"database_specific": {"severity": "HIGH"}, "affected": []}), "HIGH")
    chk(
        "sev from affected.database_specific",
        m._get_severity({"database_specific": {}, "affected": [{"database_specific": {"severity": "CRITICAL"}}]}),
        "CRITICAL",
    )
    chk("sev empty returns dash", m._get_severity({"affected": [], "database_specific": {}}), "-")

    sample_vuln_fixed = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.3.6"}],
                    }
                ]
            }
        ]
    }
    chk("extract_fixed_version returns fixed version", m.extract_fixed_version(sample_vuln_fixed), "2.3.6")
    chk("extract_fixed_version empty returns None", m.extract_fixed_version({}), None)

    from reachguard_core.sarif import generate_sarif
    sample_findings = [
        ("flask", "2.3.0", "CVE-2023-9999", "Sample summary", ReachabilityStatus.REACHABLE, "HIGH", ["app.py::main", "flask.run"], "2.3.2")
    ]
    sarif_doc = generate_sarif(sample_findings, requirements_path="requirements.txt")
    chk("SARIF version is 2.1.0", sarif_doc.get("version"), "2.1.0")
    chk("SARIF has 1 run", len(sarif_doc.get("runs", [])), 1)
    chk("SARIF result level is error for REACHABLE", sarif_doc["runs"][0]["results"][0]["level"], "error")
    chk("SARIF ruleId matches CVE", sarif_doc["runs"][0]["results"][0]["ruleId"], "CVE-2023-9999")

    from reachguard_core.osv import query_cves_batch
    batch_res = query_cves_batch([("flask", "2.3.2"), ("jinja2", "3.1.2")], max_workers=2)
    chk("query_cves_batch returns dict for all deps", len(batch_res), 2)
    chk("query_cves_batch returns list for flask", isinstance(batch_res.get(("flask", "2.3.2")), list), True)


def test_html_report_generator():
    """Phase 2: HTML Report Generator."""
    print("=== Phase 2: HTML Report Generator ===")
    from reachguard_core.html_report import generate_html_report, write_html_report

    p2_findings = [
        ("werkzeug", "2.3.3", "GHSA-29vq-49wr-vm6x", "High resource usage when parsing multipart", ReachabilityStatus.REACHABLE,   "HIGH",     ["app.main", "flask.dispatch_request", "werkzeug.safe_join"], "3.0.1"),
        ("jinja2",   "3.1.2", "GHSA-q2x7-8rv6-6q7h", "Jinja sandbox breakout via format string",   ReachabilityStatus.UNREACHABLE, "MEDIUM",   None, "3.1.3"),
        ("celery",   "5.2.7", "GHSA-1234-abcd-5678", "Celery deserialization vulnerability",        ReachabilityStatus.UNKNOWN,     "CRITICAL", None, None),
    ]

    html = generate_html_report(p2_findings, requirements_path="requirements.txt")
    chk("generate_html_report returns str", isinstance(html, str), True)
    chk("HTML report is non-empty (>1000 chars)", len(html) > 1000, True)

    chk("HTML has <!DOCTYPE html>",       "<!DOCTYPE html>" in html,      True)
    chk("HTML has <canvas id=donutChart>","donutChart" in html,           True)
    chk("HTML has <canvas id=barChart>",  "barChart" in html,             True)
    chk("HTML has findings table",        "findingsTable" in html,        True)
    chk("HTML has SCAN_DATA json blob",   "const SCAN_DATA" in html,      True)
    chk("HTML has Chart.js CDN script",   "chart.js" in html.lower(),     True)

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as tmp:
        tmp_html_path = tmp.name
    try:
        write_html_report(p2_findings, tmp_html_path, requirements_path="requirements.txt")
        written = Path(tmp_html_path).read_text(encoding="utf-8")
        chk("write_html_report file exists",         Path(tmp_html_path).exists(), True)
        chk("write_html_report file non-empty",      len(written) > 1000,          True)
    finally:
        try:
            os.unlink(tmp_html_path)
        except OSError:
            pass


def test_pre_commit_hooks():
    """Phase 2: Pre-Commit Hook YAML."""
    print("=== Phase 2: Pre-Commit Hook YAML ===")
    hook_file = PROJECT_ROOT / ".pre-commit-hooks.yaml"
    chk(".pre-commit-hooks.yaml exists", hook_file.exists(), True)

    if hook_file.exists():
        raw = hook_file.read_text(encoding="utf-8")
        chk("hooks file is non-empty", len(raw) > 0, True)
        chk("hooks file contains 'id: reachguard'", "id: reachguard" in raw, True)

    toml_file = PROJECT_ROOT / "pyproject.toml"
    if toml_file.exists():
        toml_raw = toml_file.read_text(encoding="utf-8")
        chk("pyproject.toml has reachguard entry point", 'reachguard = "reachguard_core.cli:app"' in toml_raw, True)


def test_cli_output_html():
    """Phase 2: CLI --output-html flag."""
    print("=== Phase 2: CLI --output-html flag ===")
    import inspect
    sig = inspect.signature(m.main_cmd)
    chk("main_cmd has output_html parameter", "output_html" in sig.parameters, True)


def test_cyclonedx_sbom_exporter():
    """Phase 3: CycloneDX SBOM Exporter."""
    print("=== Phase 3: CycloneDX SBOM Exporter ===")
    from reachguard_core.sbom import generate_cyclonedx_sbom, write_sbom_output

    sample_deps = [("flask", "2.3.0"), ("jinja2", "3.1.2")]
    sample_findings_sbom = [
        ("flask", "2.3.0", "CVE-2023-9999", "Sample summary", ReachabilityStatus.REACHABLE, "HIGH", ["app.py::main", "flask.run"], "2.3.2")
    ]
    sbom_doc = generate_cyclonedx_sbom(sample_findings_sbom, sample_deps, requirements_path="requirements.txt")
    chk("CycloneDX bomFormat is CycloneDX", sbom_doc.get("bomFormat"), "CycloneDX")
    chk("CycloneDX specVersion is 1.5", sbom_doc.get("specVersion"), "1.5")


def test_policy_suppression():
    """Phase 3: Policy Suppression Engine."""
    print("=== Phase 3: Policy Suppression Engine ===")
    from reachguard_core.policy import ReachGuardPolicy, load_policy

    pol = ReachGuardPolicy()
    pol.add_ignore_id("CVE-2023-1111", reason="False positive")
    pol.add_ignore_package("malicious-pkg")

    chk("Policy ignores CVE-2023-1111", pol.is_ignored("CVE-2023-1111", "other-pkg")[0], True)
    chk("Policy ignores package malicious-pkg", pol.is_ignored("CVE-2023-9999", "malicious-pkg")[0], True)


def test_extended_ast_detectors():
    """Phase 3: Extended Framework AST Detectors."""
    print("=== Phase 3: Extended Framework AST Detectors ===")
    with tempfile.TemporaryDirectory() as tmp_dir:
        code_file = Path(tmp_dir) / "app.py"
        code_file.write_text("""
import click
from django.views import View

@click.command()
def cli_entry():
    pass

class MyView(View):
    def get(self, request):
        pass
""", encoding="utf-8")

        eps_extended = find_entry_points(tmp_dir)
        chk("find_entry_points detects click @command", any("cli_entry" in ep for ep in eps_extended), True)
        chk("find_entry_points detects Django CBV MyView.get", any("MyView.get" in ep for ep in eps_extended), True)


def test_auto_discovery_and_directory_scan():
    """Auto-discovery & Directory target scanning (including src/requirements.txt)."""
    print("=== Auto-discovery & Directory target scanning ===")
    with tempfile.TemporaryDirectory() as tmp_dir:
        src_dir = Path(tmp_dir) / "src"
        src_dir.mkdir()
        req_file = src_dir / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask==2.3.2\n", encoding="utf-8")

        found_path, fmt = find_dependency_file(tmp_dir)
        chk("Auto-discovers src/requirements.txt", found_path == req_file, True)
        chk("Format identified as requirements.txt", fmt, "requirements.txt")

        deps = parse_deps(tmp_dir)
        chk("parse_deps(dir) returns 2 packages", len(deps), 2)
        chk("requests==2.28.0 found in dir scan", ("requests", "2.28.0") in deps, True)


def test_recursive_requirements():
    """Recursive -r requirement inclusions."""
    print("=== Recursive -r requirement inclusions ===")
    with tempfile.TemporaryDirectory() as tmp_dir:
        main_req = Path(tmp_dir) / "requirements.txt"
        sub_req = Path(tmp_dir) / "sub.txt"

        sub_req.write_text("jinja2==3.1.2\n", encoding="utf-8")
        main_req.write_text("-r sub.txt\nflask==2.3.2\n", encoding="utf-8")

        deps = parse_requirements(str(main_req))
        chk("Recursive parse finds 2 packages", len(deps), 2)
        chk("jinja2 from sub.txt present", ("jinja2", "3.1.2") in deps, True)
        chk("flask from main_req present", ("flask", "2.3.2") in deps, True)


def test_uv_and_pdm_lockfiles():
    """uv.lock and pdm.lock parsing."""
    print("=== uv.lock and pdm.lock parsing ===")
    sample_toml = """
[[package]]
name = "httpx"
version = "0.24.1"

[[package]]
name = "pydantic"
version = "2.0.0"
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        uv_file = Path(tmp_dir) / "uv.lock"
        pdm_file = Path(tmp_dir) / "pdm.lock"
        uv_file.write_text(sample_toml, encoding="utf-8")
        pdm_file.write_text(sample_toml, encoding="utf-8")

        uv_deps = parse_uv_lock(str(uv_file))
        pdm_deps = parse_pdm_lock(str(pdm_file))

        chk("uv.lock parses 2 packages", len(uv_deps), 2)
        chk("httpx in uv.lock", ("httpx", "0.24.1") in uv_deps, True)
        chk("pdm.lock parses 2 packages", len(pdm_deps), 2)


def run_all_tests():
    print("IMPORTS: OK\n")
    test_b1_dependency_parsers()
    test_a3_noise_filter()
    test_a2_suffix_matching()
    test_a1_entry_points()
    test_end_to_end_reachability()
    test_severity_and_patch_extraction()
    test_html_report_generator()
    test_pre_commit_hooks()
    test_cli_output_html()
    test_cyclonedx_sbom_exporter()
    test_policy_suppression()
    test_extended_ast_detectors()
    test_auto_discovery_and_directory_scan()
    test_recursive_requirements()
    test_uv_and_pdm_lockfiles()

    print("=" * 55)
    if failures:
        print(f"FAILED {len(failures)} test(s):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED")


if __name__ == "__main__":
    run_all_tests()
