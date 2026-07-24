"""Full regression test suite for ReachGuard."""

import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(str(PROJECT_ROOT))

from reachguard_core.deps import parse_deps, _normalise_name
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
    return ok


def run_all_tests():
    print("IMPORTS: OK\n")

    # ── B1: Dependency parsers ───────────────────────────────────────────────────
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
    print()

    # ── A3: Noise filter ─────────────────────────────────────────────────────────
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
    print()

    # ── A3: Jinja2 advisories produce UNKNOWN ─────────────────────────────────────
    print("=== A3: Jinja2 str.format filtering ===")
    jinja_vuln = {
        "id": "GHSA-cpwx-vrp4-4pq7",
        "details": "The |attr filter allows attackers via str.format method to escape the sandbox.",
        "affected": [],
    }
    targets = extract_vulnerable_functions(jinja_vuln)
    chk("str.format filtered from jinja advisory", "str.format" not in targets, True)
    chk("xmlattr filtered from advisory", "xmlattr" not in targets, True)
    print(f"         remaining targets: {targets}")
    print()

    # ── A2: suffix-anchored matching ─────────────────────────────────────────────
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
    print()

    # ── A1: Seeding ──────────────────────────────────────────────────────────────
    print("=== A1: Entry-point seeding ===")
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
        print()

        # ── End-to-end reachability & Call Trace ──────────────────────────────────────
        print("=== End-to-end reachability & Call Trace ===")
        test_src = PROJECT_ROOT.parent / "test-target" / "src"
        if test_src.exists():
            eps = find_entry_points(str(test_src))
            r1 = is_reachable(cg, eps, "full_dispatch_request")
            chk("full_dispatch_request reachable from __main__", r1, True)

            path = find_reachability_path(cg, eps, "full_dispatch_request")
            chk("find_reachability_path returns non-empty list", isinstance(path, list) and len(path) > 0, True)
            if path:
                print(f"         Reconstructed path: {' -> '.join(path)}")

        r2 = is_reachable(cg, eps if test_src.exists() else [], "invented_func_xyz_999")
        chk("invented function NOT reachable", r2, False)

        p_inv = find_reachability_path(cg, eps if test_src.exists() else [], "invented_func_xyz_999")
        chk("invented function path returns None", p_inv, None)

        cg_fake = {f"src{SEP}mod.upload": [], f"src{SEP}mod.reload": []}
        r3 = is_reachable(cg_fake, ["app.py::__main__"], "load")
        chk("load does NOT false-match upload/reload", r3, False)
        print()

    # ── B5 & Auto-remediation: Severity & Patch extraction ────────────────────────
    print("=== B5 & Auto-remediation: Severity & Patch extraction ===")
    chk("sev from database_specific", m._get_severity({"database_specific": {"severity": "HIGH"}, "affected": []}), "HIGH")
    chk(
        "sev from affected.database_specific",
        m._get_severity({"database_specific": {}, "affected": [{"database_specific": {"severity": "CRITICAL"}}]}),
        "CRITICAL",
    )
    chk("sev empty returns dash", m._get_severity({"affected": [], "database_specific": {}}), "-")

    # Fixed version extraction tests
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

    # SARIF generation tests
    from reachguard_core.sarif import generate_sarif
    from reachguard_core.reachability import ReachabilityStatus

    sample_findings = [
        ("flask", "2.3.0", "CVE-2023-9999", "Sample summary", ReachabilityStatus.REACHABLE, "HIGH", ["app.py::main", "flask.run"], "2.3.2")
    ]
    sarif_doc = generate_sarif(sample_findings, requirements_path="requirements.txt")
    chk("SARIF version is 2.1.0", sarif_doc.get("version"), "2.1.0")
    chk("SARIF has 1 run", len(sarif_doc.get("runs", [])), 1)
    chk("SARIF result level is error for REACHABLE", sarif_doc["runs"][0]["results"][0]["level"], "error")
    chk("SARIF ruleId matches CVE", sarif_doc["runs"][0]["results"][0]["ruleId"], "CVE-2023-9999")

    # Batch OSV query tests
    from reachguard_core.osv import query_cves_batch
    batch_res = query_cves_batch([("flask", "2.3.2"), ("jinja2", "3.1.2")], max_workers=2)
    chk("query_cves_batch returns dict for all deps", len(batch_res), 2)
    chk("query_cves_batch returns list for flask", isinstance(batch_res.get(("flask", "2.3.2")), list), True)
    print()

    # ── Summary ───────────────────────────────────────────────────────────────────
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
