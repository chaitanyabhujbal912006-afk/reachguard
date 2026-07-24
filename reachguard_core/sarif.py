"""SARIF v2.1.0 exporter for GitHub Code Scanning and IDE integration."""

import json
from reachguard_core.reachability import ReachabilityStatus

# Type hint for Finding matching cli.py
# (name, version, cve_id, summary, status, severity, call_path, fixed_version)
Finding = tuple[str, str, str, str, ReachabilityStatus, str, list[str] | None, str | None]


def generate_sarif(findings: list[Finding], requirements_path: str = "requirements.txt") -> dict:
    """Generate a SARIF v2.1.0 compliant dict from scan findings."""
    rules = []
    results = []
    seen_rule_ids = set()

    for name, version, cve_id, summary, status, severity, call_path, fixed_version in findings:
        # Define rule if not seen yet
        if cve_id not in seen_rule_ids:
            seen_rule_ids.add(cve_id)
            rules.append({
                "id": cve_id,
                "name": f"VulnerabilityIn{name.capitalize()}",
                "shortDescription": {
                    "text": summary[:100]
                },
                "fullDescription": {
                    "text": f"{cve_id} in {name} version {version}. {summary}"
                },
                "helpUri": f"https://osv.dev/vulnerability/{cve_id}",
                "properties": {
                    "tags": ["security", "vulnerability", severity.lower()]
                }
            })

        # Map reachability status to SARIF level
        if status == ReachabilityStatus.REACHABLE:
            level = "error"
        elif status == ReachabilityStatus.UNKNOWN:
            level = "warning"
        else:
            level = "note"

        # Build location
        location_uri = requirements_path.replace("\\", "/")
        loc_obj = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": location_uri
                }
            }
        }

        # Build message
        msg_text = f"[{status.value}] Package {name}=={version} affected by {cve_id}: {summary}"
        if status == ReachabilityStatus.REACHABLE and call_path:
            chain_str = " -> ".join(
                node.rsplit(".", 1)[-1] if "." in node else node for node in call_path
            )
            msg_text += f"\nTrace: {chain_str}"
        if fixed_version:
            msg_text += f"\nFix: upgrade {name} to >={fixed_version}"

        results.append({
            "ruleId": cve_id,
            "level": level,
            "message": {
                "text": msg_text
            },
            "locations": [loc_obj]
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReachGuard",
                        "semanticVersion": "0.1.4",
                        "informationUri": "https://github.com/chaitanyabhujbal912006-afk/reachguard",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }
    return sarif_doc


def write_sarif_output(findings: list[Finding], path: str, requirements_path: str = "requirements.txt") -> None:
    """Write SARIF v2.1.0 report to *path*."""
    sarif_data = generate_sarif(findings, requirements_path=requirements_path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif_data, fh, indent=2)
