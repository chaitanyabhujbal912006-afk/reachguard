"""CycloneDX v1.5 SBOM exporter with reachability annotations."""

import json
import uuid
from datetime import datetime, timezone
from reachguard_core import __version__
from reachguard_core.reachability import ReachabilityStatus

# Type hint matching cli.py
Finding = tuple[str, str, str, str, ReachabilityStatus, str, list[str] | None, str | None]


def generate_cyclonedx_sbom(
    findings: list[Finding],
    deps: list[tuple[str, str]],
    requirements_path: str = "requirements.txt",
) -> dict:
    """Generate a CycloneDX v1.5 compliant SBOM dictionary with reachability metadata."""
    bom_ref_map = {}
    components = []

    for name, version in deps:
        bom_ref = f"pkg:pypi/{name}@{version}"
        bom_ref_map[(name, version)] = bom_ref
        components.append({
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        })

    vulnerabilities = []
    for name, version, cve_id, summary, status, severity, call_path, fixed_version in findings:
        bom_ref = bom_ref_map.get((name, version), f"pkg:pypi/{name}@{version}")

        # Rating severity mapping
        severity_val = severity.lower() if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "unknown"

        vuln_obj = {
            "id": cve_id,
            "source": {
                "name": "OSV",
                "url": f"https://osv.dev/vulnerability/{cve_id}",
            },
            "description": summary,
            "ratings": [
                {
                    "severity": severity_val,
                    "method": "other",
                }
            ],
            "affects": [
                {
                    "ref": bom_ref,
                }
            ],
            "properties": [
                {
                    "name": "reachguard:reachability_status",
                    "value": status.value,
                }
            ],
        }

        if call_path:
            chain_str = " -> ".join(
                node.rsplit(".", 1)[-1] if "." in node else node for node in call_path
            )
            vuln_obj["properties"].append({
                "name": "reachguard:call_path",
                "value": chain_str,
            })

        if fixed_version:
            vuln_obj["recommendation"] = f"Upgrade {name} to {fixed_version} or higher"
            vuln_obj["properties"].append({
                "name": "reachguard:fixed_version",
                "value": fixed_version,
            })

        vulnerabilities.append(vuln_obj)

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "ReachGuard",
                    "name": "reachguard",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": requirements_path,
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    return sbom


def write_sbom_output(
    findings: list[Finding],
    deps: list[tuple[str, str]],
    path: str,
    requirements_path: str = "requirements.txt",
) -> None:
    """Write CycloneDX v1.5 JSON SBOM to *path*."""
    sbom_data = generate_cyclonedx_sbom(findings, deps, requirements_path=requirements_path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sbom_data, fh, indent=2)
