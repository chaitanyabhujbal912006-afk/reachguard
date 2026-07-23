"""OSV.dev API integration module."""

import requests

OSV_URL = "https://api.osv.dev/v1/query"

def query_cves(package_name: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """Queries OSV.dev REST API for vulnerabilities for a given package and version."""
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem}
    }
    try:
        response = requests.post(OSV_URL, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("vulns", [])
    except Exception as e:
        return []

