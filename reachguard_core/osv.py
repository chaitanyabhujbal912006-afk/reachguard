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


def query_cves_batch(
    deps: list[tuple[str, str]],
    max_workers: int = 10,
    callback=None
) -> dict[tuple[str, str], list[dict]]:
    """Query OSV.dev for multiple dependencies concurrently via ThreadPoolExecutor.

    Args:
        deps: List of (package_name, version) tuples.
        max_workers: Number of concurrent HTTP worker threads (default: 10).
        callback: Optional zero-argument function called after each completion.

    Returns:
        Dict mapping (package_name, version) -> list of OSV advisory dicts.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[tuple[str, str], list[dict]] = {}
    if not deps:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_dep = {
            executor.submit(query_cves, name, ver): (name, ver)
            for name, ver in deps
        }
        for future in as_completed(future_to_dep):
            dep = future_to_dep[future]
            try:
                results[dep] = future.result()
            except Exception:
                results[dep] = []
            if callback:
                callback()
    return results


def extract_fixed_version(vuln: dict) -> str | None:
    """Extract the minimum fixed version for *vuln* from OSV advisory events, or None."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None

