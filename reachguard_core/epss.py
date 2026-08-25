"""EPSS (Exploit Prediction Scoring System) integration for ReachGuard.

Queries first.org API (https://api.first.org/data/v1/epss) for CVE exploit probability
scores and computes composite risk ratings:
    Risk Score = Reachability Weight × Severity Weight × EPSS Score

Reachability Weights:
- REACHABLE:   1.0
- UNKNOWN:     0.5
- UNREACHABLE: 0.1

Usage:
    epss_map = fetch_epss_scores(["CVE-2023-221", "GHSA-xxxx"])
    score = epss_map.get("CVE-2023-221", 0.0)
"""

import requests

from reachguard_core.logger import get_logger
from reachguard_core.reachability import ReachabilityStatus

log = get_logger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"

_REACHABILITY_WEIGHTS = {
    ReachabilityStatus.REACHABLE:   1.0,
    ReachabilityStatus.UNKNOWN:     0.5,
    ReachabilityStatus.UNREACHABLE: 0.1,
}

_SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH":     0.8,
    "MEDIUM":   0.5,
    "LOW":      0.2,
    "-":        0.1,
}


def fetch_epss_scores(cve_ids: list[str], timeout: int = 5) -> dict[str, float]:
    """Fetch EPSS probability scores (0.0 to 1.0) for a list of CVE IDs.

    Args:
        cve_ids: List of CVE identifiers (e.g. ['CVE-2023-221']).
        timeout: HTTP timeout in seconds.

    Returns:
        Dict mapping cve_id → float epss_score.
    """
    valid_cves = [c for c in cve_ids if c.startswith("CVE-")]
    if not valid_cves:
        return {}

    cve_param = ",".join(valid_cves[:100])  # EPSS API max 100 per request
    try:
        log.debug("Fetching EPSS scores for %d CVEs...", len(valid_cves))
        resp = requests.get(EPSS_URL, params={"cve": cve_param}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        scores = {}
        for item in data:
            cve = item.get("cve")
            score_str = item.get("epss")
            if cve and score_str:
                scores[cve] = float(score_str)
        log.debug("Fetched %d EPSS scores from first.org", len(scores))
        return scores
    except Exception as exc:
        log.warning("Failed to fetch EPSS scores: %s", exc)
        return {}


def calculate_risk_score(
    status: ReachabilityStatus,
    severity: str,
    epss_score: float = 0.0,
) -> float:
    """Calculate composite risk score: Reachability Weight × Severity Weight × max(EPSS, 0.1)."""
    r_w = _REACHABILITY_WEIGHTS.get(status, 0.5)
    s_w = _SEVERITY_WEIGHTS.get(severity.upper(), 0.5)
    # Default floor of 0.1 when EPSS is unknown/not reported
    e_w = max(epss_score, 0.1)
    return round(r_w * s_w * e_w, 3)
