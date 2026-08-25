"""Tests for EPSS exploit probability scoring module."""

import responses as responses_lib

from reachguard_core.epss import EPSS_URL, calculate_risk_score, fetch_epss_scores
from reachguard_core.reachability import ReachabilityStatus


@responses_lib.activate
def test_fetch_epss_scores_success():
    responses_lib.add(
        responses_lib.GET,
        EPSS_URL,
        json={
            "status": "OK",
            "data": [
                {"cve": "CVE-2023-221", "epss": "0.12345", "percentile": "0.5"}
            ]
        },
        status=200,
    )
    scores = fetch_epss_scores(["CVE-2023-221"])
    assert "CVE-2023-221" in scores
    assert scores["CVE-2023-221"] == 0.12345


def test_fetch_epss_scores_empty_input():
    scores = fetch_epss_scores([])
    assert scores == {}


def test_calculate_risk_score_reachable():
    score = calculate_risk_score(ReachabilityStatus.REACHABLE, "CRITICAL", epss_score=0.8)
    assert score == 0.8  # 1.0 * 1.0 * 0.8


def test_calculate_risk_score_unreachable():
    score = calculate_risk_score(ReachabilityStatus.UNREACHABLE, "LOW", epss_score=0.1)
    assert score < 0.1  # low weight for unreachable
