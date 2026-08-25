"""Tests for the OSV module with mocked HTTP responses."""

import json

import pytest
import responses as responses_lib

from reachguard_core.osv import query_cves, query_cves_batch, extract_fixed_version
from reachguard_core.cache import OsvCache

OSV_URL = "https://api.osv.dev/v1/query"

FAKE_VULN = {
    "id": "PYSEC-2024-42",
    "summary": "Remote code execution in example",
    "affected": [{"ranges": [{"events": [{"introduced": "1.0"}, {"fixed": "2.1.0"}]}]}],
}


# ── query_cves ────────────────────────────────────────────────────────────────

@responses_lib.activate
def test_query_cves_returns_vulns():
    responses_lib.add(
        responses_lib.POST, OSV_URL,
        json={"vulns": [FAKE_VULN]},
        status=200,
    )
    result = query_cves("example-pkg", "1.5.0")
    assert len(result) == 1
    assert result[0]["id"] == "PYSEC-2024-42"


@responses_lib.activate
def test_query_cves_returns_empty_on_no_vulns():
    responses_lib.add(
        responses_lib.POST, OSV_URL,
        json={},
        status=200,
    )
    result = query_cves("safe-pkg", "9.0.0")
    assert result == []


@responses_lib.activate
def test_query_cves_returns_empty_on_server_error():
    """After all retries fail on 500, return empty list — do not crash."""
    responses_lib.add(responses_lib.POST, OSV_URL, status=500)
    responses_lib.add(responses_lib.POST, OSV_URL, status=500)
    responses_lib.add(responses_lib.POST, OSV_URL, status=500)
    result = query_cves("bad-server", "1.0.0", max_retries=3)
    assert result == []


@responses_lib.activate
def test_query_cves_uses_cache_on_hit(tmp_path):
    cache = OsvCache(cache_dir=tmp_path)
    cache.set("flask", "2.3.2", [FAKE_VULN])
    # No HTTP mock — if a real call is made, responses will raise ConnectionError
    result = query_cves("flask", "2.3.2", cache=cache)
    assert result == [FAKE_VULN]


@responses_lib.activate
def test_query_cves_populates_cache(tmp_path):
    responses_lib.add(
        responses_lib.POST, OSV_URL,
        json={"vulns": [FAKE_VULN]},
        status=200,
    )
    cache = OsvCache(cache_dir=tmp_path)
    query_cves("flask", "2.3.2", cache=cache)
    # Second call must hit cache (no second HTTP mock registered)
    result = query_cves("flask", "2.3.2", cache=cache)
    assert result == [FAKE_VULN]


# ── query_cves_batch ──────────────────────────────────────────────────────────

@responses_lib.activate
def test_batch_returns_results_for_all_deps():
    responses_lib.add(
        responses_lib.POST, OSV_URL,
        json={"vulns": [FAKE_VULN]},
        status=200,
    )
    responses_lib.add(
        responses_lib.POST, OSV_URL,
        json={},
        status=200,
    )
    deps = [("flask", "2.3.2"), ("requests", "2.31.0")]
    results = query_cves_batch(deps, max_workers=2)
    assert ("flask", "2.3.2") in results
    assert ("requests", "2.31.0") in results


@responses_lib.activate
def test_batch_empty_deps():
    results = query_cves_batch([], max_workers=2)
    assert results == {}


# ── extract_fixed_version ─────────────────────────────────────────────────────

def test_extract_fixed_version_found():
    version = extract_fixed_version(FAKE_VULN)
    assert version == "2.1.0"


def test_extract_fixed_version_not_present():
    vuln_no_fix = {"id": "X", "affected": [{"ranges": [{"events": [{"introduced": "1.0"}]}]}]}
    assert extract_fixed_version(vuln_no_fix) is None


def test_extract_fixed_version_empty_vuln():
    assert extract_fixed_version({}) is None
