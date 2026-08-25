"""Tests for the OSV cache module."""

import time

import pytest

from reachguard_core.cache import OsvCache

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def cache(tmp_path):
    """Return a fresh OsvCache backed by a temp directory."""
    return OsvCache(cache_dir=tmp_path, ttl=60)


FAKE_VULNS = [{"id": "PYSEC-2024-1", "summary": "Test vuln"}]


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_cache_miss_on_empty(cache):
    result = cache.get("flask", "2.3.2")
    assert result is None


def test_cache_set_and_get(cache):
    cache.set("flask", "2.3.2", FAKE_VULNS)
    result = cache.get("flask", "2.3.2")
    assert result == FAKE_VULNS


def test_cache_different_keys_do_not_collide(cache):
    cache.set("flask", "2.3.2", FAKE_VULNS)
    cache.set("django", "4.2.0", [])
    assert cache.get("flask", "2.3.2") == FAKE_VULNS
    assert cache.get("django", "4.2.0") == []


def test_cache_miss_after_ttl_expiry(tmp_path):
    """A cache entry older than TTL should return None."""
    short_cache = OsvCache(cache_dir=tmp_path, ttl=1)  # 1-second TTL
    short_cache.set("requests", "2.31.0", FAKE_VULNS)
    time.sleep(1.1)  # let it expire
    assert short_cache.get("requests", "2.31.0") is None


def test_cache_stats_hit_rate(cache):
    cache.set("flask", "2.3.2", FAKE_VULNS)
    cache.get("flask", "2.3.2")  # hit
    cache.get("not-there", "1.0")  # miss
    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 0.5


def test_cache_clear(cache):
    cache.set("flask", "2.3.2", FAKE_VULNS)
    removed = cache.clear()
    assert removed == 1
    assert cache.get("flask", "2.3.2") is None


def test_cache_disabled_does_not_read_write(tmp_path):
    disabled = OsvCache(cache_dir=tmp_path, enabled=False)
    disabled.set("flask", "2.3.2", FAKE_VULNS)
    assert disabled.get("flask", "2.3.2") is None


def test_cache_handles_corrupt_entry(cache, tmp_path):
    """A corrupt JSON file in the cache dir should be treated as a miss."""
    # Write a corrupt file at the expected path
    cache.set("flask", "2.3.2", FAKE_VULNS)
    # Overwrite with garbage
    for p in tmp_path.glob("*.json"):
        p.write_text("NOT VALID JSON", encoding="utf-8")
    result = cache.get("flask", "2.3.2")
    assert result is None
