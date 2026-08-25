"""Disk-based OSV response cache for ReachGuard.

Caches OSV advisory results keyed by (package, version) with a configurable
TTL (default 24 hours), dramatically speeding up repeated scans.

Cache location (in priority order):
1. ``--cache-dir <path>`` CLI option
2. ``REACHGUARD_CACHE_DIR`` environment variable
3. ``~/.cache/reachguard/`` (user-global, default)

Usage:
    cache = OsvCache()
    result = cache.get("flask", "2.3.2")   # None if missing or stale
    cache.set("flask", "2.3.2", [...])
"""

import hashlib
import json
import os
import time
from pathlib import Path

from reachguard_core.logger import get_logger

log = get_logger(__name__)

# Default TTL: 24 hours
_DEFAULT_TTL_SECONDS = 24 * 60 * 60
# Auto-prune entries older than 7 days on startup
_PRUNE_AGE_SECONDS = 7 * 24 * 60 * 60


def _default_cache_dir() -> Path:
    """Return the default cache directory."""
    env = os.environ.get("REACHGUARD_CACHE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "reachguard"


class OsvCache:
    """Simple file-based cache mapping (package, version) → OSV advisory list."""

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        ttl: int = _DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._ttl = ttl
        self._dir = Path(cache_dir) if cache_dir else _default_cache_dir()
        self._hits = 0
        self._misses = 0

        if self._enabled:
            try:
                self._dir.mkdir(parents=True, exist_ok=True)
                self._prune_stale()
            except OSError as exc:
                log.warning("Cache directory unavailable (%s) — disabling cache.", exc)
                self._enabled = False

    # ── Public API ───────────────────────────────────────────────────────────

    def get(self, package: str, version: str) -> list[dict] | None:
        """Return cached advisories or ``None`` if missing / stale."""
        if not self._enabled:
            return None
        path = self._entry_path(package, version)
        if not path.exists():
            self._misses += 1
            log.debug("Cache MISS %s==%s", package, version)
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            age = time.time() - data["ts"]
            if age > self._ttl:
                path.unlink(missing_ok=True)
                self._misses += 1
                log.debug("Cache EXPIRED %s==%s (age=%.0fs)", package, version, age)
                return None
            self._hits += 1
            log.debug("Cache HIT %s==%s", package, version)
            return data["vulns"]
        except (KeyError, json.JSONDecodeError, OSError) as exc:
            log.debug("Cache read error for %s==%s: %s", package, version, exc)
            self._misses += 1
            return None

    def set(self, package: str, version: str, vulns: list[dict]) -> None:
        """Write advisories to the cache."""
        if not self._enabled:
            return
        path = self._entry_path(package, version)
        try:
            path.write_text(
                json.dumps({"ts": time.time(), "vulns": vulns}, indent=None),
                encoding="utf-8",
            )
            log.debug("Cache SET %s==%s (%d vulns)", package, version, len(vulns))
        except OSError as exc:
            log.debug("Cache write error for %s==%s: %s", package, version, exc)

    def stats(self) -> dict:
        """Return hit/miss statistics."""
        total = self._hits + self._misses
        rate = self._hits / total if total else 0.0
        return {"hits": self._hits, "misses": self._misses, "hit_rate": rate}

    def clear(self) -> int:
        """Delete all cache entries. Returns number of files removed."""
        if not self._enabled:
            return 0
        removed = 0
        try:
            for p in self._dir.glob("*.json"):
                p.unlink(missing_ok=True)
                removed += 1
        except OSError:
            pass
        log.debug("Cache cleared: %d entries removed", removed)
        return removed

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _entry_path(self, package: str, version: str) -> Path:
        key = f"{package.lower()}=={version}"
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self._dir / f"{digest}.json"

    def _prune_stale(self) -> None:
        """Remove entries older than _PRUNE_AGE_SECONDS."""
        now = time.time()
        pruned = 0
        try:
            for p in self._dir.glob("*.json"):
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    if now - data.get("ts", 0) > _PRUNE_AGE_SECONDS:
                        p.unlink(missing_ok=True)
                        pruned += 1
                except (json.JSONDecodeError, OSError):
                    p.unlink(missing_ok=True)
                    pruned += 1
        except OSError:
            pass
        if pruned:
            log.debug("Cache pruned %d stale entries on startup.", pruned)
