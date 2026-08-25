"""OSV.dev API integration module with caching and retry logic."""

import sys
import time

import requests

from reachguard_core.logger import get_logger

log = get_logger(__name__)

OSV_URL = "https://api.osv.dev/v1/query"

# ── Internal helpers ──────────────────────────────────────────────────────────

def _warn(msg: str) -> None:
    """Print a warning to stderr (Rich not required)."""
    print(f"[OSV warning] {msg}", file=sys.stderr)


def _query_with_retry(
    package_name: str,
    version: str,
    ecosystem: str = "PyPI",
    timeout: int = 10,
    max_retries: int = 3,
) -> list[dict]:
    """Make OSV HTTP request with exponential-backoff retry on transient errors."""
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    delay = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            log.debug("OSV query attempt %d/%d: %s==%s", attempt, max_retries, package_name, version)
            response = requests.post(OSV_URL, json=payload, timeout=timeout)

            if response.status_code == 429 or response.status_code >= 500:
                # Rate-limited or server error — back off and retry
                log.warning(
                    "OSV HTTP %d for %s==%s (attempt %d/%d) — retrying in %.0fs",
                    response.status_code, package_name, version, attempt, max_retries, delay,
                )
                if attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                # Final attempt failed
                _warn(f"{package_name}=={version}: OSV HTTP error {response.status_code} after {max_retries} attempts")
                return []

            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulns", [])
            log.debug("OSV returned %d vulns for %s==%s", len(vulns), package_name, version)
            return vulns

        except requests.exceptions.Timeout:
            log.warning("OSV timeout for %s==%s (attempt %d/%d)", package_name, version, attempt, max_retries)
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2
                continue
            _warn(f"{package_name}=={version}: OSV request timed out after {timeout}s")
            return []
        except requests.exceptions.ConnectionError as exc:
            log.warning("OSV connection error for %s==%s: %s", package_name, version, str(exc)[:80])
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2
                continue
            _warn(f"{package_name}=={version}: OSV connection error — {str(exc)[:80]}")
            return []
        except requests.exceptions.HTTPError as exc:
            _warn(f"{package_name}=={version}: OSV HTTP error {exc.response.status_code}")
            return []
        except Exception as exc:
            _warn(f"{package_name}=={version}: unexpected OSV error — {str(exc)[:80]}")
            return []

    return []


# ── Public API ────────────────────────────────────────────────────────────────

def query_cves(
    package_name: str,
    version: str,
    ecosystem: str = "PyPI",
    timeout: int = 10,
    cache=None,
    max_retries: int = 3,
) -> list[dict]:
    """Query OSV.dev for vulnerabilities affecting *package_name*==*version*.

    Args:
        package_name: Normalised PyPI package name.
        version:      Exact version string.
        ecosystem:    Package ecosystem (default ``"PyPI"``).
        timeout:      HTTP request timeout in seconds.
        cache:        Optional :class:`~reachguard_core.cache.OsvCache` instance.
        max_retries:  Number of retry attempts on transient errors (default: 3).

    Returns:
        List of OSV advisory dicts.
    """
    # Check cache first
    if cache is not None:
        cached = cache.get(package_name, version)
        if cached is not None:
            return cached

    vulns = _query_with_retry(package_name, version, ecosystem=ecosystem, timeout=timeout, max_retries=max_retries)

    # Populate cache
    if cache is not None:
        cache.set(package_name, version, vulns)

    return vulns



def query_cves_batch(
    deps: list[tuple[str, str]],
    max_workers: int = 10,
    callback=None,
    timeout: int = 10,
    cache=None,
) -> dict[tuple[str, str], list[dict]]:
    """Query OSV.dev for multiple dependencies concurrently via ThreadPoolExecutor.

    Args:
        deps:        List of ``(package_name, version)`` tuples.
        max_workers: Number of concurrent HTTP worker threads (default: 10).
        callback:    Optional zero-argument callable invoked after each dep completes.
        timeout:     HTTP request timeout per query in seconds.
        cache:       Optional :class:`~reachguard_core.cache.OsvCache` instance.

    Returns:
        Dict mapping ``(package_name, version)`` → list of OSV advisory dicts.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[tuple[str, str], list[dict]] = {}
    if not deps:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_dep = {
            executor.submit(query_cves, name, ver, timeout=timeout, cache=cache): (name, ver)
            for name, ver in deps
        }
        for future in as_completed(future_to_dep):
            dep = future_to_dep[future]
            try:
                results[dep] = future.result()
            except Exception as exc:
                log.error("Unexpected error querying OSV for %s==%s: %s", dep[0], dep[1], exc)
                results[dep] = []
            if callback:
                callback()
    return results


def extract_fixed_version(vuln: dict) -> str | None:
    """Extract the minimum fixed version for *vuln* from OSV advisory events, or None."""
    return next(
        (
            event["fixed"]
            for affected in vuln.get("affected", [])
            for r in affected.get("ranges", [])
            for event in r.get("events", [])
            if "fixed" in event
        ),
        None,
    )

