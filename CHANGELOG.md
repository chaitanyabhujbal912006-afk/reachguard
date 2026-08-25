# Changelog

All notable changes to ReachGuard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-08-26

### 🚀 Production Release

#### Added
- **Import-based pre-filter** (`import_scanner.py`): AST-walks all source files to build a map of
  which packages are imported. Unimported packages are immediately marked `UNREACHABLE` without
  needing a call graph — eliminates ~40% of false `UNKNOWN` results.
- **Disk-based OSV cache** (`cache.py`): Caches OSV advisory responses in `~/.cache/reachguard/`
  with a 24-hour TTL. Dramatically speeds up repeated scans (especially in CI). Supports
  `--no-cache` and `--cache-dir` flags. Auto-prunes entries older than 7 days on startup.
- **Structured logging** (`logger.py`): `--verbose` (DEBUG), `--quiet` (ERROR), `--log-file`, and
  `--log-format json` (for SIEM/Splunk ingestion).
- **`--min-severity`** flag: Filter findings to `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **`--only-reachable`** flag: Show only `REACHABLE` findings (suppresses `UNKNOWN`/`UNREACHABLE`).
- **`--timeout`** flag: Configure OSV HTTP request timeout per dependency (default: 10s).
- **`--max-workers`** flag: Control number of concurrent OSV HTTP threads (default: 10).
- **`--exit-code`** flag: Choose exit code strategy — `none` (always 0), `any` (1 on any CVE),
  `reachable` (1 on REACHABLE only, default).
- **`--log-file`** / **`--log-format`** flags for file and JSON log output.
- **`__main__.py` auto-seeding**: Files named `__main__.py` are automatically included as entry
  points without needing a decorator.
- **`asyncio.run()` / `uvicorn.run()` detection**: Functions calling these are now seeded as
  entry points.
- **FastAPI lifespan** (`startup`, `shutdown` decorators) detected as entry points.
- **CI mode**: Auto-detects `CI=true` environment variable; logs at DEBUG.
- **Progress count** in spinner: `[3/47]` shown during OSV query progress.
- **Duplicate package warning**: Warns when the same package appears twice with different versions.
- **Retry with exponential backoff**: OSV queries retry up to 3 times on HTTP 429/5xx errors.
- **CI/CD pipeline** (`.github/workflows/ci.yml`): Matrix tests on Python 3.10–3.12, coverage
  upload to Codecov, ruff linting, auto-publish to PyPI on tagged release via OIDC.
- **`[project.optional-dependencies].dev`** in `pyproject.toml`: `pytest`, `pytest-cov`,
  `responses` for HTTP mocking — install via `pip install -e ".[dev]"`.
- **`CHANGELOG.md`**: This file.

#### Changed
- **`__version__`** is now read dynamically from `importlib.metadata` instead of hardcoded in each
  module. `sarif.py` and `sbom.py` updated accordingly.
- **`scan()`** now accepts `min_severity`, `only_reachable`, `timeout`, `cache`, `max_workers`,
  and `verbose` parameters.
- **`check_reachability_details()`** accepts optional `import_scanner` and `package_name` args for
  import-based pre-filtering.
- **Findings are now sorted** by `(reachability_rank, severity)` — CRITICAL REACHABLE comes first.
- **`pyproject.toml`**: Bumped version to `1.0.0`, status to `Production/Stable`, added dev extras,
  pytest/coverage config.
- **`ROADMAP.md`**: Marked Phase 4 items (EPSS, git-diff PR scanning) as pending.

#### Fixed
- `OSError` on `-r include` missing file now warns instead of crashing.
- `SyntaxError` / `UnicodeDecodeError` in entrypoints scanner now logs at DEBUG instead of silently
  eating the error.
- `_build_call_graph` now logs PyCG errors at `WARNING` level for traceability.
- JSON output now includes `reachguard_version` field.

---

## [0.3.0] — 2026-08-25

### Added
- Zero-config auto-discovery: `find_dependency_file()` searches cwd and subdirs automatically.
- PyCG venv detection: `_find_pycg_cmd()` searches `venv/`, `.venv/`, PATH.
- `uv.lock` / `pdm.lock` lockfile support.
- Recursive `-r includes` support in `requirements.txt`.
- Expanded framework detection: Tornado, Aiohttp, Litestar, Bottle.
- Test suite refactored to `pytest` structure (15 tests, all passing).
- `action.yml` default changed from `requirements.txt` to `.` (directory auto-discovery).

---

## [0.2.0] — 2026-08-24

### Added
- CycloneDX v1.5 SBOM export (`--output-sbom`).
- Policy suppression engine (`.reachguardignore` / `reachguard.toml`).
- Extended AST detectors: Django CBVs, Celery, Click, Typer.

---

## [0.1.0] — 2026-08-23

### Added
- Initial release.
- OSV.dev vulnerability scanning with async parallel queries.
- PyCG-based call graph + BFS reachability analysis.
- Flask / FastAPI / Starlette entry-point detection.
- SARIF v2.1.0 export, HTML dashboard, JSON output.
- `--suggest-fixes` patch recommendations.
- Pre-commit hook integration.
