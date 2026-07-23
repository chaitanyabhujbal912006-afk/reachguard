"""Dependency file parsers.

Supports three formats automatically detected by filename:
- ``requirements.txt`` (and any *requirements*.txt variant)
- ``pyproject.toml``   (PEP 621 ``[project.dependencies]`` +
                        Poetry ``[tool.poetry.dependencies]``)
- ``Pipfile.lock``     (exact-pinned ``default`` + ``develop`` sections)

All parsers return ``list[tuple[str, str]]`` of ``(normalised_name, version)``.
Versions without an exact pin are silently skipped — reachability analysis
only makes sense against a known, fixed version.
"""

import re
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# requirements.txt  (and pip-compile output)
# ---------------------------------------------------------------------------

import importlib.metadata

def _resolve_installed_version(pkg_name: str) -> str | None:
    """Return the installed version of *pkg_name* via importlib.metadata, or None."""
    try:
        return importlib.metadata.version(pkg_name)
    except Exception:
        # Try normalised name variants
        try:
            return importlib.metadata.version(pkg_name.replace("-", "_"))
        except Exception:
            return None


def parse_requirements(filepath: str) -> list[tuple[str, str]]:
    """Parse a pip requirements file, returning (name, version) pairs.

    Handles:
    - Exact pins: ``flask==2.3.0``
    - Range pins: ``flask>=2.0.0`` (resolves installed version via importlib)
    - Unpinned: ``flask`` (resolves installed version via importlib)
    - Extras: ``celery[redis]==5.2.7`` (extras stripped)
    - Comments (``#``) and blank lines are ignored.
    """
    deps: list[tuple[str, str]] = []
    with open(filepath, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Exact pin regex: pkg==1.2.3
            match_exact = re.match(
                r"^([A-Za-z0-9_\-\.]+(?:\[[A-Za-z0-9_,\-\.]+\])?)==([0-9A-Za-z\.\-]+)",
                line,
            )
            if match_exact:
                raw_pkg, version = match_exact.group(1), match_exact.group(2)
                pkg = re.sub(r"\[.*?\]", "", raw_pkg)  # strip extras
                deps.append((_normalise_name(pkg), version))
                continue

            # Unpinned or range specification: pkg, pkg>=1.0, pkg~=1.0
            match_unpinned = re.match(
                r"^([A-Za-z0-9_\-\.]+(?:\[[A-Za-z0-9_,\-\.]+\])?)",
                line,
            )
            if match_unpinned:
                raw_pkg = match_unpinned.group(1)
                pkg = re.sub(r"\[.*?\]", "", raw_pkg)
                norm_name = _normalise_name(pkg)
                installed_ver = _resolve_installed_version(norm_name)
                if installed_ver:
                    deps.append((norm_name, installed_ver))
    return deps


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------

def parse_pyproject(filepath: str) -> list[tuple[str, str]]:
    """Parse pinned dependencies from a ``pyproject.toml`` file.

    Reads PEP 621 ``[project.dependencies]`` and Poetry
    ``[tool.poetry.dependencies]`` sections.  Only exact pins
    (``==x.y.z`` or ``"x.y.z"``) are returned.
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []   # No TOML parser available — skip silently.

    with open(filepath, "rb") as fh:
        data = tomllib.load(fh)

    deps: list[tuple[str, str]] = []

    # ── PEP 621: [project.dependencies] ─────────────────────────────────────
    for spec in data.get("project", {}).get("dependencies", []):
        result = _parse_pep508_pin(spec)
        if result:
            deps.append(result)

    # ── Poetry: [tool.poetry.dependencies] ──────────────────────────────────
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for pkg, constraint in poetry_deps.items():
        if pkg.lower() == "python":
            continue
        if isinstance(constraint, str):
            ver = re.match(r"[=^~]?=?([0-9][0-9A-Za-z\.\-]*)", constraint)
            if ver:
                deps.append((_normalise_name(pkg), ver.group(1)))
        elif isinstance(constraint, dict):
            ver_str = constraint.get("version", "")
            ver = re.match(r"[=^~]?=?([0-9][0-9A-Za-z\.\-]*)", ver_str)
            if ver:
                deps.append((_normalise_name(pkg), ver.group(1)))

    return deps


# ---------------------------------------------------------------------------
# Pipfile.lock
# ---------------------------------------------------------------------------

def parse_pipfile_lock(filepath: str) -> list[tuple[str, str]]:
    """Parse exact-pinned packages from a ``Pipfile.lock`` file."""
    with open(filepath, encoding="utf-8") as fh:
        data = json.load(fh)

    deps: list[tuple[str, str]] = []
    for section in ("default", "develop"):
        for pkg, meta in data.get(section, {}).items():
            version_str = meta.get("version", "")
            # Pipfile.lock version strings look like "==2.3.0"
            match = re.match(r"==(.*)", version_str)
            if match:
                deps.append((_normalise_name(pkg), match.group(1)))
    return deps


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def parse_deps(filepath: str) -> list[tuple[str, str]]:
    """Auto-detect dependency file format and parse it.

    Dispatches to the correct parser based on the file name:

    - ``*requirements*.txt`` → :func:`parse_requirements`
    - ``pyproject.toml``     → :func:`parse_pyproject`
    - ``Pipfile.lock``       → :func:`parse_pipfile_lock`
    - anything else          → tries :func:`parse_requirements` as fallback
    """
    name = Path(filepath).name.lower()
    if name == "pyproject.toml":
        return parse_pyproject(filepath)
    if name.endswith(".lock"):           # Pipfile.lock, poetry.lock, etc.
        return parse_pipfile_lock(filepath)
    # Default: requirements.txt (and pip-compile variants)
    return parse_requirements(filepath)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_name(name: str) -> str:
    """Normalise a package name per PEP 503 (lowercase, hyphens)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_pep508_pin(spec: str) -> tuple[str, str] | None:
    """Extract (name, version) from a PEP 508 dependency string if exactly pinned.

    Returns ``None`` for range specifiers, URL requirements, etc.
    """
    # Strip extras and environment markers:  "flask[async]==2.3.0; python>=3.8"
    spec = spec.split(";")[0].strip()
    match = re.match(
        r"^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?==([0-9A-Za-z\.\-]+)",
        spec,
    )
    if match:
        return (_normalise_name(match.group(1)), match.group(2))
    return None
