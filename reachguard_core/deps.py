"""Dependency file parsers and auto-discovery.

Supports multiple dependency formats automatically detected by filename:
- ``requirements.txt`` (and any *requirements*.txt variant, including nested -r includes)
- ``pyproject.toml``   (PEP 621 ``[project.dependencies]`` + Poetry & PDM dependencies)
- ``Pipfile.lock``     (exact-pinned ``default`` + ``develop`` sections)
- ``poetry.lock``      (TOML-based Poetry lockfile)
- ``uv.lock``          (TOML-based uv lockfile)
- ``pdm.lock``         (TOML-based PDM lockfile)

Also supports zero-config directory scanning: given a folder (or no argument),
ReachGuard automatically discovers dependency files in root or subdirectories
(e.g., ``src/requirements.txt``), falling back to installed packages if needed.
"""

import json
import re
import importlib.metadata
from pathlib import Path


# ---------------------------------------------------------------------------
# Installed package resolver
# ---------------------------------------------------------------------------

def _resolve_installed_version(pkg_name: str) -> str | None:
    """Return the installed version of *pkg_name* via importlib.metadata, or None."""
    try:
        return importlib.metadata.version(pkg_name)
    except Exception:
        try:
            return importlib.metadata.version(pkg_name.replace("-", "_"))
        except Exception:
            return None


def parse_installed_environment() -> list[tuple[str, str]]:
    """Scan all installed packages in the active Python environment.

    Used as a zero-config fallback when no dependency file is present in a repo.
    """
    deps: list[tuple[str, str]] = []
    try:
        for dist in importlib.metadata.distributions():
            name = dist.metadata.get("Name")
            ver = dist.version
            if name and ver:
                deps.append((_normalise_name(name), ver))
    except Exception:
        pass
    return deps


# ---------------------------------------------------------------------------
# requirements.txt (and recursive -r includes)
# ---------------------------------------------------------------------------

def parse_requirements(filepath: str, _visited: set[str] | None = None) -> list[tuple[str, str]]:
    """Parse a pip requirements file, returning (name, version) pairs.

    Handles:
    - Exact pins: ``flask==2.3.0``
    - Range pins: ``flask>=2.0.0`` (resolves installed version or min version)
    - Unpinned: ``flask`` (resolves installed version via importlib)
    - Extras: ``celery[redis]==5.2.7`` (extras stripped)
    - Recursive includes: ``-r subrequirements.txt``
    - Comments (``#``) and blank lines are ignored.
    """
    if _visited is None:
        _visited = set()

    path_obj = Path(filepath).resolve()
    path_str = str(path_obj)
    if path_str in _visited:
        return []
    _visited.add(path_str)

    if not path_obj.exists() or not path_obj.is_file():
        return []

    deps: list[tuple[str, str]] = []
    base_dir = path_obj.parent

    with open(path_obj, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle recursive -r / --requirement includes
            if line.startswith("-r ") or line.startswith("--requirement "):
                inc_target = line.split(maxsplit=1)[1].strip()
                inc_path = base_dir / inc_target
                if inc_path.exists():
                    deps.extend(parse_requirements(str(inc_path), _visited))
                continue

            if line.startswith("-"):
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

            # Range pins or unpinned specifier: pkg>=1.0, pkg~=1.0, pkg
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
                else:
                    # Attempt to extract minimum range bound e.g. pkg>=2.3.0
                    bound_match = re.search(r"[>=~^]=?\s*([0-9][0-9A-Za-z\.\-]*)", line)
                    if bound_match:
                        deps.append((norm_name, bound_match.group(1)))

    return deps


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------

def parse_pyproject(filepath: str) -> list[tuple[str, str]]:
    """Parse dependencies from a ``pyproject.toml`` file.

    Reads PEP 621 ``[project.dependencies]`` and Poetry
    ``[tool.poetry.dependencies]`` sections.
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []   # No TOML parser available — skip silently.

    try:
        with open(filepath, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return []

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
        norm_name = _normalise_name(pkg)
        ver_str = constraint if isinstance(constraint, str) else (constraint.get("version", "") if isinstance(constraint, dict) else "")
        ver_match = re.search(r"([0-9][0-9A-Za-z\.\-]*)", ver_str)
        if ver_match:
            installed = _resolve_installed_version(norm_name)
            deps.append((norm_name, installed or ver_match.group(1)))

    return deps


# ---------------------------------------------------------------------------
# Lockfile parsers (Pipfile.lock, poetry.lock, uv.lock, pdm.lock)
# ---------------------------------------------------------------------------

def parse_pipfile_lock(filepath: str) -> list[tuple[str, str]]:
    """Parse exact-pinned packages from a ``Pipfile.lock`` file."""
    try:
        with open(filepath, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return []

    deps: list[tuple[str, str]] = []
    for section in ("default", "develop"):
        for pkg, meta in data.get(section, {}).items():
            version_str = meta.get("version", "")
            match = re.match(r"==(.*)", version_str)
            if match:
                deps.append((_normalise_name(pkg), match.group(1)))
    return deps


def parse_poetry_lock(filepath: str) -> list[tuple[str, str]]:
    """Parse exact-pinned packages from a ``poetry.lock`` TOML file."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return []

    try:
        with open(filepath, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return []

    deps: list[tuple[str, str]] = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name and version:
            deps.append((_normalise_name(name), version))
    return deps


def parse_uv_lock(filepath: str) -> list[tuple[str, str]]:
    """Parse exact-pinned packages from a ``uv.lock`` TOML file."""
    return parse_poetry_lock(filepath)  # Shares identical [[package]] structure


def parse_pdm_lock(filepath: str) -> list[tuple[str, str]]:
    """Parse exact-pinned packages from a ``pdm.lock`` TOML file."""
    return parse_poetry_lock(filepath)  # Shares identical [[package]] structure


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------

def find_dependency_file(target: str | Path | None = None) -> tuple[Path | None, str]:
    """Auto-discover a dependency file starting from *target*.

    Args:
        target: Optional path to a file or directory.

    Returns:
        Tuple of ``(path_or_None, file_format)``.
    """
    if target is None:
        target_dir = Path.cwd()
    else:
        target_path = Path(target)
        if target_path.is_file():
            name = target_path.name.lower()
            if name == "pyproject.toml":
                return target_path, "pyproject.toml"
            if name == "pipfile.lock":
                return target_path, "pipfile.lock"
            if name == "poetry.lock":
                return target_path, "poetry.lock"
            if name == "uv.lock":
                return target_path, "uv.lock"
            if name == "pdm.lock":
                return target_path, "pdm.lock"
            return target_path, "requirements.txt"
        elif target_path.is_dir():
            target_dir = target_path
        else:
            return None, "none"

    # Search order for directory targets
    candidates = [
        # 1. Root requirements files
        ("requirements.txt", "requirements.txt"),
        ("requirements-dev.txt", "requirements.txt"),
        # 2. Subdirectory requirements files (e.g. src/requirements.txt, app/requirements.txt)
        ("src/requirements.txt", "requirements.txt"),
        ("app/requirements.txt", "requirements.txt"),
        ("config/requirements.txt", "requirements.txt"),
        ("requirements/prod.txt", "requirements.txt"),
        ("requirements/base.txt", "requirements.txt"),
        ("requirements/main.txt", "requirements.txt"),
        # 3. Project / lock files
        ("pyproject.toml", "pyproject.toml"),
        ("Pipfile.lock", "pipfile.lock"),
        ("poetry.lock", "poetry.lock"),
        ("uv.lock", "uv.lock"),
        ("pdm.lock", "pdm.lock"),
        ("src/pyproject.toml", "pyproject.toml"),
        ("app/pyproject.toml", "pyproject.toml"),
    ]

    for rel_path, fmt in candidates:
        candidate = target_dir / rel_path
        if candidate.is_file():
            return candidate, fmt

    # Fallback search for any *requirements*.txt file under target_dir (up to depth 2)
    try:
        for req_file in target_dir.glob("*requirements*.txt"):
            if req_file.is_file():
                return req_file, "requirements.txt"
        for req_file in target_dir.glob("*/*requirements*.txt"):
            if req_file.is_file():
                return req_file, "requirements.txt"
    except Exception:
        pass

    return None, "none"


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def parse_deps(filepath: str | None = None) -> list[tuple[str, str]]:
    """Auto-detect dependency file format and parse it.

    Supports direct file paths, directory paths (auto-discovers requirements.txt /
    src/requirements.txt / pyproject.toml / etc.), or None (scans active cwd / env).
    """
    path_obj, fmt = find_dependency_file(filepath)
    if not path_obj or fmt == "none":
        # Zero-config fallback: parse installed packages in environment
        return parse_installed_environment()

    str_path = str(path_obj)
    if fmt == "pyproject.toml":
        deps = parse_pyproject(str_path)
    elif fmt == "pipfile.lock":
        deps = parse_pipfile_lock(str_path)
    elif fmt in ("poetry.lock", "uv.lock", "pdm.lock"):
        deps = parse_poetry_lock(str_path)
    else:
        deps = parse_requirements(str_path)

    # Deduplicate while preserving insertion order
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str]] = []
    for item in deps:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_name(name: str) -> str:
    """Normalise a package name per PEP 503 (lowercase, hyphens)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_pep508_pin(spec: str) -> tuple[str, str] | None:
    """Extract (name, version) from a PEP 508 dependency string if pinned or range-specified."""
    spec = spec.split(";")[0].strip()
    match_exact = re.match(
        r"^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?==([0-9A-Za-z\.\-]+)",
        spec,
    )
    if match_exact:
        return (_normalise_name(match_exact.group(1)), match_exact.group(2))

    # Match name and optional range constraint
    match_name = re.match(r"^([A-Za-z0-9_\-\.]+)", spec)
    if match_name:
        pkg = match_name.group(1)
        norm = _normalise_name(pkg)
        installed = _resolve_installed_version(norm)
        if installed:
            return (norm, installed)
        # Extract version number if present
        ver_match = re.search(r"([0-9][0-9A-Za-z\.\-]*)", spec)
        if ver_match:
            return (norm, ver_match.group(1))

    return None

