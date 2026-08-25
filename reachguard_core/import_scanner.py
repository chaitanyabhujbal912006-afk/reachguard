"""AST-based import scanner for ReachGuard.

Walks all Python source files in a directory and builds a map of
which packages are imported, enabling an import-based reachability
pre-filter: if a package is never imported → UNREACHABLE immediately,
without needing a call graph.

Usage:
    scanner = ImportScanner(src_path)
    imported = scanner.scan()           # set of normalised package names
    if "flask" not in imported:
        status = ReachabilityStatus.UNREACHABLE
"""

import ast
import os
import re
from pathlib import Path

from reachguard_core.logger import get_logger

log = get_logger(__name__)

# ── Name normalisation ────────────────────────────────────────────────────────

def _normalise(name: str) -> str:
    """Normalise a Python import name to a PyPI package name.

    Python import names use underscores; PyPI names use hyphens.
    E.g. ``PIL`` → ``pillow``, ``yaml`` → ``pyyaml``, ``sklearn`` → ``scikit-learn``.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


# Well-known import-name → package-name remappings
_IMPORT_TO_PKG: dict[str, str] = {
    "yaml":      "pyyaml",
    "cv2":       "opencv-python",
    "PIL":       "pillow",
    "sklearn":   "scikit-learn",
    "bs4":       "beautifulsoup4",
    "attr":      "attrs",
    "dotenv":    "python-dotenv",
    "jose":      "python-jose",
    "jwt":       "pyjwt",
    "dateutil":  "python-dateutil",
    "google.cloud": "google-cloud",
    "pkg_resources": "setuptools",
    "gi":        "pygobject",
}


def _map_import_to_pkg(import_name: str) -> str:
    """Convert an import name (top-level module) to a likely PyPI package name."""
    top = import_name.split(".")[0]
    if top in _IMPORT_TO_PKG:
        return _IMPORT_TO_PKG[top]
    return _normalise(top)


# ── Scanner ───────────────────────────────────────────────────────────────────

class ImportScanner:
    """Scans Python source files to find which packages are imported."""

    def __init__(self, src_path: str) -> None:
        self._src = Path(src_path)
        self._result: set[str] | None = None

    def scan(self) -> set[str]:
        """Return the set of normalised package names imported anywhere in *src_path*."""
        if self._result is not None:
            return self._result

        imported: set[str] = set()
        files_scanned = 0

        for root, _dirs, files in os.walk(self._src):
            # Skip common non-project directories
            _dirs[:] = [
                d for d in _dirs
                if d not in {"__pycache__", ".git", ".venv", "venv", "node_modules", ".tox"}
            ]
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                filepath = Path(root) / filename
                try:
                    source = filepath.read_text(encoding="utf-8", errors="ignore")
                    tree = ast.parse(source, filename=str(filepath))
                    files_scanned += 1
                except (SyntaxError, OSError) as exc:
                    log.debug("Skipping %s: %s", filepath, exc)
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imported.add(_map_import_to_pkg(alias.name))
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imported.add(_map_import_to_pkg(node.module))

        log.debug("ImportScanner: scanned %d files, found %d imported packages", files_scanned, len(imported))
        self._result = imported
        return imported

    def is_imported(self, package_name: str) -> bool:
        """Return True if *package_name* (normalised) is imported in any source file."""
        norm = _normalise(package_name)
        imported = self.scan()
        # Direct match or prefix match (e.g. "google-cloud" matches "google-cloud-storage")
        return any(
            imp == norm or imp.startswith(norm + "-") or norm.startswith(imp + "-")
            for imp in imported
        )
