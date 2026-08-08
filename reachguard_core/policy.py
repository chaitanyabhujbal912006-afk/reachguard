"""Policy & ignore configuration loader for ReachGuard.

Supports policy definitions via:
- ``.reachguardignore`` (simple line-based list of CVE IDs or package names)
- ``reachguard.toml`` or ``pyproject.toml`` (``[tool.reachguard.ignore]`` sections)

Allows developers to dismiss known false positives or accepted risks
with optional expiration dates and audit notes.
"""

from datetime import datetime, timezone
from pathlib import Path
import re

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None


class ReachGuardPolicy:
    """Encapsulates suppression rules for ReachGuard scan findings."""

    def __init__(self) -> None:
        # cve_id or package_name -> rule dict
        self.ignored_ids: dict[str, dict] = {}
        self.ignored_packages: set[str] = set()

    def add_ignore_id(self, cve_id: str, reason: str = "", expires: str | None = None) -> None:
        """Add a specific CVE/GHSA ID to ignore list."""
        self.ignored_ids[cve_id.upper()] = {
            "reason": reason,
            "expires": expires,
        }

    def add_ignore_package(self, package_name: str) -> None:
        """Add a package name to ignore list."""
        self.ignored_packages.add(package_name.lower())

    def is_ignored(self, cve_id: str, package_name: str) -> tuple[bool, str]:
        """Check if *cve_id* or *package_name* is currently suppressed.

        Returns:
            Tuple of ``(is_ignored, reason)``.
        """
        pkg_norm = package_name.lower()
        if pkg_norm in self.ignored_packages:
            return True, f"Package '{package_name}' ignored by policy"

        cve_norm = cve_id.upper()
        if cve_norm in self.ignored_ids:
            rule = self.ignored_ids[cve_norm]
            expires = rule.get("expires")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    if now > exp_dt:
                        return False, ""  # Policy expired
                except ValueError:
                    pass
            reason = rule.get("reason") or "Ignored by policy"
            return True, reason

        return False, ""


def load_policy(config_path: str | None = None) -> ReachGuardPolicy:
    """Auto-detect and load policy rules from file system.

    Checks:
    1. Explicit *config_path* if provided.
    2. ``.reachguardignore`` in current directory.
    3. ``reachguard.toml`` in current directory.
    4. ``pyproject.toml`` ``[tool.reachguard]`` section.
    """
    policy = ReachGuardPolicy()

    # 1. Explicit path
    if config_path and Path(config_path).exists():
        _parse_policy_file(Path(config_path), policy)
        return policy

    # 2. .reachguardignore
    dot_ignore = Path(".reachguardignore")
    if dot_ignore.exists():
        _parse_dot_ignore(dot_ignore, policy)

    # 3. reachguard.toml
    toml_config = Path("reachguard.toml")
    if toml_config.exists():
        _parse_toml_config(toml_config, policy)

    # 4. pyproject.toml
    pyproject = Path("pyproject.toml")
    if pyproject.exists():
        _parse_pyproject_config(pyproject, policy)

    return policy


def _parse_dot_ignore(filepath: Path, policy: ReachGuardPolicy) -> None:
    """Parse line-based .reachguardignore file."""
    try:
        with open(filepath, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Split by space if reason provided: CVE-2023-1234 # Reason
                parts = line.split("#", 1)
                token = parts[0].strip()
                reason = parts[1].strip() if len(parts) > 1 else "Ignored via .reachguardignore"
                if token.startswith("CVE-") or token.startswith("GHSA-") or token.startswith("PYSEC-"):
                    policy.add_ignore_id(token, reason=reason)
                else:
                    policy.add_ignore_package(token)
    except Exception:
        pass


def _parse_toml_config(filepath: Path, policy: ReachGuardPolicy) -> None:
    """Parse reachguard.toml config file."""
    if not tomllib:
        return
    try:
        with open(filepath, "rb") as fh:
            data = tomllib.load(fh)
        _extract_toml_policy(data, policy)
    except Exception:
        pass


def _parse_pyproject_config(filepath: Path, policy: ReachGuardPolicy) -> None:
    """Parse [tool.reachguard] in pyproject.toml."""
    if not tomllib:
        return
    try:
        with open(filepath, "rb") as fh:
            data = tomllib.load(fh)
        reachguard_section = data.get("tool", {}).get("reachguard", {})
        _extract_toml_policy(reachguard_section, policy)
    except Exception:
        pass


def _parse_policy_file(filepath: Path, policy: ReachGuardPolicy) -> None:
    """Dispatch file parsing based on extension."""
    if filepath.suffix.lower() == ".toml":
        _parse_toml_config(filepath, policy)
    else:
        _parse_dot_ignore(filepath, policy)


def _extract_toml_policy(data: dict, policy: ReachGuardPolicy) -> None:
    """Extract ignore rules from a parsed TOML dict."""
    ignore_sec = data.get("ignore", {})
    if isinstance(ignore_sec, list):
        for item in ignore_sec:
            if isinstance(item, str):
                policy.add_ignore_id(item)
    elif isinstance(ignore_sec, dict):
        for key, val in ignore_sec.items():
            if isinstance(val, str):
                policy.add_ignore_id(key, reason=val)
            elif isinstance(val, dict):
                reason = val.get("reason", "")
                expires = val.get("expires", None)
                policy.add_ignore_id(key, reason=reason, expires=expires)

    ignored_pkgs = data.get("ignore_packages", [])
    if isinstance(ignored_pkgs, list):
        for pkg in ignored_pkgs:
            if isinstance(pkg, str):
                policy.add_ignore_package(pkg)
