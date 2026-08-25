"""Tests for the ImportScanner module."""

import textwrap
from pathlib import Path

from reachguard_core.import_scanner import ImportScanner, _map_import_to_pkg, _normalise

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_src(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create Python files in *tmp_path* from a {filename: source} dict."""
    src = tmp_path / "src"
    src.mkdir()
    for name, code in files.items():
        (src / name).write_text(textwrap.dedent(code), encoding="utf-8")
    return src


# ── Unit tests ────────────────────────────────────────────────────────────────

def test_normalise_replaces_underscores():
    assert _normalise("some_package") == "some-package"


def test_map_import_pil_to_pillow():
    assert _map_import_to_pkg("PIL") == "pillow"


def test_map_import_yaml_to_pyyaml():
    assert _map_import_to_pkg("yaml") == "pyyaml"


def test_map_import_sklearn_to_scikit_learn():
    assert _map_import_to_pkg("sklearn") == "scikit-learn"


def test_map_import_regular_package():
    assert _map_import_to_pkg("flask") == "flask"


# ── Integration tests ─────────────────────────────────────────────────────────

def test_scanner_finds_direct_import(tmp_path):
    src = make_src(tmp_path, {
        "app.py": """
            import flask
            app = flask.Flask(__name__)
        """
    })
    scanner = ImportScanner(str(src))
    assert scanner.is_imported("flask")


def test_scanner_finds_from_import(tmp_path):
    src = make_src(tmp_path, {
        "views.py": """
            from requests import Session
        """
    })
    scanner = ImportScanner(str(src))
    assert scanner.is_imported("requests")


def test_scanner_returns_false_for_unimported(tmp_path):
    src = make_src(tmp_path, {
        "app.py": """
            import flask
        """
    })
    scanner = ImportScanner(str(src))
    assert not scanner.is_imported("django")


def test_scanner_handles_syntax_error(tmp_path):
    """Files with syntax errors should be skipped gracefully."""
    src = make_src(tmp_path, {
        "bad.py": "def foo(: pass",
        "good.py": "import requests",
    })
    scanner = ImportScanner(str(src))
    assert scanner.is_imported("requests")


def test_scanner_skips_venv_directory(tmp_path):
    """The .venv directory should not be scanned."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import flask", encoding="utf-8")
    venv = src / ".venv" / "lib" / "site-packages"
    venv.mkdir(parents=True)
    (venv / "evil.py").write_text("import django", encoding="utf-8")

    scanner = ImportScanner(str(src))
    assert scanner.is_imported("flask")
    assert not scanner.is_imported("django")


def test_scanner_caches_result(tmp_path):
    """Calling scan() twice should return the same object (cached)."""
    src = make_src(tmp_path, {"a.py": "import flask"})
    scanner = ImportScanner(str(src))
    result1 = scanner.scan()
    result2 = scanner.scan()
    assert result1 is result2


def test_scanner_pil_via_from_import(tmp_path):
    src = make_src(tmp_path, {
        "img.py": "from PIL import Image"
    })
    scanner = ImportScanner(str(src))
    assert scanner.is_imported("pillow")


def test_scanner_empty_directory(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    scanner = ImportScanner(str(src))
    assert scanner.scan() == set()
