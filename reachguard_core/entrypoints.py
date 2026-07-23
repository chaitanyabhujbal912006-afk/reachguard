"""Entry point detection for Python repositories.

Walks a directory tree and identifies functions that act as program
entry points, including:
  - ``if __name__ == '__main__'`` blocks
  - Flask / FastAPI / Starlette route-decorated functions
"""

import ast
import os


def find_entry_points(repo_path: str) -> list[str]:
    """Return a list of qualified entry point identifiers found under *repo_path*.

    Each entry is a string of the form ``<filepath>::<name>`` where *name*
    is either ``__main__`` (for a top-level ``if __name__ == '__main__'``
    block) or the decorated function name.

    Args:
        repo_path: Absolute or relative path to the root of the repository
            (or any directory of Python source files) to scan.

    Returns:
        A list of entry point strings, potentially with duplicates if a
        function has more than one qualifying decorator.
    """
    entry_points: list[str] = []

    for root, _dirs, files in os.walk(repo_path):
        for filename in files:
            if not filename.endswith(".py"):
                continue

            filepath = os.path.join(root, filename)

            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    source = fh.read()
                tree = ast.parse(source, filename=filepath)
            except (SyntaxError, UnicodeDecodeError):
                # Silently skip files we cannot parse.
                continue

            for node in ast.walk(tree):
                # -- if __name__ == "__main__" blocks -------------------------
                if isinstance(node, ast.If):
                    test = node.test
                    if (
                        isinstance(test, ast.Compare)
                        and isinstance(test.left, ast.Name)
                        and test.left.id == "__name__"
                        and len(test.comparators) == 1
                        and isinstance(test.comparators[0], ast.Constant)
                        and test.comparators[0].value == "__main__"
                    ):
                        entry_points.append(f"{filepath}::__main__")

                # -- Web-framework route decorators ---------------------------
                # Matches Flask (@app.route, @bp.route),
                # FastAPI/Starlette (@app.get, @router.post, ...), etc.
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        dec_str = ast.dump(decorator)
                        if any(
                            kw in dec_str
                            for kw in ("route", "get", "post", "put", "delete", "patch", "websocket")
                        ):
                            entry_points.append(f"{filepath}::{node.name}")
                            # Record once per function even with multiple decorators.
                            break

    return entry_points
