"""Entry point detection for Python repositories.

Walks a directory tree and identifies functions that act as program
entry points, including:
  - ``if __name__ == '__main__'`` blocks
  - Flask / FastAPI / Starlette route-decorated functions
  - Django path/re_path/url view decorators
  - Celery @task and @shared_task decorated functions
"""

import ast
import os

# HTTP-method and routing keywords used by Flask, FastAPI, Starlette, Django, etc.
_ROUTE_KEYWORDS: frozenset[str] = frozenset({
    "route",
    "get", "post", "put", "delete", "patch", "head", "options",
    "websocket",
    # Django URL patterns
    "path", "re_path", "url",
    # Celery tasks
    "task", "shared_task",
})


def find_entry_points(repo_path: str) -> list[str]:
    """Return a list of qualified entry point identifiers found under *repo_path*.

    Each entry is a string of the form ``<filepath>::<name>`` where *name*
    is either ``__main__`` (for a top-level ``if __name__ == '__main__'``
    block) or the decorated function name.

    Args:
        repo_path: Absolute or relative path to the root of the repository
            (or any directory of Python source files) to scan.

    Returns:
        A deduplicated list of entry point strings.
    """
    entry_points: list[str] = []
    seen: set[str] = set()

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
                        ep = f"{filepath}::__main__"
                        if ep not in seen:
                            seen.add(ep)
                            entry_points.append(ep)

                # -- Web-framework route decorators ---------------------------
                # Matches Flask (@app.route, @bp.route),
                # FastAPI/Starlette (@app.get, @router.post, ...),
                # Django (@path, @re_path), Celery (@task, @shared_task), etc.
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        # Extract the attribute name (e.g. "route" from app.route)
                        # or the plain Name (e.g. "task") from the decorator AST.
                        dec_name: str | None = None
                        if isinstance(decorator, ast.Attribute):
                            dec_name = decorator.attr
                        elif isinstance(decorator, ast.Name):
                            dec_name = decorator.id
                        elif isinstance(decorator, ast.Call):
                            func = decorator.func
                            if isinstance(func, ast.Attribute):
                                dec_name = func.attr
                            elif isinstance(func, ast.Name):
                                dec_name = func.id

                        if dec_name and dec_name in _ROUTE_KEYWORDS:
                            ep = f"{filepath}::{node.name}"
                            if ep not in seen:
                                seen.add(ep)
                                entry_points.append(ep)
                            # Record once per function even with multiple decorators.
                            break

    return entry_points
