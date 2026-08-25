"""Entry point detection for Python repositories.

Walks a directory tree and identifies functions and class methods that act
as program entry points, including:
  - ``if __name__ == '__main__'`` blocks
  - Flask / FastAPI / Starlette route-decorated functions & event handlers
  - Django path/re_path/url view decorators & Class-Based Views (CBVs)
  - Click & Typer CLI commands (@click.command, @app.command)
  - Celery @task and @shared_task decorated functions
"""

import ast
import os

# HTTP-method, routing, CLI, and task keywords used across major Python frameworks
_ROUTE_KEYWORDS: frozenset[str] = frozenset({
    # Flask / FastAPI / Starlette / Litestar / Bottle routes & event handlers
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    "websocket", "on_event", "lifespan", "endpoint", "handler",
    # Django URL patterns
    "path", "re_path", "url",
    # Click & Typer CLI decorators
    "command", "group", "cli",
    # Celery background tasks
    "task", "shared_task",
    # Tornado / Aiohttp web handlers
    "prepare", "initialize", "web",
})

# Base class names for Django / DRF / Tornado / Aiohttp Class-Based Views
_DJANGO_CBV_BASES: frozenset[str] = frozenset({
    "View", "APIView", "ModelViewSet", "GenericAPIView", "ReadOnlyModelViewSet",
    "CreateAPIView", "ListAPIView", "RetrieveAPIView", "UpdateAPIView", "DestroyAPIView",
    "RequestHandler", "ViewHandler",
})


def find_entry_points(repo_path: str) -> list[str]:
    """Return a list of qualified entry point identifiers found under *repo_path*.

    Each entry is a string of the form ``<filepath>::<name>`` where *name*
    is either ``__main__``, the decorated function name, or a CBV method.

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

                # -- Web & CLI Framework Decorators ---------------------------
                # Matches Flask, FastAPI, Starlette, Django, Click, Typer, Celery
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
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
                            break

                # -- Django Class-Based Views (CBVs) --------------------------
                if isinstance(node, ast.ClassDef):
                    # Check if class inherits from known View / APIView bases
                    base_names = set()
                    for base in node.bases:
                        if isinstance(base, ast.Name):
                            base_names.add(base.id)
                        elif isinstance(base, ast.Attribute):
                            base_names.add(base.attr)

                    if base_names & _DJANGO_CBV_BASES:
                        # Extract HTTP handler methods (get, post, put, delete, dispatch)
                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                if item.name in ("get", "post", "put", "delete", "patch", "dispatch", "handle"):
                                    ep = f"{filepath}::{node.name}.{item.name}"
                                    if ep not in seen:
                                        seen.add(ep)
                                        entry_points.append(ep)

    return entry_points
