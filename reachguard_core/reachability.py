"""Reachability analysis for OSV vulnerabilities.

Combines:
- ``extract_vulnerable_functions`` -- mine function/class names from an OSV
  advisory's free-text and structured fields.
- ``is_reachable`` -- BFS traversal of a PyCG call-graph dict to decide
  whether *any* entry point can reach a target function.
- ``ReachabilityStatus`` -- enum capturing the three outcomes possible when
  OSV data is sparse.

A1 fix (call graph / entry-point name normalisation)
----------------------------------------------------
PyCG produces keys like ``src\\flask\\app.Flask.wsgi_app``.
``find_entry_points`` produces strings like
``../test-target/src/flask/cli.py::routes_command``.
These never matched directly, so the old code fell back to seeding *every*
call graph node, making everything look reachable.
Fix: three-tier seeding strategy (basename → module-path prefix → __main__).

A2 fix (target-function matching)
----------------------------------
Old code used ``target in node or node in target`` (substring), so the
target ``"load"`` matched ``"upload"``, ``"reload"`` etc.
Fix: suffix-anchored set-intersection of normalised name forms.

A3 fix (stdlib / template noise filtering)
-------------------------------------------
Some OSV advisories mention names like ``str.format`` or ``xmlattr`` which
are not Python callables in user code (stdlib methods, Jinja filters, etc.).
Extracting them as targets produces false UNREACHABLE results because they
will never appear in a PyCG call graph.  Fix: ``_is_noise_target()`` drops
them before they reach the BFS.
"""

import os
import re
from enum import Enum

# OS path separator — used to identify user-code keys in PyCG output.
_SEP = os.sep  # '\\' on Windows, '/' on POSIX


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------

class ReachabilityStatus(str, Enum):
    """Outcome of a reachability check."""

    REACHABLE = "REACHABLE"
    """The target function is reachable from at least one entry point."""

    UNREACHABLE = "UNREACHABLE"
    """The target function is explicitly not reachable from any entry point."""

    UNKNOWN = "UNKNOWN"
    """No function-level target was found in the advisory; manual review
    is needed but the package is imported and used."""


# ---------------------------------------------------------------------------
# Step 9 -- extract function/class names from OSV advisory data
# ---------------------------------------------------------------------------

# Regex patterns for picking up identifiers mentioned in free text.
# Catches: backtick-quoted names, ``func_name()``, and "function foo".
_BACKTICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]*)`")
_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]+)\s*\(\)")
_KEYWORD_RE = re.compile(
    r"(?:function|class|method|def)\s+([A-Za-z_][A-Za-z0-9_.]*)", re.IGNORECASE
)


# Python keywords and common English stop-words that the regex might
# extract from advisory prose but that are useless as function targets.
_STOPWORDS: frozenset[str] = frozenset({
    "and", "or", "not", "in", "is", "if", "for", "the", "a", "an",
    "with", "from", "to", "of", "on", "by", "be", "this", "that",
    "as", "at", "it", "its", "new", "use", "via",
    # Python keywords that could appear in "method X" patterns:
    "class", "def", "return", "import", "None", "True", "False",
})
_MIN_NAME_LEN = 4  # Ignore single-word tokens shorter than this.


# ---------------------------------------------------------------------------
# A3 -- stdlib / template noise filter
# ---------------------------------------------------------------------------

# Built-in type names whose dotted methods (e.g. str.format, int.bit_length)
# will never appear as user-callable nodes in a PyCG call graph.
_STDLIB_TYPES: frozenset[str] = frozenset({
    "str", "int", "float", "bool", "bytes", "bytearray",
    "list", "tuple", "dict", "set", "frozenset",
    "type", "object", "super",
})

# Jinja2 / Django template filter names that appear in advisory prose but
# are not Python function identifiers in user source code.
_TEMPLATE_NOISE: frozenset[str] = frozenset({
    "xmlattr", "tojson", "truncate", "wordwrap", "filesizeformat",
    "striptags", "urlencode", "urlize", "groupby", "selectattr",
    "rejectattr", "forceescape", "safe", "escape", "indent",
})


def _is_noise_target(name: str) -> bool:
    """Return True if *name* is unlikely to appear in a PyCG call graph.

    Covers:
    - stdlib type method references like ``str.format``, ``int.bit_length``
    - Jinja2/Django template filter names
    - Names whose left-hand dotted prefix is a known built-in type
    """
    # "str.format" -> prefix "str" is a stdlib type
    if "." in name:
        prefix = name.split(".", 1)[0]
        if prefix in _STDLIB_TYPES:
            return True
    # Plain template filter names
    bare = name.rsplit(".", 1)[-1]
    if bare in _TEMPLATE_NOISE:
        return True
    return False


def _extract_names_from_text(text: str) -> list[str]:
    """Pull plausible Python identifiers from a free-text string."""
    names: list[str] = []
    for pattern in (_BACKTICK_RE, _FUNC_CALL_RE, _KEYWORD_RE):
        names.extend(pattern.findall(text))

    # Filter: remove stop-words, too-short tokens, pure numbers, and noise.
    filtered = [
        n for n in names
        if len(n) >= _MIN_NAME_LEN
        and n not in _STOPWORDS
        and not n.isdigit()
        and not _is_noise_target(n)   # A3: drop stdlib/template names
    ]

    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for n in filtered:
        if n not in seen:
            seen.add(n)
            unique.append(n)
    return unique


def extract_vulnerable_functions(vuln: dict) -> list[str]:
    """Pull function-level identifiers from an OSV advisory, if present.

    OSV does not standardise function-level data, so this function uses
    several heuristics in decreasing priority:

    1. ``affected[].ecosystem_specific`` or ``database_specific`` fields
       (some ecosystems store ``functions`` lists here).
    2. Free-text mining from ``details`` and ``summary`` via regex.

    Returns an empty list when no function names can be identified -- that
    is the expected, common case.  Callers should treat an empty return as
    "reachability unknown".
    """
    functions: list[str] = []

    for affected in vuln.get("affected", []):
        # Some ecosystems (e.g. Go) put a "functions" list here.
        for spec in (
            affected.get("ecosystem_specific", {}),
            affected.get("database_specific", {}),
        ):
            if isinstance(spec, dict):
                funcs = spec.get("functions") or spec.get("vulnerable_functions") or []
                if isinstance(funcs, list):
                    functions.extend(funcs)

    # Fall back to free-text mining.
    if not functions:
        for field in ("details", "summary"):
            text = vuln.get(field, "") or ""
            functions.extend(_extract_names_from_text(text))

    # Deduplicate.
    seen: set[str] = set()
    unique: list[str] = []
    for f in functions:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# A1 helpers -- call graph / entry-point name normalisation
# ---------------------------------------------------------------------------

def _ep_func_name(ep: str) -> str:
    """Extract bare function name from an entry-point string.

    >>> _ep_func_name('../src/app.py::login')
    'login'
    """
    return ep.rsplit("::", 1)[-1]


def _ep_to_cg_prefix(ep: str) -> str:
    """Convert an entry-point filepath to the path prefix used in PyCG keys.

    PyCG keys for user code look like ``src\\flask\\app.Flask.run``.
    Entry points look like ``../test-target/src/flask/cli.py::func``.
    This function extracts ``src\\flask\\cli`` (without the .py extension)
    so it can be used as a ``str.startswith`` prefix against CG keys.
    """
    file_path = ep.rsplit("::", 1)[0]          # '../test-target/src/flask/cli.py'
    norm = file_path.replace("/", _SEP).replace("\\\\", _SEP)
    if norm.endswith(".py"):
        norm = norm[:-3]                        # strip .py
    parts = [p for p in norm.split(_SEP) if p not in ("..", ".", "")]
    # Heuristic: start from the 'src' directory if present, else last 3 parts.
    try:
        src_idx = next(i for i, p in enumerate(parts) if p == "src")
        meaningful = parts[src_idx:]
    except StopIteration:
        meaningful = parts[-3:]
    return _SEP.join(meaningful)                # e.g. 'src\\flask\\cli'


def _seed_from_entry_points(
    call_graph: dict[str, list[str]],
    entry_points: list[str],
) -> list[str]:
    """Return the set of call-graph keys to seed BFS from.

    Uses a three-tier strategy so that entry points that don't share a
    naming scheme with PyCG keys still produce a meaningful (not trivially
    over-broad) seed set.

    Tier 1 — basename match
        ``routes_command`` matches any CG key whose last dotted segment is
        ``routes_command``.
    Tier 2 — module-path prefix match
        ``src\\flask\\cli`` matches any CG key that starts with that prefix.
    Tier 3 — ``__main__`` present
        An ``if __name__ == '__main__'`` entry point means the whole app runs
        from top-level, so we seed all *user-code* keys (those containing the
        OS path separator — PyCG's marker for keys derived from source files).
    Tier 4 — nothing matched (last resort)
        Fall back to all keys.  This is the old behaviour; it is intentionally
        kept as a safety net rather than silently returning an empty seed set.
    """
    has_main    = any(_ep_func_name(ep) == "__main__" for ep in entry_points)
    ep_basenames = {_ep_func_name(ep) for ep in entry_points if _ep_func_name(ep) != "__main__"}
    ep_prefixes  = {_ep_to_cg_prefix(ep) for ep in entry_points}

    # All CG keys that originate from user source (contain path separator).
    user_code_keys = [k for k in call_graph if _SEP in k]

    seeds: set[str] = set()

    # Tier 1: bare function-name match.
    for k in call_graph:
        after_sep = k.rsplit(_SEP, 1)[-1]       # 'app.Flask.run'
        bare      = after_sep.rsplit(".", 1)[-1] # 'run'
        if bare in ep_basenames:
            seeds.add(k)

    # Tier 2: file-path prefix match.
    for k in call_graph:
        for prefix in ep_prefixes:
            if prefix and k.startswith(prefix):
                seeds.add(k)

    # Tier 3: __main__ -> whole user codebase is reachable from that script.
    if has_main:
        seeds.update(user_code_keys)

    # Tier 4: fallback — nothing matched at all.
    if not seeds:
        return list(call_graph.keys())

    return list(seeds)


# ---------------------------------------------------------------------------
# A2 helpers -- suffix-anchored target matching
# ---------------------------------------------------------------------------

def _target_name_forms(target: str) -> frozenset[str]:
    """All matchable forms of an advisory target name.

    >>> _target_name_forms('werkzeug.safe_join')
    frozenset({'werkzeug.safe_join', 'safe_join'})
    >>> _target_name_forms('full_load')
    frozenset({'full_load'})
    """
    forms = {target}
    if "." in target:
        forms.add(target.rsplit(".", 1)[-1])  # bare name only
    return frozenset(forms)


def _cg_key_name_forms(key: str) -> frozenset[str]:
    """All suffix-anchored dotted forms of a PyCG key.

    ``src\\flask\\app.Flask.safe_join`` produces::

        {'safe_join', 'Flask.safe_join', 'app.Flask.safe_join'}

    ``werkzeug.safe_join`` produces::

        {'safe_join', 'werkzeug.safe_join'}

    This ensures that ``target='safe_join'`` matches
    ``'werkzeug.safe_join'`` but **not** ``'upload'`` or ``'reload'``.
    """
    after_sep = key.rsplit(_SEP, 1)[-1]  # strip path prefix if present
    parts = after_sep.split(".")
    return frozenset(".".join(parts[i:]) for i in range(len(parts)))


def _node_matches_target(cg_key: str, target: str) -> bool:
    """Return True iff *cg_key* is a name-form match for *target*."""
    return bool(_target_name_forms(target) & _cg_key_name_forms(cg_key))


# ---------------------------------------------------------------------------
# BFS reachability check (uses A1 + A2 fixes)
# ---------------------------------------------------------------------------

from collections import deque


def find_reachability_path(
    call_graph: dict[str, list[str]],
    entry_points: list[str],
    target_function: str,
) -> list[str] | None:
    """Return the shortest call path from an entry point to *target_function*.

    Uses BFS over *call_graph* to reconstruct the trace.

    Returns:
        List of node strings representing the call chain, e.g.::

            ["src\\\\app.Flask.run", "src\\\\app.Flask.dispatch_request", "werkzeug.safe_join"]

        Returns ``None`` if *target_function* cannot be reached.
    """
    seeds = _seed_from_entry_points(call_graph, entry_points)
    if not seeds:
        return None

    visited: set[str] = set(seeds)
    queue = deque([(s, [s]) for s in seeds])

    while queue:
        current, path = queue.popleft()

        if _node_matches_target(current, target_function):
            return path

        for callee in call_graph.get(current, []):
            if callee not in visited:
                visited.add(callee)
                queue.append((callee, path + [callee]))

    return None


def is_reachable(
    call_graph: dict[str, list[str]],
    entry_points: list[str],
    target_function: str,
) -> bool:
    """Return *True* if *target_function* is reachable from any entry point.

    Convenience wrapper around :func:`find_reachability_path`.
    """
    return find_reachability_path(call_graph, entry_points, target_function) is not None


def check_reachability_details(
    call_graph: dict[str, list[str]],
    entry_points: list[str],
    vuln: dict,
) -> tuple[ReachabilityStatus, list[str] | None]:
    """High-level helper returning status and the call trace list if reachable.

    Returns:
        A tuple of ``(ReachabilityStatus, call_path_list_or_None)``.
    """
    targets = extract_vulnerable_functions(vuln)

    if not targets:
        return ReachabilityStatus.UNKNOWN, None

    for target in targets:
        path = find_reachability_path(call_graph, entry_points, target)
        if path:
            return ReachabilityStatus.REACHABLE, path

    return ReachabilityStatus.UNREACHABLE, None


def check_reachability(
    call_graph: dict[str, list[str]],
    entry_points: list[str],
    vuln: dict,
) -> ReachabilityStatus:
    """High-level helper that combines extraction and reachability check."""
    status, _ = check_reachability_details(call_graph, entry_points, vuln)
    return status
