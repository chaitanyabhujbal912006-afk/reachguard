"""ReachGuard core package."""

import importlib.metadata

try:
    __version__ = importlib.metadata.version("reachguard")
except importlib.metadata.PackageNotFoundError:
    __version__ = "1.0.0"
