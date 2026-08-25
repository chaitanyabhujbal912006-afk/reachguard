"""Structured logging for ReachGuard.

Provides a centrally configured logger that respects:
- ``--verbose`` / ``-v``  → DEBUG level (raw API responses, full tracebacks)
- ``--quiet``             → ERROR level only (CI log-friendly)
- ``--log-file``          → tee output to a file
- ``--log-format json``   → machine-readable JSON log lines (SIEM/Splunk)

Usage in any module:
    from reachguard_core.logger import get_logger
    log = get_logger(__name__)
    log.debug("raw osv response: %s", data)
    log.warning("PyCG timed out")
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── Formatters ───────────────────────────────────────────────────────────────

class _PlainFormatter(logging.Formatter):
    """Human-readable log formatter: ``[LEVEL] message``."""
    _LEVEL_LABELS = {
        logging.DEBUG:    "DEBUG",
        logging.INFO:     "INFO ",
        logging.WARNING:  "WARN ",
        logging.ERROR:    "ERROR",
        logging.CRITICAL: "CRIT ",
    }

    def format(self, record: logging.LogRecord) -> str:
        label = self._LEVEL_LABELS.get(record.levelno, record.levelname)
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        msg = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return f"[{ts}] {label} {record.name}: {msg}"


class _JSONFormatter(logging.Formatter):
    """Machine-readable JSON log formatter for SIEM/Splunk ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts":      datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)


# ── Root logger setup ────────────────────────────────────────────────────────

_ROOT_LOGGER_NAME = "reachguard"
_configured = False


def configure_logging(
    verbose: bool = False,
    quiet: bool = False,
    log_file: str | None = None,
    log_format: str = "plain",
) -> None:
    """Configure the root ReachGuard logger.  Call once from CLI startup."""
    global _configured

    root = logging.getLogger(_ROOT_LOGGER_NAME)
    root.handlers.clear()

    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING   # default: only warnings and errors to stderr

    root.setLevel(level)

    formatter: logging.Formatter
    if log_format == "json":
        formatter = _JSONFormatter()
    else:
        formatter = _PlainFormatter()

    # Always attach a stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(level)
    root.addHandler(stderr_handler)

    # Optionally tee to a file at DEBUG level
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            root.addHandler(file_handler)
        except OSError as exc:
            root.warning("Could not open log file %s: %s", log_file, exc)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``reachguard`` namespace."""
    if not _configured:
        # Lazy default: silent unless configure_logging() is called
        logging.getLogger(_ROOT_LOGGER_NAME).addHandler(logging.NullHandler())
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
