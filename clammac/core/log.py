"""Application logging.

Logs go to a rotating file in ``~/Library/Logs/ClamMac`` so a user can hand
them over when something goes wrong, and to stderr when ClamMac is run from a
terminal. Nothing here ever logs the *contents* of a scanned file -- only its
path, and only at debug level.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

from . import paths

__all__ = ["configure", "get_logger", "log_file_path", "read_recent"]

_CONFIGURED = False
_FORMAT = "%(asctime)s  %(levelname)-7s  %(name)-22s  %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def log_file_path() -> Path:
    return paths.logs_dir() / "clammac.log"


def configure(*, verbose: bool | None = None) -> None:
    """Set up handlers once. Safe to call repeatedly."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    if verbose is None:
        verbose = os.environ.get("CLAMMAC_DEBUG", "").lower() in {"1", "true", "yes"}

    root = logging.getLogger("clammac")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)

    try:
        paths.logs_dir().mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path(), maxBytes=2 << 20, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        root.addHandler(file_handler)
    except OSError:
        # A read-only home directory should not prevent the app from running.
        pass

    if sys.stderr is not None and not paths.running_frozen():
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(formatter)
        stream.setLevel(logging.DEBUG if verbose else logging.WARNING)
        root.addHandler(stream)


def get_logger(name: str) -> logging.Logger:
    """A logger under the ``clammac`` namespace."""
    configure()
    short = name.split(".")[-1] if name.startswith("clammac") else name
    return logging.getLogger(f"clammac.{short}")


def read_recent(limit: int = 500) -> list[str]:
    """The last ``limit`` lines of the log, for the in-app log viewer."""
    path = log_file_path()
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.readlines()[-limit:]
    except OSError:
        return []
