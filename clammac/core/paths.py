"""Filesystem locations ClamMac uses, and the rules for choosing them.

Everything ClamMac writes lives under a single support directory so that the
application can be removed completely by deleting the bundle plus that one
folder. Nothing is ever written outside the user's home directory unless the
user explicitly authorises a system-wide engine install.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..version import APP_NAME

__all__ = [
    "is_macos",
    "support_dir",
    "engine_dir",
    "database_dir",
    "quarantine_dir",
    "logs_dir",
    "cache_dir",
    "config_file",
    "history_db",
    "runtime_dir",
    "bundle_dir",
    "running_frozen",
    "ensure_tree",
    "home",
    "default_scan_targets",
    "quick_scan_targets",
    "shorten",
]


def is_macos() -> bool:
    """True when running on macOS.

    ClamMac is a macOS application, but the core package stays importable
    everywhere so that it can be exercised by the test suite on CI runners.
    """
    return sys.platform == "darwin"


def running_frozen() -> bool:
    """True when executing from inside a PyInstaller-built .app bundle."""
    return bool(getattr(sys, "frozen", False))


def home() -> Path:
    return Path.home()


def bundle_dir() -> Path:
    """Directory holding the running application's resources.

    Inside a frozen bundle this is ``ClamMac.app/Contents/Frameworks``; from a
    source checkout it is the repository root.
    """
    if running_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent.parent


def _base() -> Path:
    """Root of every path ClamMac writes to.

    Honours ``CLAMMAC_HOME`` so tests -- and users who want the whole thing on
    an external volume -- can relocate the entire tree.
    """
    override = os.environ.get("CLAMMAC_HOME")
    if override:
        return Path(override).expanduser()
    if is_macos():
        return home() / "Library" / "Application Support" / APP_NAME
    # Sensible non-macOS fallback so the module is testable anywhere.
    xdg = os.environ.get("XDG_DATA_HOME")
    root = Path(xdg).expanduser() if xdg else home() / ".local" / "share"
    return root / APP_NAME.lower()


def support_dir() -> Path:
    return _base()


def engine_dir() -> Path:
    """Where a ClamMac-managed copy of the ClamAV engine is unpacked."""
    return _base() / "Engine"


def database_dir() -> Path:
    """Virus signature databases downloaded by freshclam."""
    return _base() / "Database"


def quarantine_dir() -> Path:
    """Encrypted-at-rest-by-permissions store for isolated files."""
    return _base() / "Quarantine"


def logs_dir() -> Path:
    if is_macos():
        return home() / "Library" / "Logs" / APP_NAME
    return _base() / "Logs"


def cache_dir() -> Path:
    return _base() / "Cache"


def runtime_dir() -> Path:
    """Short-lived state: sockets, pid files, clamd config."""
    return _base() / "Runtime"


def config_file() -> Path:
    return _base() / "settings.json"


def history_db() -> Path:
    return _base() / "history.sqlite3"


def ensure_tree() -> None:
    """Create every directory ClamMac needs, with private permissions.

    Quarantine is deliberately ``0700`` -- it holds files the scanner believes
    are malicious, and no other account on the machine should be able to read
    them, let alone execute them.
    """
    for path in (
        support_dir(),
        engine_dir(),
        database_dir(),
        logs_dir(),
        cache_dir(),
        runtime_dir(),
    ):
        path.mkdir(parents=True, exist_ok=True)
    quarantine = quarantine_dir()
    quarantine.mkdir(parents=True, exist_ok=True)
    try:
        quarantine.chmod(0o700)
        support_dir().chmod(0o700)
    except OSError:
        # A non-fatal permissions quirk should never stop the app from starting.
        pass


def quick_scan_targets() -> list[Path]:
    """Directories a quick scan covers.

    These are the places a Mac actually picks things up: the browser drop
    zone, the desktop, mail attachments, and the user-writable launch points
    that persistence tends to use.
    """
    h = home()
    candidates = [
        h / "Downloads",
        h / "Desktop",
        h / "Library" / "Caches" / "com.apple.Safari",
        h / "Library" / "Mail Downloads",
        h / "Library" / "Containers" / "com.apple.mail" / "Data" / "Library" / "Mail Downloads",
        h / "Library" / "LaunchAgents",
        h / "Applications",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path("/tmp"),
    ]
    return [p for p in candidates if p.exists()]


def default_scan_targets() -> list[Path]:
    """Directories a full scan covers by default: the whole home folder."""
    return [home()]


def shorten(path: os.PathLike[str] | str, *, max_len: int = 64) -> str:
    """Render a path for display: home-relative, middle-elided if long."""
    text = str(path)
    try:
        rel = Path(text).relative_to(home())
        text = "~/" + str(rel)
    except ValueError:
        pass
    if len(text) <= max_len:
        return text
    keep = max_len - 3
    head = keep // 2
    tail = keep - head
    return text[:head] + "..." + text[-tail:]
