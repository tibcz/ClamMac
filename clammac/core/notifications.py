"""User-facing notifications.

The interface layer normally installs a Qt-backed notifier so alerts appear
under ClamMac's own name and icon. When ClamMac runs headless -- a scheduled
scan fired by launchd, with no window open -- there is no Qt application to
post through, so it falls back to ``osascript``.
"""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from ..version import APP_NAME
from . import paths
from .log import get_logger

log = get_logger(__name__)

__all__ = ["Notification", "Notifier", "Urgency", "notifier"]


class Urgency(str, Enum):
    INFO = "info"
    WARNING = "warning"
    THREAT = "threat"


@dataclass(frozen=True)
class Notification:
    title: str
    body: str
    urgency: Urgency = Urgency.INFO
    subtitle: str = ""


Backend = Callable[[Notification], bool]


class Notifier:
    """Posts notifications through whichever backend is available."""

    def __init__(self) -> None:
        self._backend: Backend | None = None
        self._enabled = True
        self._lock = threading.Lock()

    def set_backend(self, backend: Backend | None) -> None:
        """Install a richer backend, normally the Qt tray icon."""
        with self._lock:
            self._backend = backend

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def post(self, notification: Notification) -> bool:
        if not self._enabled:
            return False
        with self._lock:
            backend = self._backend
        if backend is not None:
            try:
                if backend(notification):
                    return True
            except Exception as exc:
                log.debug("notification backend failed: %s", exc)
        return _post_via_osascript(notification)

    # -- convenience ------------------------------------------------------

    def info(self, title: str, body: str, subtitle: str = "") -> bool:
        return self.post(Notification(title, body, Urgency.INFO, subtitle))

    def warn(self, title: str, body: str, subtitle: str = "") -> bool:
        return self.post(Notification(title, body, Urgency.WARNING, subtitle))

    def threat(self, title: str, body: str, subtitle: str = "") -> bool:
        return self.post(Notification(title, body, Urgency.THREAT, subtitle))

    def scan_finished(self, *, scanned: int, infected: int, label: str) -> bool:
        if infected:
            plural = "threat" if infected == 1 else "threats"
            return self.threat(
                f"{infected} {plural} found",
                f"{label} checked {scanned:,} files. Open ClamMac to review them.",
            )
        return self.info(
            "No threats found",
            f"{label} checked {scanned:,} files and everything was clean.",
        )


def _post_via_osascript(notification: Notification) -> bool:
    """Last-resort notification path for when there is no GUI running."""
    if not paths.is_macos():
        log.info("notification: %s -- %s", notification.title, notification.body)
        return False
    script = (
        f"display notification {_quote(notification.body)} "
        f"with title {_quote(APP_NAME)} "
        f"subtitle {_quote(notification.subtitle or notification.title)}"
    )
    try:
        subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("osascript notification failed: %s", exc)
        return False
    return True


def _quote(value: str) -> str:
    """Quote a string for AppleScript."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{escaped}"'


#: The notifier the rest of the application uses.
notifier = Notifier()
