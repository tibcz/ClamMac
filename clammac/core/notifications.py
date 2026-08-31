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

__all__ = ["THREAT_SOUND", "Notification", "Notifier", "Urgency", "notifier"]


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


#: The alert macOS plays for a detection. One of the sounds every install
#: has in /System/Library/Sounds, so there is nothing to ship and nothing to
#: go missing.
THREAT_SOUND = "Basso"


class Notifier:
    """Posts notifications through whichever backend is available."""

    def __init__(self) -> None:
        self._backend: Backend | None = None
        self._enabled = True
        self._sound = True
        self._lock = threading.Lock()

    def set_backend(self, backend: Backend | None) -> None:
        """Install a richer backend, normally the Qt tray icon."""
        with self._lock:
            self._backend = backend

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def set_sound_enabled(self, enabled: bool) -> None:
        """Whether a detection is announced audibly as well as visually."""
        self._sound = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def sound_enabled(self) -> bool:
        return self._sound

    def post(self, notification: Notification) -> bool:
        if not self._enabled:
            return False
        with self._lock:
            backend = self._backend
        posted = False
        if backend is not None:
            try:
                posted = bool(backend(notification))
            except Exception as exc:
                log.debug("notification backend failed: %s", exc)
        if not posted:
            # osascript can carry the sound itself, so let it, rather than
            # playing the same alert twice.
            return _post_via_osascript(notification, sound=self._wants_sound(notification))
        if self._wants_sound(notification):
            _play_alert()
        return True

    def _wants_sound(self, notification: Notification) -> bool:
        return self._sound and notification.urgency is Urgency.THREAT

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


def _post_via_osascript(notification: Notification, *, sound: bool = False) -> bool:
    """Last-resort notification path for when there is no GUI running."""
    if not paths.is_macos():
        log.info("notification: %s -- %s", notification.title, notification.body)
        return False
    script = (
        f"display notification {_quote(notification.body)} "
        f"with title {_quote(APP_NAME)} "
        f"subtitle {_quote(notification.subtitle or notification.title)}"
    )
    if sound:
        script += f" sound name {_quote(THREAT_SOUND)}"
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


def _play_alert(name: str = THREAT_SOUND) -> bool:
    """Play one of the system alert sounds, without waiting for it.

    Used when a richer backend has already shown the notification but cannot
    make a noise of its own -- Qt's tray balloon, for one.
    """
    if not paths.is_macos():
        return False
    sound = f"/System/Library/Sounds/{name}.aiff"
    try:
        subprocess.Popen(
            ["/usr/bin/afplay", sound],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("could not play the alert sound: %s", exc)
        return False
    return True


def _quote(value: str) -> str:
    """Quote a string for AppleScript."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return f'"{escaped}"'


#: The notifier the rest of the application uses.
notifier = Notifier()
