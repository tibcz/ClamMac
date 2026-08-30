"""Real-time protection: scanning files as they arrive.

A directory snapshot is taken on start and re-taken on a short interval. Files
that are new, or whose size or modification time changed, are queued. A queued
file is not scanned immediately -- it is held until it has stopped changing for
``settle_seconds``, because a browser download or a copy in progress would
otherwise be scanned half-written, producing a useless verdict and a wasted
pass over the same file a moment later.

Verdicts come from ``clamd`` over its socket. Shelling out to ``clamscan`` per
file would mean reloading the signature database every time, which takes tens
of seconds and would make protection worse than useless.

The interface can also push change notifications in through
``notify_changed()``. Qt's file watcher sits on FSEvents, so when the GUI is
running that path reacts in milliseconds and the poll is just a safety net.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from . import paths
from .clamd import ClamdClient, ClamdError, ScanVerdict
from .config import Settings
from .log import get_logger

log = get_logger(__name__)

__all__ = ["RealtimeWatcher", "WatchEvent", "WatcherState"]

_POLL_INTERVAL = 3.0
_MAX_TRACKED = 200_000


class WatcherState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"

    @property
    def label(self) -> str:
        return {
            WatcherState.STOPPED: "Off",
            WatcherState.STARTING: "Starting",
            WatcherState.RUNNING: "On",
            WatcherState.DEGRADED: "Needs attention",
        }[self]


@dataclass(frozen=True)
class WatchEvent:
    """A file the watcher looked at."""

    path: Path
    verdict: ScanVerdict
    at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def infected(self) -> bool:
        return self.verdict.infected


DetectionFn = Callable[[WatchEvent], None]
StateFn = Callable[[WatcherState, str], None]


class RealtimeWatcher:
    """Watches folders and scans what lands in them."""

    def __init__(
        self,
        settings: Settings,
        client: ClamdClient,
        *,
        on_detection: DetectionFn | None = None,
        on_clean: DetectionFn | None = None,
        on_state: StateFn | None = None,
    ) -> None:
        self.settings = settings
        self.client = client
        self.on_detection = on_detection
        self.on_clean = on_clean
        self.on_state = on_state

        self.state = WatcherState.STOPPED
        self.detail = ""
        self.scanned_count = 0
        self.detection_count = 0
        self.last_event: WatchEvent | None = None

        self._paths: list[Path] = []
        self._snapshot: dict[str, tuple[float, int]] = {}
        self._pending: dict[str, float] = {}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.RLock()

    # -- lifecycle --------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.running:
            return True
        self._paths = self.settings.protection.watched_paths()
        if not self._paths:
            self._set_state(WatcherState.DEGRADED, "No folders are selected to watch.")
            return False
        if not self.client.ping():
            self._set_state(
                WatcherState.DEGRADED,
                "The ClamAV daemon is not running, so files cannot be checked as they arrive.",
            )
            return False

        self._set_state(WatcherState.STARTING, "Taking stock of the watched folders")
        self._stop.clear()
        self._snapshot = {}
        self._pending = {}
        self._thread = threading.Thread(target=self._run, name="realtime-watch", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)
        self._thread = None
        self._set_state(WatcherState.STOPPED, "")

    def reconfigure(self, settings: Settings) -> None:
        """Apply changed settings, restarting if the watched set moved."""
        self.settings = settings
        new_paths = settings.protection.watched_paths()
        if self.running and new_paths != self._paths:
            self.stop()
            self.start()

    @property
    def watched_paths(self) -> list[Path]:
        return list(self._paths)

    def notify_changed(self, path: Path) -> None:
        """Hint from the interface that something under ``path`` changed."""
        if not self.running:
            return
        with self._lock:
            if path.is_file():
                self._pending.setdefault(str(path), time.monotonic())
            elif path.is_dir():
                self._scan_directory_into_snapshot(path, queue_new=True)
        self._wake.set()

    # -- the loop ---------------------------------------------------------

    def _run(self) -> None:
        try:
            for root in self._paths:
                self._scan_directory_into_snapshot(root, queue_new=False, recursive=True)
            log.info(
                "real-time protection watching %d folder(s), %d files known",
                len(self._paths),
                len(self._snapshot),
            )
            self._set_state(WatcherState.RUNNING, "")

            while not self._stop.is_set():
                self._wake.wait(_POLL_INTERVAL)
                self._wake.clear()
                if self._stop.is_set():
                    break
                try:
                    self._poll()
                    self._drain_settled()
                except Exception as exc:
                    log.exception("real-time protection hit an error")
                    self._set_state(WatcherState.DEGRADED, str(exc))
        finally:
            if self.state is not WatcherState.DEGRADED:
                self._set_state(WatcherState.STOPPED, "")

    def _poll(self) -> None:
        for root in self._paths:
            if self._stop.is_set():
                return
            self._scan_directory_into_snapshot(root, queue_new=True, recursive=True)

    def _scan_directory_into_snapshot(
        self, root: Path, *, queue_new: bool, recursive: bool = True
    ) -> None:
        """Walk ``root``, updating the snapshot and queueing anything changed."""
        quarantine = str(paths.quarantine_dir())
        exclusions = self.settings.exclusions
        limit_bytes = max(self.settings.protection.max_file_size_mb, 0) * 1024 * 1024

        stack = [root]
        while stack:
            if self._stop.is_set():
                return
            directory = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        full = entry.path
                        if full.startswith(quarantine):
                            continue
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if recursive and entry.name not in _SKIP_DIRS:
                                    stack.append(Path(full))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue

                        if exclusions.excluded(Path(full)):
                            continue
                        if limit_bytes and stat.st_size > limit_bytes:
                            continue

                        fingerprint = (stat.st_mtime, stat.st_size)
                        with self._lock:
                            previous = self._snapshot.get(full)
                            if previous == fingerprint:
                                continue
                            if len(self._snapshot) < _MAX_TRACKED:
                                self._snapshot[full] = fingerprint
                            if queue_new:
                                self._pending[full] = time.monotonic()
            except (OSError, PermissionError):
                continue

    def _drain_settled(self) -> None:
        """Scan everything that has stopped changing."""
        settle = max(self.settings.protection.settle_seconds, 0.0)
        now = time.monotonic()
        with self._lock:
            ready = [p for p, queued_at in self._pending.items() if now - queued_at >= settle]
            for path in ready:
                self._pending.pop(path, None)

        for path_text in ready:
            if self._stop.is_set():
                return
            candidate = Path(path_text)
            if not candidate.is_file():
                continue
            self._check(candidate)

    def _check(self, path: Path) -> None:
        try:
            verdict = self.client.scan_path(path)
        except ClamdError as exc:
            self._set_state(
                WatcherState.DEGRADED,
                f"The ClamAV daemon stopped responding: {exc}",
            )
            return

        if not verdict:
            return
        result = verdict[0]
        event = WatchEvent(path=path, verdict=result)
        self.last_event = event
        self.scanned_count += 1

        if result.infected:
            self.detection_count += 1
            log.warning("real-time detection: %s (%s)", path, result.signature)
            if self.on_detection is not None:
                self.on_detection(event)
        elif self.on_clean is not None and self.settings.protection.notify_on_clean:
            self.on_clean(event)

    # -- state ------------------------------------------------------------

    def _set_state(self, state: WatcherState, detail: str) -> None:
        if self.state is state and self.detail == detail:
            return
        self.state = state
        self.detail = detail
        if detail:
            log.info("real-time protection %s: %s", state.value, detail)
        else:
            log.info("real-time protection %s", state.value)
        if self.on_state is not None:
            self.on_state(state, detail)


#: Directories that generate constant churn and hold nothing worth watching.
_SKIP_DIRS = frozenset(
    {
        ".Trash",
        ".Spotlight-V100",
        ".fseventsd",
        ".DocumentRevisions-V100",
        ".TemporaryItems",
        ".git",
        "node_modules",
    }
)
