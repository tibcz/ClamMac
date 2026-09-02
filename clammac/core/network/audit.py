"""Running an audit: gather a snapshot, apply the rules, hand back a report.

The work is a dozen short command invocations, which together take a couple of
seconds -- long enough that doing it on the interface thread would freeze the
window, so it runs in a thread and reports through the same plain-callback
pattern the scanner uses.

Nothing here is continuous. An audit is a photograph of one moment, taken
because the user asked for it. That is a deliberate limit: watching the network
in real time would mean a privileged helper and a permanent packet path
through this application, and neither is worth it to answer "what is this Mac
exposing".
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from .. import paths
from ..config import NetworkSettings
from ..log import get_logger
from . import probe
from .checks import derive_sharing, evaluate
from .model import AuditReport, Snapshot

log = get_logger(__name__)

__all__ = ["AuditProgress", "AuditState", "NetworkAudit", "capture", "run_audit"]


class AuditState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def is_active(self) -> bool:
        return self is AuditState.RUNNING


@dataclass(frozen=True)
class AuditProgress:
    step: int
    total: int
    message: str

    @property
    def fraction(self) -> float:
        return min(1.0, self.step / self.total) if self.total else 0.0


ProgressCallback = Callable[[AuditProgress], None]


# --------------------------------------------------------------------------
# gathering
# --------------------------------------------------------------------------


def capture(
    settings: NetworkSettings | None = None,
    *,
    on_progress: ProgressCallback | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Snapshot:
    """Ask the machine everything, in one pass."""
    options = settings or NetworkSettings()
    timeout = max(1.0, float(options.command_timeout))
    stop = cancelled or (lambda: False)

    snapshot = Snapshot(
        captured_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    snapshot.hostname, snapshot.platform = probe.host_description()

    def sockets(target: Snapshot) -> None:
        listeners, connections, notes = probe.collect_sockets(timeout=timeout)
        ignored = {int(port) for port in options.ignored_ports}
        target.listeners = [
            listener for listener in listeners if listener.port not in ignored
        ]
        target.connections = connections if options.include_connections else []
        target.limitations.extend(notes)

    def firewall(target: Snapshot) -> None:
        state, notes = probe.collect_firewall(timeout=timeout)
        target.firewall = state
        target.limitations.extend(notes)

    def interfaces(target: Snapshot) -> None:
        target.interfaces = probe.collect_interfaces(timeout=timeout)

    def routing(target: Snapshot) -> None:
        target.route = probe.collect_route(timeout=timeout)

    def resolvers(target: Snapshot) -> None:
        target.dns = probe.collect_dns(timeout=timeout)

    def wireless(target: Snapshot) -> None:
        if options.check_wireless:
            target.wireless = probe.collect_wireless(timeout=timeout)

    def proxies(target: Snapshot) -> None:
        target.proxy = probe.collect_proxy(timeout=timeout)

    def neighbours(target: Snapshot) -> None:
        target.neighbours = probe.collect_neighbours(timeout=timeout)

    def hosts(target: Snapshot) -> None:
        target.hosts_overrides = probe.collect_hosts_overrides()

    def processes(target: Snapshot) -> None:
        target.processes = probe.collect_processes(timeout=timeout)

    steps = [
        ("Listing open ports and connections", sockets),
        ("Reading firewall settings", firewall),
        ("Reading network interfaces", interfaces),
        ("Reading the routing table", routing),
        ("Reading DNS configuration", resolvers),
        ("Checking Wi-Fi security", wireless),
        ("Reading proxy settings", proxies),
        ("Reading the local address table", neighbours),
        ("Checking /etc/hosts", hosts),
        ("Listing running services", processes),
    ]

    total = len(steps) + 1
    for index, (message, action) in enumerate(steps, start=1):
        if stop():
            break
        if on_progress is not None:
            on_progress(AuditProgress(index, total, message))
        try:
            action(snapshot)
        except Exception as exc:  # a probe must never take the audit down
            log.exception("network probe '%s' failed", message)
            snapshot.limitations.append(f"{message} failed: {exc}")

    snapshot.sharing = derive_sharing(snapshot)
    snapshot.elevated = _is_root()

    if not paths.is_macos():
        snapshot.limitations.append(
            "This is not macOS, so the firewall, Wi-Fi and sharing checks were skipped."
        )
    if not snapshot.elevated:
        snapshot.limitations.append(
            "The audit ran without administrator rights. Sockets opened by other users "
            "and the packet filter's rules are not visible; everything else is complete."
        )

    if on_progress is not None:
        on_progress(AuditProgress(total, total, "Applying the rules"))
    return snapshot


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run_audit(
    settings: NetworkSettings | None = None,
    *,
    on_progress: ProgressCallback | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> AuditReport:
    """Capture and evaluate in one call. Used by the headless path and tests."""
    started = datetime.now(UTC)
    clock = time.monotonic()
    snapshot = capture(settings, on_progress=on_progress, cancelled=cancelled)
    findings = evaluate(snapshot)
    finished = datetime.now(UTC)
    return AuditReport(
        audit_id=uuid.uuid4().hex[:12],
        started_at=started.isoformat(timespec="seconds"),
        finished_at=finished.isoformat(timespec="seconds"),
        duration=time.monotonic() - clock,
        snapshot=snapshot,
        findings=findings,
    )


# --------------------------------------------------------------------------
# the job
# --------------------------------------------------------------------------


class NetworkAudit:
    """One audit, run on its own thread, reporting through callbacks."""

    def __init__(
        self,
        settings: NetworkSettings | None = None,
        *,
        on_progress: ProgressCallback | None = None,
        on_finished: Callable[[NetworkAudit], None] | None = None,
    ) -> None:
        self.settings = settings or NetworkSettings()
        self.on_progress = on_progress
        self.on_finished = on_finished

        self.state = AuditState.IDLE
        self.report: AuditReport | None = None
        self.failure = ""

        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._done = threading.Event()

    # -- control -------------------------------------------------------

    def start(self) -> NetworkAudit:
        if self.state.is_active:
            raise RuntimeError("This audit is already running.")
        self.state = AuditState.RUNNING
        self._cancel.clear()
        self._done.clear()
        self._thread = threading.Thread(target=self._run, name="clammac-netaudit", daemon=True)
        self._thread.start()
        return self

    def cancel(self) -> None:
        self._cancel.set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    # -- internals -----------------------------------------------------

    def _run(self) -> None:
        try:
            self.report = run_audit(
                self.settings,
                on_progress=self._progress,
                cancelled=self._cancel.is_set,
            )
            self.state = AuditState.CANCELLED if self._cancel.is_set() else AuditState.COMPLETED
        except Exception as exc:
            log.exception("the network audit failed")
            self.state = AuditState.FAILED
            self.failure = str(exc)
        finally:
            # The listener runs before the event is set, so a caller that
            # waits for the audit can rely on everything the listener does --
            # recording it to history, most of all -- having already happened.
            if self.on_finished is not None:
                try:
                    self.on_finished(self)
                except Exception:
                    log.exception("a network audit listener raised")
            self._done.set()

    def _progress(self, progress: AuditProgress) -> None:
        if self.on_progress is not None:
            try:
                self.on_progress(progress)
            except Exception:
                log.exception("a network audit progress listener raised")
