"""The application's brain: one object that owns all the moving parts.

The interface talks to this and nothing else. Keeping the coordination here --
rather than spread across window classes -- means the same logic drives a
scheduled scan fired by launchd with no GUI at all, and means all of it can be
tested without starting Qt.
"""

from __future__ import annotations

import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import config as config_module
from . import eicar, freshclam, launchagent, paths, scheduler
from . import engine as engine_module
from .clamd import ClamdDaemon, ClamdError
from .config import Settings, ThreatAction
from .history import History, NetworkAuditRecord, ScanRecord
from .log import get_logger
from .network import NetworkAudit, Severity
from .notifications import notifier
from .quarantine import Quarantine, QuarantineError
from .scanner import FileResult, FileStatus, ScanJob, ScanKind
from .watcher import RealtimeWatcher, WatcherState, WatchEvent

log = get_logger(__name__)

__all__ = ["AppService", "Health", "ProtectionStatus"]


class Health(str, Enum):
    """The single most important thing on the dashboard."""

    PROTECTED = "protected"
    ATTENTION = "attention"
    AT_RISK = "at_risk"
    SETTING_UP = "setting_up"

    @property
    def headline(self) -> str:
        return {
            Health.PROTECTED: "You're protected",
            Health.ATTENTION: "Needs attention",
            Health.AT_RISK: "Not protected",
            Health.SETTING_UP: "Setting up",
        }[self]


@dataclass
class ProtectionStatus:
    """A snapshot of everything the dashboard shows."""

    health: Health
    reasons: list[str]
    engine_version: str = ""
    engine_origin: str = ""
    database_version: int = 0
    database_age_days: float | None = None
    database_stale: bool = False
    realtime: WatcherState = WatcherState.STOPPED
    realtime_detail: str = ""
    quarantine_count: int = 0
    last_scan: ScanRecord | None = None
    threats_total: int = 0
    last_network_audit: NetworkAuditRecord | None = None

    @property
    def has_engine(self) -> bool:
        return bool(self.engine_version)


class AppService:
    """Owns the engine, the scanner, quarantine, history and protection."""

    def __init__(self, settings: Settings | None = None) -> None:
        paths.ensure_tree()
        self.settings: Settings = settings if settings is not None else config_module.load()
        self.history = History()
        self.quarantine = Quarantine()

        self.engine: engine_module.EngineInfo | None = None
        self.daemon: ClamdDaemon | None = None
        self.watcher: RealtimeWatcher | None = None

        self.active_scan: ScanJob | None = None
        self.active_update: freshclam.UpdateJob | None = None
        self.active_audit: NetworkAudit | None = None

        self._lock = threading.RLock()
        self._status_listeners: list[Callable[[ProtectionStatus], None]] = []
        self._threat_listeners: list[Callable[[FileResult, str], None]] = []

        self.refresh_engine()

    # -- engine -----------------------------------------------------------

    def refresh_engine(self) -> engine_module.EngineInfo | None:
        """Re-detect the engine and remember what was found."""
        self.engine = engine_module.discover(self.settings)
        if self.engine is not None:
            self.settings.engine_path = str(self.engine.tools.root.parent)
            self.settings.engine_version = self.engine.engine_version
            if self.daemon is None or self.daemon.tools != self.engine.tools:
                self.daemon = ClamdDaemon(self.engine.tools)
        return self.engine

    @property
    def ready(self) -> bool:
        """True when there is an engine and at least one signature database."""
        return self.engine is not None and engine_module.database_info().present

    def require_engine(self) -> engine_module.EngineInfo:
        if self.engine is None:
            raise RuntimeError("No ClamAV engine is installed yet.")
        return self.engine

    # -- status -----------------------------------------------------------

    def status(self) -> ProtectionStatus:
        """Assemble the dashboard's view of the world."""
        database = engine_module.database_info()
        stale = database.is_stale(self.settings.updates.stale_after_days)
        last = self.history.last_scan()
        stats = self.history.statistics()
        audit = self.history.last_network_audit()
        watcher_state = self.watcher.state if self.watcher else WatcherState.STOPPED
        watcher_detail = self.watcher.detail if self.watcher else ""

        reasons: list[str] = []
        health = Health.PROTECTED

        if self.engine is None:
            health = Health.SETTING_UP
            reasons.append("The ClamAV engine has not been installed yet.")
        elif not database.present:
            health = Health.AT_RISK
            reasons.append("No virus definitions have been downloaded yet.")
        else:
            if stale:
                health = Health.ATTENTION
                age = database.age_days()
                reasons.append(
                    f"Virus definitions are {age:.0f} days old."
                    if age is not None
                    else "Virus definitions may be out of date."
                )
            if self.settings.protection.enabled and watcher_state is WatcherState.DEGRADED:
                health = Health.ATTENTION
                reasons.append(watcher_detail or "Real-time protection is not running.")
            if not self.settings.protection.enabled:
                reasons.append("Real-time protection is off.")
                if health is Health.PROTECTED:
                    health = Health.ATTENTION
            if last is None:
                reasons.append("No scan has been run yet.")
                if health is Health.PROTECTED:
                    health = Health.ATTENTION

        # The network audit runs without an engine, so its findings are folded
        # in here rather than inside the branch above. It is only allowed to
        # speak once the user has actually run one: nagging every existing
        # installation into "needs attention" the moment it updates would be
        # rude, and would train people to ignore the word. It raises ATTENTION
        # and never AT_RISK, because "Not protected" is a statement about the
        # scanner and saying it over a network finding would be a lie.
        if audit is not None and audit.critical:
            if health is Health.PROTECTED:
                health = Health.ATTENTION
            reasons.insert(
                0,
                f"{audit.critical} service"
                f"{'s are' if audit.critical != 1 else ' is'} exposed to the network.",
            )
        elif audit is not None and audit.high:
            if health is Health.PROTECTED:
                health = Health.ATTENTION
            reasons.append(
                f"The network audit found {audit.high} thing"
                f"{'s' if audit.high != 1 else ''} worth fixing."
            )

        return ProtectionStatus(
            health=health,
            reasons=reasons,
            engine_version=self.engine.engine_version if self.engine else "",
            engine_origin=self.engine.tools.origin if self.engine else "",
            database_version=self.engine.database_version if self.engine else 0,
            database_age_days=database.age_days(),
            database_stale=stale,
            realtime=watcher_state,
            realtime_detail=watcher_detail,
            quarantine_count=self.quarantine.count(),
            last_scan=last,
            threats_total=stats["threats_total"],
            last_network_audit=audit,
        )

    def add_status_listener(self, callback: Callable[[ProtectionStatus], None]) -> None:
        self._status_listeners.append(callback)

    def add_threat_listener(self, callback: Callable[[FileResult, str], None]) -> None:
        self._threat_listeners.append(callback)

    def notify_status(self) -> None:
        status = self.status()
        for callback in list(self._status_listeners):
            try:
                callback(status)
            except Exception:
                log.exception("a status listener raised")

    # -- settings ---------------------------------------------------------

    def save_settings(self) -> None:
        config_module.save(self.settings)
        notifier.set_enabled(self.settings.interface.notifications)
        notifier.set_sound_enabled(self.settings.interface.sound_on_threat)
        if self.watcher is not None:
            self.watcher.reconfigure(self.settings)
        if paths.is_macos():
            launchagent.sync_all(self.settings)
        self.notify_status()

    # -- scanning ---------------------------------------------------------

    def resolve_targets(self, kind: ScanKind, targets: list[Path] | None = None) -> list[Path]:
        if kind is ScanKind.QUICK:
            return paths.quick_scan_targets()
        if kind is ScanKind.FULL:
            return paths.default_scan_targets()
        return list(targets or [])

    def start_scan(
        self,
        kind: ScanKind = ScanKind.CUSTOM,
        targets: list[Path] | None = None,
        *,
        on_progress=None,
        on_detection=None,
        on_finished=None,
    ) -> ScanJob:
        """Kick off a scan and arrange for its results to be acted on."""
        with self._lock:
            if self.active_scan is not None and self.active_scan.state.is_active:
                raise RuntimeError("A scan is already running.")
            info = self.require_engine()
            chosen = self.resolve_targets(kind, targets)
            if not chosen:
                raise ValueError("There is nothing to scan.")

            job = ScanJob(
                tools=info.tools,
                targets=chosen,
                settings=self.settings,
                kind=kind,
                on_progress=on_progress,
                on_detection=on_detection,
            )

            def finished(finished_job: ScanJob) -> None:
                try:
                    self._handle_scan_finished(finished_job)
                finally:
                    if on_finished is not None:
                        on_finished(finished_job)
                    with self._lock:
                        if self.active_scan is finished_job:
                            self.active_scan = None
                    self.notify_status()

            job.on_finished = finished
            self.active_scan = job
            job.start()
            return job

    def _handle_scan_finished(self, job: ScanJob) -> None:
        """Apply the configured action to each detection, then record it all."""
        action = self.settings.scan.on_threat
        recorded: list[tuple[str, str, str, str]] = []

        for detection in job.detections:
            applied, quarantine_id = self._act_on(detection, action, job.job_id)
            recorded.append((detection.path, detection.signature, applied, quarantine_id))
            for listener in list(self._threat_listeners):
                try:
                    listener(detection, applied)
                except Exception:
                    log.exception("a threat listener raised")

        self.history.record_scan(
            ScanRecord(
                id=job.job_id,
                kind=job.kind.value,
                targets=[str(t) for t in job.targets],
                started_at=job.started_at.isoformat(timespec="seconds") if job.started_at else "",
                finished_at=job.finished_at.isoformat(timespec="seconds") if job.finished_at else "",
                state=job.state.value,
                scanned=job.scanned,
                infected=len(job.detections),
                errors=len(job.errors),
                duration=job.elapsed,
                engine_version=self.engine.engine_version if self.engine else "",
                database_version=self.engine.database_version if self.engine else 0,
                data_scanned_mb=job.summary.data_scanned_mb,
            )
        )
        if recorded:
            self.history.record_detections(job.job_id, recorded)

        if job.kind is not ScanKind.SELFTEST and self.settings.interface.notifications:
            notifier.scan_finished(
                scanned=job.scanned, infected=len(job.detections), label=job.kind.label
            )

    def _act_on(self, detection: FileResult, action: ThreatAction, scan_id: str) -> tuple[str, str]:
        """Carry out the user's chosen response to one detection."""
        # A self-test detection is a success, not an incident: never quarantine
        # or delete the file the user asked us to plant.
        if eicar.is_test_signature(detection.signature):
            return "report", ""

        target = Path(detection.path)
        if action is ThreatAction.QUARANTINE:
            try:
                entry = self.quarantine.add(target, detection.signature, scan_id=scan_id)
                return "quarantine", entry.entry_id
            except QuarantineError as exc:
                log.error("could not quarantine %s: %s", target, exc)
                self.history.record_event(
                    "quarantine", f"Could not quarantine {target.name}: {exc}", "error"
                )
                return "failed", ""

        if action is ThreatAction.DELETE:
            try:
                target.unlink()
                return "deleted", ""
            except OSError as exc:
                log.error("could not delete %s: %s", target, exc)
                self.history.record_event(
                    "delete", f"Could not delete {target.name}: {exc}", "error"
                )
                return "failed", ""

        return "report", ""

    def stop_scan(self) -> None:
        with self._lock:
            job = self.active_scan
        if job is not None:
            job.cancel()

    # -- definition updates ----------------------------------------------

    def update_definitions(
        self, *, on_progress=None, on_finished=None, blocking: bool = False
    ) -> freshclam.UpdateJob:
        info = self.require_engine()
        job = freshclam.UpdateJob(tools=info.tools, on_progress=on_progress)

        def finished(update: freshclam.UpdateJob) -> None:
            if update.outcome is freshclam.UpdateOutcome.UPDATED:
                scheduler.mark_update_run()
                self.history.record_event("update", update.summary_line())
                # clamd holds the old database in memory until told otherwise.
                if self.daemon is not None and self.daemon.is_running():
                    self.daemon.client.reload()
                if self.settings.updates.notify_on_update:
                    notifier.info("Virus definitions updated", update.summary_line())
            elif update.outcome is freshclam.UpdateOutcome.UP_TO_DATE:
                scheduler.mark_update_run()
            else:
                self.history.record_event("update", update.summary_line(), "error")
            self.refresh_engine()
            if on_finished is not None:
                on_finished(update)
            self.notify_status()

        job.on_finished = finished
        self.active_update = job
        if blocking:
            job.run_blocking()
        else:
            job.start()
        return job

    # -- network audit ----------------------------------------------------

    def start_network_audit(self, *, on_progress=None, on_finished=None) -> NetworkAudit:
        """Examine what this Mac exposes to the network.

        Needs no engine and no definitions: it reads the machine's own
        configuration, so it works before ClamAV has ever been installed.
        """
        with self._lock:
            if self.active_audit is not None and self.active_audit.state.is_active:
                raise RuntimeError("A network audit is already running.")

            audit = NetworkAudit(self.settings.network, on_progress=on_progress)

            def finished(job: NetworkAudit) -> None:
                try:
                    self._handle_audit_finished(job)
                finally:
                    if on_finished is not None:
                        on_finished(job)
                    with self._lock:
                        if self.active_audit is job:
                            self.active_audit = None
                    self.notify_status()

            audit.on_finished = finished
            self.active_audit = audit
            audit.start()
            return audit

    def _handle_audit_finished(self, job: NetworkAudit) -> None:
        report = job.report
        if report is None:
            return
        try:
            self.history.record_network_audit(report)
        except Exception:
            log.exception("could not record the network audit")

        counts = report.counts
        serious = counts[Severity.CRITICAL] + counts[Severity.HIGH]
        self.history.record_event(
            "network",
            f"Network audit scored {report.score}/100 with {serious} serious "
            f"finding{'s' if serious != 1 else ''}.",
            "error" if counts[Severity.CRITICAL] else "info",
        )
        if counts[Severity.CRITICAL] and self.settings.interface.notifications:
            worst = next(f for f in report.ordered if f.severity is Severity.CRITICAL)
            notifier.threat("Network exposure found", worst.title)

    def stop_network_audit(self) -> None:
        with self._lock:
            audit = self.active_audit
        if audit is not None:
            audit.cancel()

    # -- real-time protection --------------------------------------------

    def start_protection(self) -> bool:
        """Bring up clamd and the folder watcher."""
        info = self.require_engine()
        if self.daemon is None:
            self.daemon = ClamdDaemon(info.tools)
        if not self.daemon.available:
            log.warning("this engine has no clamd, so real-time protection is unavailable")
            return False

        try:
            self.daemon.start(settings=self.settings)
        except ClamdError as exc:
            log.error("could not start clamd: %s", exc)
            self.history.record_event("protection", f"Could not start clamd: {exc}", "error")
            return False

        if self.watcher is None:
            self.watcher = RealtimeWatcher(
                self.settings,
                self.daemon.client,
                on_detection=self._on_realtime_detection,
                on_state=lambda *_: self.notify_status(),
            )
        else:
            self.watcher.reconfigure(self.settings)

        started = self.watcher.start()
        self.notify_status()
        return started

    def stop_protection(self) -> None:
        if self.watcher is not None:
            self.watcher.stop()
        if self.daemon is not None:
            self.daemon.stop()
        self.notify_status()

    def _on_realtime_detection(self, event: WatchEvent) -> None:
        detection = FileResult(
            path=str(event.path),
            status=FileStatus.INFECTED,
            signature=event.verdict.signature,
        )
        applied, quarantine_id = self._act_on(
            detection, self.settings.scan.on_threat, "realtime"
        )
        self.history.record_detections(
            "realtime", [(detection.path, detection.signature, applied, quarantine_id)]
        )
        notifier.threat(
            "Threat blocked",
            f"{event.path.name} was detected as {event.verdict.signature}.",
        )
        for listener in list(self._threat_listeners):
            try:
                listener(detection, applied)
            except Exception:
                log.exception("a threat listener raised")
        self.notify_status()

    # -- self test --------------------------------------------------------

    def run_self_test(self, *, on_finished=None) -> ScanJob:
        """Plant an EICAR test file and confirm the scanner finds it."""
        directory = Path(eicar.write_test_file()).parent

        def finished(job: ScanJob) -> None:
            shutil.rmtree(directory, ignore_errors=True)
            if on_finished is not None:
                on_finished(job)

        return self.start_scan(
            ScanKind.SELFTEST, [directory], on_finished=finished
        )

    # -- shutdown ---------------------------------------------------------

    def shutdown(self) -> None:
        """Stop everything cleanly."""
        try:
            self.stop_scan()
        except Exception:
            pass
        try:
            self.stop_network_audit()
        except Exception:
            pass
        try:
            self.stop_protection()
        except Exception:
            pass
        try:
            config_module.save(self.settings)
        except Exception:
            pass
