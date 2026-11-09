"""Running scans and making sense of what the scanner says.

``clamscan`` reports one line per file as it goes. ClamMac reads that stream
live rather than waiting for the process to finish, which is what makes the
progress display honest: the file named on screen is the file the engine is
actually working on.

Scans run in a session of their own so the whole process group can be paused
with SIGSTOP and resumed with SIGCONT. A paused scan holds its place instead of
starting over, which matters when a full scan is an hour long.

A job can instead run in parallel: a private ``clamd`` scans on every
performance core while ClamMac walks the targets and hands it one file at a
time (see :mod:`clammac.core.parallel`). Pausing then stops handing out files,
and cancelling stops the daemon. If clamd is missing or will not start, the
job falls back to ``clamscan`` rather than failing.

Nothing in this module has any Qt dependency; the interface layer subscribes
through plain callbacks.
"""

from __future__ import annotations

import os
import queue
import re
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from . import engine as engine_module
from . import parallel as parallel_module
from . import paths
from .clamd import ClamdClient, ClamdDaemon, ClamdError
from .config import Settings, ThreatAction
from .log import get_logger

log = get_logger(__name__)

__all__ = [
    "FileResult",
    "FileStatus",
    "JobState",
    "ScanJob",
    "ScanKind",
    "ScanProgress",
    "ScanSummary",
    "count_files",
    "parse_result_line",
    "parse_summary",
]


class FileStatus(str, Enum):
    CLEAN = "clean"
    INFECTED = "infected"
    EMPTY = "empty"
    ERROR = "error"
    EXCLUDED = "excluded"


class JobState(str, Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    RUNNING = "running"
    PAUSED = "paused"
    FINISHING = "finishing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in {JobState.COMPLETED, JobState.CANCELLED, JobState.FAILED}

    @property
    def is_active(self) -> bool:
        return self in {JobState.PREPARING, JobState.RUNNING, JobState.PAUSED, JobState.FINISHING}


class ScanKind(str, Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    SCHEDULED = "scheduled"
    REALTIME = "realtime"
    SELFTEST = "selftest"

    @property
    def label(self) -> str:
        return {
            ScanKind.QUICK: "Quick scan",
            ScanKind.FULL: "Full scan",
            ScanKind.CUSTOM: "Custom scan",
            ScanKind.SCHEDULED: "Scheduled scan",
            ScanKind.REALTIME: "Real-time check",
            ScanKind.SELFTEST: "Self-test",
        }[self]


@dataclass(frozen=True)
class FileResult:
    """One line of scanner output, interpreted."""

    path: str
    status: FileStatus
    signature: str = ""
    detail: str = ""

    @property
    def is_threat(self) -> bool:
        return self.status is FileStatus.INFECTED


@dataclass
class ScanSummary:
    """The totals clamscan prints when it finishes."""

    known_viruses: int = 0
    engine_version: str = ""
    scanned_directories: int = 0
    scanned_files: int = 0
    infected_files: int = 0
    data_scanned_mb: float = 0.0
    data_read_mb: float = 0.0
    seconds: float = 0.0


@dataclass
class ScanProgress:
    """A live snapshot handed to the interface on every update."""

    state: JobState
    current_path: str = ""
    scanned: int = 0
    infected: int = 0
    errors: int = 0
    total: int = 0
    elapsed: float = 0.0

    @property
    def fraction(self) -> float:
        """Completion as 0..1, or -1 when the total is not known."""
        if self.total <= 0:
            return -1.0
        return min(1.0, self.scanned / self.total)

    @property
    def rate(self) -> float:
        return self.scanned / self.elapsed if self.elapsed > 0.05 else 0.0

    @property
    def eta_seconds(self) -> float:
        rate = self.rate
        if rate <= 0 or self.total <= 0 or self.scanned >= self.total:
            return -1.0
        return (self.total - self.scanned) / rate


# --------------------------------------------------------------------------
# output parsing
# --------------------------------------------------------------------------

_FOUND = re.compile(r"^(?P<path>.*): (?P<sig>.+) FOUND$")
_OK = re.compile(r"^(?P<path>.*): OK$")
_EMPTY = re.compile(r"^(?P<path>.*): Empty file$")
_EXCLUDED = re.compile(r"^(?P<path>.*): Excluded$")
_ERROR = re.compile(r"^(?P<path>.*): (?P<detail>.*ERROR|.*Access denied.*|Can't .*)$")

#: Directories that hold nothing worth counting and churn constantly.
_NOISY_DIRS = frozenset({".git", ".Trash", ".Spotlight-V100", ".fseventsd"})

_SUMMARY_HEADER = "----------- SCAN SUMMARY -----------"
_SUMMARY_FIELDS = {
    "Known viruses": ("known_viruses", int),
    "Engine version": ("engine_version", str),
    "Scanned directories": ("scanned_directories", int),
    "Scanned files": ("scanned_files", int),
    "Infected files": ("infected_files", int),
}


def parse_result_line(line: str) -> FileResult | None:
    """Interpret one line of ``clamscan`` output.

    Paths may themselves contain ``": "``, so each candidate shape is matched
    greedily from the left and anchored on the *status* at the end of the line
    rather than by splitting on the first colon.
    """
    text = line.rstrip("\n\r")
    if not text or text.startswith(("-----", "Known viruses:", "Engine version:")):
        return None

    match = _FOUND.match(text)
    if match:
        signature = match.group("sig").strip()
        # clamd's output adds a trailing marker the plain scanner does not.
        if signature.endswith("(Multiple)"):
            signature = signature[: -len("(Multiple)")].strip()
        return FileResult(match.group("path"), FileStatus.INFECTED, signature=signature)

    match = _OK.match(text)
    if match:
        return FileResult(match.group("path"), FileStatus.CLEAN)

    match = _EMPTY.match(text)
    if match:
        return FileResult(match.group("path"), FileStatus.EMPTY)

    match = _EXCLUDED.match(text)
    if match:
        return FileResult(match.group("path"), FileStatus.EXCLUDED)

    match = _ERROR.match(text)
    if match:
        return FileResult(
            match.group("path"), FileStatus.ERROR, detail=match.group("detail").strip()
        )

    if text.startswith(("LibClamAV Error:", "ERROR:", "WARNING:")):
        return FileResult("", FileStatus.ERROR, detail=text)

    return None


def parse_summary(lines: list[str]) -> ScanSummary:
    """Pull the totals out of the summary block."""
    summary = ScanSummary()
    for line in lines:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key in _SUMMARY_FIELDS:
            name, caster = _SUMMARY_FIELDS[key]
            try:
                setattr(summary, name, caster(value))
            except (ValueError, TypeError):
                pass
        elif key == "Data scanned":
            summary.data_scanned_mb = _size_in_mb(value)
        elif key == "Data read":
            summary.data_read_mb = _size_in_mb(value)
        elif key == "Time":
            summary.seconds = _leading_float(value)
    return summary


def _leading_float(value: str) -> float:
    match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)", value)
    return float(match.group(1)) if match else 0.0


#: How many megabytes one of clamscan's units is worth. It picks the unit to
#: suit the number -- "170 B" for a handful of files, "6.64 MiB", "3.2 GiB" --
#: so reading the figure without its unit is wrong by a factor of a thousand
#: in either direction. Binary units are converted honestly rather than
#: treated as their decimal near-namesakes.
_SIZE_UNITS_IN_MB = {
    "b": 1 / 1e6,
    "kb": 1e-3,
    "kib": 1024 / 1e6,
    "mb": 1.0,
    "mib": 1024 * 1024 / 1e6,
    "gb": 1e3,
    "gib": 1024 * 1024 * 1024 / 1e6,
    "tb": 1e6,
    "tib": 1024**4 / 1e6,
}

_SIZE = re.compile(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]i?B|B)\b", re.IGNORECASE)


def _size_in_mb(value: str) -> float:
    """Read one of clamscan's size figures and return it in megabytes.

    A bare number with no unit is taken as megabytes, which is what older
    ClamAV releases printed and what the field has always been named for.
    """
    match = _SIZE.match(value)
    if match is None:
        return _leading_float(value)
    amount = float(match.group(1))
    return amount * _SIZE_UNITS_IN_MB.get(match.group(2).lower(), 1.0)


# --------------------------------------------------------------------------
# counting, for a real progress bar
# --------------------------------------------------------------------------


def count_files(
    targets: list[Path],
    settings: Settings,
    *,
    time_budget: float = 6.0,
    cap: int = 400_000,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    """Estimate how many files a scan will visit.

    ``clamscan`` never says how much work is left, so ClamMac counts first.
    The walk is bounded by both a time budget and a hard cap: on a large disk
    an exact count would take longer than some scans do, and a progress bar is
    not worth making the user wait for. Returning 0 means "unknown", and the
    interface shows indeterminate progress instead of a wrong percentage.
    """
    deadline = time.monotonic() + time_budget
    total = 0
    exclusions = settings.exclusions
    quarantine = str(paths.quarantine_dir())

    for target in targets:
        if target.is_file():
            total += 1
            continue
        stack = [target]
        while stack:
            if total >= cap or time.monotonic() > deadline:
                return 0
            if should_stop is not None and should_stop():
                return 0
            directory = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        # Dotfiles are still counted; only the noisy caches
                        # that never hold anything interesting are skipped.
                        if entry.name in _NOISY_DIRS:
                            continue
                        full = Path(entry.path)
                        if entry.path.startswith(quarantine) or exclusions.excluded(full):
                            continue
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(full)
                            elif entry.is_file(follow_symlinks=False):
                                total += 1
                        except OSError:
                            continue
            except (OSError, PermissionError):
                continue
    return total


# --------------------------------------------------------------------------
# the job
# --------------------------------------------------------------------------

ProgressFn = Callable[[ScanProgress], None]
DetectionFn = Callable[[FileResult], None]
FinishedFn = Callable[["ScanJob"], None]


@dataclass
class ScanJob:
    """A single scan, run on its own thread."""

    tools: engine_module.EngineTools
    targets: list[Path]
    settings: Settings
    kind: ScanKind = ScanKind.CUSTOM
    #: Scan on every performance core through a private clamd.
    parallel: bool = False

    on_progress: ProgressFn | None = None
    on_detection: DetectionFn | None = None
    on_finished: FinishedFn | None = None
    on_log: Callable[[str], None] | None = None

    job_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: JobState = JobState.IDLE
    started_at: datetime | None = None
    finished_at: datetime | None = None
    detections: list[FileResult] = field(default_factory=list)
    errors: list[FileResult] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    failure: str = ""
    total_estimate: int = 0

    _process: subprocess.Popen[str] | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _scanned: int = 0
    _current: str = ""
    _monotonic_start: float = 0.0
    _paused_at: float = 0.0
    _paused_total: float = 0.0
    _daemon: ClamdDaemon | None = field(default=None, repr=False)
    _running: threading.Event = field(default_factory=threading.Event, repr=False)
    _abort: threading.Event = field(default_factory=threading.Event, repr=False)
    _callback_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _last_emit: float = 0.0
    workers: int = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Begin scanning on a background thread."""
        if self.state.is_active:
            raise RuntimeError("this scan is already running")
        self._stop.clear()
        self._abort.clear()
        self._running.set()
        self.state = JobState.PREPARING
        self.started_at = datetime.now(UTC)
        self._monotonic_start = time.monotonic()
        self._thread = threading.Thread(target=self._run, name=f"scan-{self.job_id}", daemon=True)
        self._thread.start()

    def pause(self) -> bool:
        """Suspend the scan where it stands.

        A clamscan scan is frozen with SIGSTOP. A multi-core scan stops
        handing out files instead: the few already with clamd finish, and the
        daemon then sits idle until the scan is resumed.
        """
        with self._lock:
            if self.state is not JobState.RUNNING:
                return False
            if self._daemon is not None:
                self._running.clear()
            elif self._process is None:
                return False
            else:
                try:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGSTOP)
                except (OSError, ProcessLookupError) as exc:
                    log.warning("could not pause scan %s: %s", self.job_id, exc)
                    return False
            self.state = JobState.PAUSED
            self._paused_at = time.monotonic()
        self._emit(force=True)
        return True

    def resume(self) -> bool:
        with self._lock:
            if self.state is not JobState.PAUSED:
                return False
            if self._daemon is not None:
                self._running.set()
            elif self._process is None:
                return False
            else:
                try:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGCONT)
                except (OSError, ProcessLookupError) as exc:
                    log.warning("could not resume scan %s: %s", self.job_id, exc)
                    return False
            self.state = JobState.RUNNING
            if self._paused_at:
                self._paused_total += time.monotonic() - self._paused_at
                self._paused_at = 0.0
        self._emit(force=True)
        return True

    def cancel(self) -> None:
        """Stop the scan. Safe to call from any thread, or twice."""
        self._stop.set()
        # Wake a paused parallel scan so its threads can see the stop.
        self._running.set()
        with self._lock:
            process = self._process
            daemon = self._daemon
            was_paused = self.state is JobState.PAUSED
        if daemon is not None:
            daemon.kill()
        if process is None or process.poll() is not None:
            return
        try:
            group = os.getpgid(process.pid)
            if was_paused:
                # A stopped process cannot act on SIGTERM until it runs again.
                os.killpg(group, signal.SIGCONT)
            os.killpg(group, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass

    def wait(self, timeout: float | None = None) -> bool:
        """Block until the scan ends. Returns False if it timed out."""
        if self._thread is None:
            return True
        self._thread.join(timeout)
        return not self._thread.is_alive()

    # -- derived state ----------------------------------------------------

    @property
    def elapsed(self) -> float:
        if not self._monotonic_start:
            return 0.0
        end = time.monotonic()
        if self.state.is_terminal and self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        active = end - self._monotonic_start - self._paused_total
        if self.state is JobState.PAUSED and self._paused_at:
            active -= end - self._paused_at
        return max(active, 0.0)

    def progress(self) -> ScanProgress:
        with self._lock:
            return ScanProgress(
                state=self.state,
                current_path=self._current,
                scanned=self._scanned,
                infected=len(self.detections),
                errors=len(self.errors),
                total=self.total_estimate,
                elapsed=self.elapsed,
            )

    # -- the worker -------------------------------------------------------

    def _run(self) -> None:
        try:
            self._prepare()
            if self._stop.is_set():
                self._finish(JobState.CANCELLED)
                return
            self._execute()
        except Exception as exc:
            log.exception("scan %s failed", self.job_id)
            self.failure = str(exc)
            self._finish(JobState.FAILED)

    def _prepare(self) -> None:
        self._emit(force=True)
        self.total_estimate = count_files(
            self.targets, self.settings, should_stop=self._stop.is_set
        )
        log.info(
            "scan %s (%s) over %d target(s), estimated %s files",
            self.job_id,
            self.kind.value,
            len(self.targets),
            self.total_estimate or "unknown",
        )

    def _execute(self) -> None:
        if self.parallel and self.tools.clamd is not None:
            try:
                self._execute_parallel()
                return
            except ClamdError as exc:
                if self._stop.is_set():
                    self._finish(JobState.CANCELLED)
                    return
                log.warning(
                    "scan %s: multi-core scan unavailable (%s); using clamscan", self.job_id, exc
                )
                self._log(f"Multi-core scan unavailable ({exc}); scanning on one core.")
        self._execute_single()

    def _execute_single(self) -> None:
        command = engine_module.nice_prefix(self.settings) + engine_module.build_scan_command(
            self.tools, self.targets, self.settings
        )
        self._log(" ".join(command))

        with self._lock:
            self.state = JobState.RUNNING
        self._emit(force=True)

        summary_lines: list[str] = []
        in_summary = False

        # start_new_session gives the child its own process group, so pause,
        # resume and cancel reach clamscan and everything it spawns.
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
            env=engine_module.scan_environment(self.settings),
        )
        with self._lock:
            self._process = process

        assert process.stdout is not None
        for line in process.stdout:
            if self._stop.is_set():
                break
            stripped = line.rstrip("\n")
            if stripped.startswith(_SUMMARY_HEADER[:11]):
                in_summary = True
            if in_summary:
                summary_lines.append(stripped)
                continue

            result = parse_result_line(stripped)
            if result is None:
                if stripped.strip():
                    self._log(stripped)
                continue

            self._record(result)

        returncode = process.wait()
        self.summary = parse_summary(summary_lines)
        if self.summary.scanned_files:
            with self._lock:
                self._scanned = max(self._scanned, self.summary.scanned_files)

        if self._stop.is_set():
            self._finish(JobState.CANCELLED)
        elif returncode in (0, 1):
            # 0: nothing found. 1: something found. Both are successful scans.
            self._finish(JobState.COMPLETED)
        else:
            self.failure = self.failure or f"clamscan exited with status {returncode}"
            self._finish(JobState.FAILED)

    def _execute_parallel(self) -> None:
        """Scan through a private clamd on every performance core.

        Raises :class:`ClamdError` only if the daemon cannot be brought up, so
        the caller can fall back to clamscan. Once scanning has begun, a
        daemon that dies fails the scan instead: falling back halfway would
        rescan everything already done.
        """
        workers = parallel_module.worker_count()
        daemon = ClamdDaemon(
            self.tools,
            name="clamd-scan",
            max_threads=workers,
            low_priority=self.settings.scan.low_priority,
        )
        # One left behind by a crash would hold stale settings; replace it.
        if daemon.is_running():
            daemon.stop()
        with self._lock:
            self._daemon = daemon
            self.workers = workers
        try:
            self._log(f"Starting the multi-core scanner on {workers} cores.")
            try:
                daemon.start(settings=self.settings)
            except ClamdError:
                with self._lock:
                    self._daemon = None
                raise
            if self._stop.is_set():
                self._finish(JobState.CANCELLED)
                return
            engine_version = ""
            try:
                engine_version = daemon.client.version().split("/")[0].replace("ClamAV ", "")
            except ClamdError:
                pass

            with self._lock:
                self.state = JobState.RUNNING
            self._emit(force=True)
            self._feed(daemon, workers)
        finally:
            with self._lock:
                self._daemon = None
            daemon.kill()

        self.summary = ScanSummary(
            engine_version=engine_version,
            scanned_files=self._scanned,
            infected_files=len(self.detections),
            seconds=self.elapsed,
        )
        if self._stop.is_set() and not self._abort.is_set():
            self._finish(JobState.CANCELLED)
        elif self._abort.is_set():
            self._finish(JobState.FAILED)
        else:
            self._finish(JobState.COMPLETED)

    def _feed(self, daemon: ClamdDaemon, workers: int) -> None:
        """Walk the targets and keep every scanner thread busy."""
        # Twice as many connections as clamd threads, so a thread finishing a
        # file always has the next one already waiting for it.
        connections = workers * 2
        pending: queue.Queue[str | None] = queue.Queue(maxsize=connections * 32)
        halted = lambda: self._stop.is_set() or self._abort.is_set()  # noqa: E731

        def scan_worker() -> None:
            client = ClamdClient(daemon.socket_path, timeout=600.0)
            while True:
                path = pending.get()
                if path is None:
                    return
                if halted():
                    continue
                self._running.wait()
                if halted():
                    continue
                try:
                    scan_one(client, path)
                except Exception:
                    # A thread that died here would leave the walk blocked on
                    # a full queue forever; count the file as an error instead.
                    log.exception("scan %s: could not handle %s", self.job_id, path)
                    self._record(FileResult(path, FileStatus.ERROR, detail="internal error"))

        def scan_one(client: ClamdClient, path: str) -> None:
            try:
                verdict = client.scan_file(path)
            except ClamdError as exc:
                if halted():
                    return
                if not daemon.is_running():
                    self.failure = self.failure or "The scanner stopped unexpectedly."
                    log.error("scan %s: clamd went away: %s", self.job_id, exc)
                    self._abort.set()
                    return
                self._record(FileResult(path, FileStatus.ERROR, detail=str(exc)))
                return
            if verdict.infected:
                result = FileResult(path, FileStatus.INFECTED, signature=verdict.signature)
            elif verdict.error:
                result = FileResult(path, FileStatus.ERROR, detail=verdict.error)
            else:
                result = FileResult(path, FileStatus.CLEAN)
            self._record(result)

        threads = [
            threading.Thread(target=scan_worker, name=f"scan-{self.job_id}-{n}", daemon=True)
            for n in range(connections)
        ]
        for thread in threads:
            thread.start()

        def walk_error(path: str, detail: str) -> None:
            self._record(FileResult(path, FileStatus.ERROR, detail=detail))

        try:
            for path in parallel_module.iter_scan_files(
                self.targets, self.settings, should_stop=halted, on_error=walk_error
            ):
                while not halted():
                    self._running.wait(timeout=0.5)
                    if not self._running.is_set():
                        continue
                    try:
                        pending.put(path, timeout=0.5)
                        break
                    except queue.Full:
                        continue
                if halted():
                    break
        finally:
            for _ in threads:
                pending.put(None)
            for thread in threads:
                thread.join()

    def _record(self, result: FileResult) -> None:
        """Count one verdict, from whichever thread produced it."""
        with self._lock:
            if result.path:
                self._scanned += 1
                self._current = result.path
            if result.status is FileStatus.INFECTED:
                self.detections.append(result)
            elif result.status is FileStatus.ERROR:
                self.errors.append(result)

        if result.status is FileStatus.INFECTED and self.on_detection is not None:
            with self._callback_lock:
                self.on_detection(result)
        self._emit()

    def _finish(self, state: JobState) -> None:
        with self._lock:
            self.state = state
            self.finished_at = datetime.now(UTC)
            self._current = ""
        log.info(
            "scan %s %s: %d scanned, %d infected, %d errors in %.1fs",
            self.job_id,
            state.value,
            self._scanned,
            len(self.detections),
            len(self.errors),
            self.elapsed,
        )
        self._emit(force=True)
        if self.on_finished is not None:
            self.on_finished(self)

    def _emit(self, *, force: bool = False) -> None:
        """Tell the interface where the scan stands.

        Emitting on every file would flood the interface; 20 Hz is smoother
        than the eye needs and costs nothing. State changes always go out.
        """
        if self.on_progress is None:
            return
        with self._callback_lock:
            now = time.monotonic()
            if not force and now - self._last_emit <= 0.05:
                return
            self._last_emit = now
            self.on_progress(self.progress())

    def _log(self, message: str) -> None:
        if self.on_log is not None:
            self.on_log(message)
        log.debug("[%s] %s", self.job_id, message)

    # -- convenience ------------------------------------------------------

    @property
    def scanned(self) -> int:
        return self._scanned

    @property
    def threat_action(self) -> ThreatAction:
        return self.settings.scan.on_threat

    def target_description(self) -> str:
        if not self.targets:
            return "Nothing"
        if len(self.targets) == 1:
            return paths.shorten(self.targets[0])
        return f"{paths.shorten(self.targets[0])} and {len(self.targets) - 1} more"

    def iter_detections(self) -> Iterator[FileResult]:
        yield from self.detections
