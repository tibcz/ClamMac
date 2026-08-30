"""Virus definition updates, driven by ClamAV's own ``freshclam``.

ClamMac generates a private ``freshclam.conf`` pointing at its own database
directory, so updates never touch a system-wide install and never need root.
Output is parsed live to drive a progress bar and to report what actually
changed, because "up to date" and "downloaded 200 MB" both exit zero and users
deserve to be told which one happened.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable

from . import engine as engine_module
from . import paths
from .log import get_logger

log = get_logger(__name__)

__all__ = [
    "UpdateOutcome",
    "UpdateState",
    "DatabaseChange",
    "UpdateProgress",
    "UpdateJob",
    "parse_update_line",
]


class UpdateState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in {UpdateState.COMPLETED, UpdateState.CANCELLED, UpdateState.FAILED}


class UpdateOutcome(str, Enum):
    UNKNOWN = "unknown"
    UP_TO_DATE = "up_to_date"
    UPDATED = "updated"
    FAILED = "failed"

    @property
    def label(self) -> str:
        return {
            UpdateOutcome.UNKNOWN: "Finished",
            UpdateOutcome.UP_TO_DATE: "Definitions are already current",
            UpdateOutcome.UPDATED: "Definitions updated",
            UpdateOutcome.FAILED: "Update failed",
        }[self]


@dataclass(frozen=True)
class DatabaseChange:
    """One database freshclam reported on."""

    name: str
    version: int = 0
    signatures: int = 0
    updated: bool = False


@dataclass
class UpdateProgress:
    state: UpdateState = UpdateState.IDLE
    message: str = ""
    fraction: float = -1.0
    current_database: str = ""


# --------------------------------------------------------------------------
# output parsing
# --------------------------------------------------------------------------

_UP_TO_DATE = re.compile(
    r"^(?P<name>[\w.\-]+) database is up[- ]to[- ]date.*?version:\s*(?P<version>\d+)"
    r"(?:,\s*sigs:\s*(?P<sigs>\d+))?",
    re.IGNORECASE,
)
_UPDATED = re.compile(
    r"^(?P<name>[\w.\-]+)(?:\.c[vl]d)? (?:database )?updated.*?version:\s*(?P<version>\d+)"
    r"(?:,\s*sigs:\s*(?P<sigs>\d+))?",
    re.IGNORECASE,
)
_DOWNLOADING = re.compile(
    r"(?:Downloading|Retrieving)\s+(?P<name>\S+).*?\[\s*(?P<percent>\d+)%\]", re.IGNORECASE
)
_TESTING = re.compile(r"Testing database", re.IGNORECASE)


def parse_update_line(line: str) -> tuple[DatabaseChange | None, UpdateProgress | None]:
    """Interpret one line of freshclam output.

    Returns a database change when the line reports one, and/or a progress
    update when the line carries one. Most lines produce neither.
    """
    text = line.strip()
    if not text:
        return None, None

    match = _DOWNLOADING.search(text)
    if match:
        percent = int(match.group("percent"))
        return None, UpdateProgress(
            state=UpdateState.RUNNING,
            message=f"Downloading {match.group('name')}",
            fraction=percent / 100.0,
            current_database=match.group("name"),
        )

    match = _UPDATED.match(text)
    if match:
        change = DatabaseChange(
            name=match.group("name"),
            version=int(match.group("version") or 0),
            signatures=int(match.group("sigs") or 0),
            updated=True,
        )
        return change, UpdateProgress(
            state=UpdateState.RUNNING,
            message=f"Updated {change.name} to version {change.version}",
            current_database=change.name,
        )

    match = _UP_TO_DATE.match(text)
    if match:
        change = DatabaseChange(
            name=match.group("name"),
            version=int(match.group("version") or 0),
            signatures=int(match.group("sigs") or 0),
            updated=False,
        )
        return change, UpdateProgress(
            state=UpdateState.RUNNING,
            message=f"{change.name} is already current",
            current_database=change.name,
        )

    if _TESTING.search(text):
        return None, UpdateProgress(state=UpdateState.RUNNING, message="Verifying databases")

    return None, None


# --------------------------------------------------------------------------
# the job
# --------------------------------------------------------------------------


@dataclass
class UpdateJob:
    """One run of freshclam, on a background thread."""

    tools: engine_module.EngineTools
    database: Path = field(default_factory=paths.database_dir)

    on_progress: Callable[[UpdateProgress], None] | None = None
    on_finished: Callable[["UpdateJob"], None] | None = None
    on_log: Callable[[str], None] | None = None

    state: UpdateState = UpdateState.IDLE
    outcome: UpdateOutcome = UpdateOutcome.UNKNOWN
    changes: list[DatabaseChange] = field(default_factory=list)
    output: list[str] = field(default_factory=list)
    failure: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None

    _process: subprocess.Popen[str] | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)

    def start(self) -> None:
        if self.state is UpdateState.RUNNING:
            raise RuntimeError("an update is already running")
        self._stop.clear()
        self.state = UpdateState.RUNNING
        self.started_at = datetime.now(timezone.utc)
        self.changes.clear()
        self.output.clear()
        self._thread = threading.Thread(target=self._run, name="freshclam", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._stop.set()
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    def wait(self, timeout: float | None = None) -> bool:
        if self._thread is None:
            return True
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def run_blocking(self) -> UpdateOutcome:
        """Run to completion on the calling thread, for scheduled updates."""
        self.state = UpdateState.RUNNING
        self.started_at = datetime.now(timezone.utc)
        self._run()
        return self.outcome

    # -- worker -----------------------------------------------------------

    def _run(self) -> None:
        try:
            self.database.mkdir(parents=True, exist_ok=True)
            config = engine_module.write_freshclam_conf(self.database)
            command = [
                str(self.tools.freshclam),
                f"--config-file={config}",
                f"--datadir={self.database}",
                "--stdout",
            ]
            self._emit(UpdateProgress(UpdateState.RUNNING, "Contacting the ClamAV mirrors"))
            self._log(" ".join(command))

            process = subprocess.Popen(  # noqa: S603
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=engine_module._clean_env(),
            )
            self._process = process
            assert process.stdout is not None
            for line in process.stdout:
                if self._stop.is_set():
                    break
                text = line.rstrip("\n")
                if text.strip():
                    self.output.append(text)
                    self._log(text)
                change, progress = parse_update_line(text)
                if change is not None:
                    self._record(change)
                if progress is not None:
                    self._emit(progress)

            returncode = process.wait()

            if self._stop.is_set():
                self._finish(UpdateState.CANCELLED, UpdateOutcome.FAILED)
                return
            if returncode == 0:
                updated = any(c.updated for c in self.changes)
                self._finish(
                    UpdateState.COMPLETED,
                    UpdateOutcome.UPDATED if updated else UpdateOutcome.UP_TO_DATE,
                )
            else:
                self.failure = self._explain(returncode)
                self._finish(UpdateState.FAILED, UpdateOutcome.FAILED)
        except Exception as exc:  # noqa: BLE001 - never let an update crash the app
            log.exception("definition update failed")
            self.failure = str(exc)
            self._finish(UpdateState.FAILED, UpdateOutcome.FAILED)

    def _record(self, change: DatabaseChange) -> None:
        self.changes = [c for c in self.changes if c.name != change.name]
        self.changes.append(change)

    def _explain(self, returncode: int) -> str:
        """Turn a freshclam exit code into something a person can act on."""
        tail = "\n".join(self.output[-6:]) or "No output."
        hints = {
            40: "freshclam could not reach the ClamAV mirrors. Check your internet connection.",
            43: "The ClamAV mirrors reported an error. Try again in a few minutes.",
            44: "The downloaded database failed verification and was discarded.",
            56: "freshclam could not write to ClamMac's database folder.",
            58: "freshclam's configuration was rejected.",
        }
        hint = hints.get(returncode, f"freshclam exited with status {returncode}.")
        return f"{hint}\n\n{tail}"

    def _finish(self, state: UpdateState, outcome: UpdateOutcome) -> None:
        self.state = state
        self.outcome = outcome
        self.finished_at = datetime.now(timezone.utc)
        log.info(
            "definition update %s (%s), %d database(s) reported",
            state.value,
            outcome.value,
            len(self.changes),
        )
        self._emit(
            UpdateProgress(
                state=state,
                message=self.failure if state is UpdateState.FAILED else outcome.label,
                fraction=1.0,
            )
        )
        if self.on_finished is not None:
            self.on_finished(self)

    def _emit(self, progress: UpdateProgress) -> None:
        if self.on_progress is not None:
            self.on_progress(progress)

    def _log(self, message: str) -> None:
        if self.on_log is not None:
            self.on_log(message)
        log.debug("[freshclam] %s", message)

    # -- results ----------------------------------------------------------

    @property
    def total_signatures(self) -> int:
        return sum(c.signatures for c in self.changes)

    def summary_line(self) -> str:
        if self.outcome is UpdateOutcome.FAILED:
            return self.failure.splitlines()[0] if self.failure else "Update failed"
        updated = [c.name for c in self.changes if c.updated]
        if updated:
            return "Updated " + ", ".join(sorted(updated))
        return "Definitions are already up to date"
