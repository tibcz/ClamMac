"""Durable record of what ClamMac has done: scans, detections, and events.

Backed by SQLite in WAL mode with a fresh connection per operation. Scans run
on background threads and the interface reads on the main one, and passing a
single connection between them is the classic way to get
``ProgrammingError: SQLite objects created in a thread...``. Opening per call
costs microseconds and removes the whole class of problem.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import paths
from .log import get_logger

log = get_logger(__name__)

__all__ = [
    "DetectionRecord",
    "EventRecord",
    "History",
    "NetworkAuditRecord",
    "NetworkFindingRecord",
    "ScanRecord",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    targets         TEXT NOT NULL DEFAULT '[]',
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    state           TEXT NOT NULL,
    scanned         INTEGER NOT NULL DEFAULT 0,
    infected        INTEGER NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    duration        REAL NOT NULL DEFAULT 0,
    engine_version  TEXT NOT NULL DEFAULT '',
    database_version INTEGER NOT NULL DEFAULT 0,
    data_scanned_mb REAL NOT NULL DEFAULT 0,
    owner_pid       INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS detections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL,
    path          TEXT NOT NULL,
    signature     TEXT NOT NULL,
    detected_at   TEXT NOT NULL,
    action        TEXT NOT NULL DEFAULT 'report',
    quarantine_id TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT NOT NULL,
    kind    TEXT NOT NULL,
    level   TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS net_audits (
    id          TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration    REAL NOT NULL DEFAULT 0,
    score       INTEGER NOT NULL DEFAULT 0,
    grade       TEXT NOT NULL DEFAULT '',
    headline    TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    platform    TEXT NOT NULL DEFAULT '',
    listening   INTEGER NOT NULL DEFAULT 0,
    exposed     INTEGER NOT NULL DEFAULT 0,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS net_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id       TEXT NOT NULL,
    check_id       TEXT NOT NULL,
    severity       TEXT NOT NULL,
    category       TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    evidence       TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (audit_id) REFERENCES net_audits (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_started    ON scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_audit_when   ON net_audits (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_find_audit   ON net_findings (audit_id);
CREATE INDEX IF NOT EXISTS idx_detect_scan      ON detections (scan_id);
CREATE INDEX IF NOT EXISTS idx_detect_when      ON detections (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_when      ON events (at DESC);
"""


#: Columns added after 1.0, applied to databases created before they existed.
_MIGRATIONS = {
    "scans": {
        "owner_pid": "INTEGER NOT NULL DEFAULT 0",
        "updated_at": "TEXT NOT NULL DEFAULT ''",
    },
}

#: A scan in one of these states is still going, or it was when it last wrote.
ACTIVE_STATES = ("preparing", "running", "paused", "finishing")

#: The state a scan is moved to when the process that owned it vanished.
INTERRUPTED = "interrupted"

#: A detection that has been journaled but not yet acted on.
PENDING_ACTION = "found"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # it exists; it just is not ours
    except OSError:
        return False
    return True


@dataclass
class ScanRecord:
    id: str
    kind: str
    targets: list[str]
    started_at: str
    finished_at: str = ""
    state: str = "completed"
    scanned: int = 0
    infected: int = 0
    errors: int = 0
    duration: float = 0.0
    engine_version: str = ""
    database_version: int = 0
    data_scanned_mb: float = 0.0
    owner_pid: int = 0
    updated_at: str = ""

    @property
    def started(self) -> datetime:
        return _parse(self.started_at)

    @property
    def clean(self) -> bool:
        return self.infected == 0

    @property
    def interrupted(self) -> bool:
        return self.state == INTERRUPTED

    @property
    def in_progress(self) -> bool:
        return self.state in ACTIVE_STATES

    @property
    def target_summary(self) -> str:
        if not self.targets:
            return "Nothing"
        if len(self.targets) == 1:
            return paths.shorten(self.targets[0], max_len=48)
        return f"{paths.shorten(self.targets[0], max_len=34)} +{len(self.targets) - 1}"


@dataclass
class DetectionRecord:
    id: int
    scan_id: str
    path: str
    signature: str
    detected_at: str
    action: str = "report"
    quarantine_id: str = ""

    @property
    def when(self) -> datetime:
        return _parse(self.detected_at)

    @property
    def name(self) -> str:
        return Path(self.path).name


@dataclass
class NetworkAuditRecord:
    """The headline numbers from one network audit, kept for comparison."""

    id: str
    started_at: str
    finished_at: str = ""
    duration: float = 0.0
    score: int = 0
    grade: str = ""
    headline: str = ""
    hostname: str = ""
    platform: str = ""
    listening: int = 0
    exposed: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def started(self) -> datetime:
        return _parse(self.started_at)

    @property
    def serious(self) -> int:
        return self.critical + self.high

    @property
    def clean(self) -> bool:
        return self.serious == 0


@dataclass
class NetworkFindingRecord:
    id: int
    audit_id: str
    check_id: str
    severity: str
    category: str
    title: str = ""
    summary: str = ""
    recommendation: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class EventRecord:
    id: int
    at: str
    kind: str
    level: str
    message: str

    @property
    def when(self) -> datetime:
        return _parse(self.at)


def _parse(text: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class History:
    """Everything ClamMac remembers."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else paths.history_db()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prepare()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=15.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _prepare(self) -> None:
        try:
            with self._connect() as connection:
                # WAL lets the interface read while a scan is still writing.
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(_SCHEMA)
                self._migrate(connection)
            self.path.chmod(0o600)
        except (sqlite3.Error, OSError) as exc:
            log.error("could not prepare the history database: %s", exc)

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        for table, columns in _MIGRATIONS.items():
            present = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in present:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # -- writes -----------------------------------------------------------

    def begin_scan(self, record: ScanRecord) -> None:
        """Write a scan down the moment it starts, before any of it can be lost.

        The row is the journal entry that lets a later launch tell "finished"
        from "the process died": until :meth:`record_scan` closes it out, its
        state is an active one and ``owner_pid`` names the process responsible.
        """
        record.owner_pid = record.owner_pid or os.getpid()
        record.updated_at = _now()
        self.record_scan(record)

    def checkpoint_scan(
        self,
        scan_id: str,
        *,
        state: str,
        scanned: int,
        infected: int,
        errors: int,
        duration: float,
    ) -> None:
        """Save a running scan's counters. Never touches a scan already closed."""
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        with self._connect() as connection:
            connection.execute(
                f"""UPDATE scans SET state=?, scanned=?, infected=?, errors=?,
                      duration=?, updated_at=?
                   WHERE id=? AND state IN ({placeholders})""",
                (state, scanned, infected, errors, duration, _now(), scan_id, *ACTIVE_STATES),
            )

    def record_scan(self, record: ScanRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO scans
                   (id, kind, targets, started_at, finished_at, state, scanned,
                    infected, errors, duration, engine_version, database_version,
                    data_scanned_mb, owner_pid, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     finished_at=excluded.finished_at, state=excluded.state,
                     scanned=excluded.scanned, infected=excluded.infected,
                     errors=excluded.errors, duration=excluded.duration,
                     data_scanned_mb=excluded.data_scanned_mb,
                     updated_at=excluded.updated_at""",
                (
                    record.id,
                    record.kind,
                    json.dumps(record.targets),
                    record.started_at,
                    record.finished_at,
                    record.state,
                    record.scanned,
                    record.infected,
                    record.errors,
                    record.duration,
                    record.engine_version,
                    record.database_version,
                    record.data_scanned_mb,
                    record.owner_pid,
                    record.updated_at or _now(),
                ),
            )

    def record_detection(
        self,
        scan_id: str,
        path: str,
        signature: str,
        action: str = PENDING_ACTION,
        quarantine_id: str = "",
    ) -> None:
        """Store one detection straight away, before anything has been done about it."""
        self.record_detections(scan_id, [(path, signature, action, quarantine_id)])

    def settle_detection(
        self, scan_id: str, path: str, signature: str, action: str, quarantine_id: str = ""
    ) -> None:
        """Record what became of a journaled detection, adding it if it was never journaled."""
        with self._connect() as connection:
            updated = connection.execute(
                """UPDATE detections SET action=?, quarantine_id=?
                   WHERE scan_id=? AND path=? AND signature=? AND action=?""",
                (action, quarantine_id, scan_id, path, signature, PENDING_ACTION),
            ).rowcount
            if not updated:
                already = connection.execute(
                    "SELECT 1 FROM detections WHERE scan_id=? AND path=? AND signature=?",
                    (scan_id, path, signature),
                ).fetchone()
                if not already:
                    connection.execute(
                        """INSERT INTO detections
                           (scan_id, path, signature, detected_at, action, quarantine_id)
                           VALUES (?,?,?,?,?,?)""",
                        (scan_id, path, signature, _now(), action, quarantine_id),
                    )

    def record_detections(self, scan_id: str, items: Iterable[tuple[str, str, str, str]]) -> None:
        """Store detections as ``(path, signature, action, quarantine_id)``."""
        rows = [(scan_id, p, s, _now(), a, q) for p, s, a, q in items]
        if not rows:
            return
        with self._connect() as connection:
            connection.executemany(
                """INSERT INTO detections
                   (scan_id, path, signature, detected_at, action, quarantine_id)
                   VALUES (?,?,?,?,?,?)""",
                rows,
            )

    def record_network_audit(self, report: Any) -> None:
        """Store an audit's summary and its findings.

        Duck-typed on purpose: ``history`` sits below the network package and
        should not import it back.
        """
        counts = {severity.value: count for severity, count in report.counts.items()}
        snapshot = report.snapshot
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO net_audits
                   (id, started_at, finished_at, duration, score, grade, headline,
                    hostname, platform, listening, exposed, critical, high, medium, low)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     finished_at=excluded.finished_at, duration=excluded.duration,
                     score=excluded.score, grade=excluded.grade,
                     headline=excluded.headline, listening=excluded.listening,
                     exposed=excluded.exposed, critical=excluded.critical,
                     high=excluded.high, medium=excluded.medium, low=excluded.low""",
                (
                    report.audit_id,
                    report.started_at,
                    report.finished_at,
                    report.duration,
                    report.score,
                    report.grade,
                    report.headline,
                    snapshot.hostname,
                    snapshot.platform,
                    len(snapshot.listeners),
                    len(snapshot.exposed_listeners),
                    counts.get("critical", 0),
                    counts.get("high", 0),
                    counts.get("medium", 0),
                    counts.get("low", 0),
                ),
            )
            connection.execute(
                "DELETE FROM net_findings WHERE audit_id = ?", (report.audit_id,)
            )
            connection.executemany(
                """INSERT INTO net_findings
                   (audit_id, check_id, severity, category, title, summary,
                    recommendation, evidence)
                   VALUES (?,?,?,?,?,?,?,?)""",
                [
                    (
                        report.audit_id,
                        finding.check_id,
                        finding.severity.value,
                        finding.category.value,
                        finding.title,
                        finding.summary,
                        finding.recommendation,
                        json.dumps(list(finding.evidence)),
                    )
                    for finding in report.ordered
                ],
            )

    def record_event(self, kind: str, message: str, level: str = "info") -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO events (at, kind, level, message) VALUES (?,?,?,?)",
                (_now(), kind, level, message),
            )

    # -- reads ------------------------------------------------------------

    def scans(self, limit: int = 200, offset: int = 0) -> list[ScanRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [_scan_from_row(r) for r in rows]

    def scan(self, scan_id: str) -> ScanRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _scan_from_row(row) if row else None

    def last_scan(self) -> ScanRecord | None:
        """The most recent scan that is over; one still running has no result yet."""
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT * FROM scans WHERE state NOT IN ({placeholders}) "
                "ORDER BY started_at DESC LIMIT 1",
                ACTIVE_STATES,
            ).fetchone()
        return _scan_from_row(row) if row else None

    def orphaned_scans(self) -> list[ScanRecord]:
        """Scans left active by a process that no longer exists."""
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM scans WHERE state IN ({placeholders}) ORDER BY started_at",
                ACTIVE_STATES,
            ).fetchall()
        mine = os.getpid()
        return [
            record
            for record in map(_scan_from_row, rows)
            if record.owner_pid != mine and not _process_alive(record.owner_pid)
        ]

    def mark_interrupted(self, scan_id: str, *, infected: int) -> None:
        """Close out an orphaned scan, keeping everything it had counted."""
        placeholders = ",".join("?" for _ in ACTIVE_STATES)
        with self._connect() as connection:
            connection.execute(
                f"""UPDATE scans SET state=?, infected=?,
                      finished_at=CASE WHEN updated_at != '' THEN updated_at ELSE ? END
                   WHERE id=? AND state IN ({placeholders})""",
                (INTERRUPTED, infected, _now(), scan_id, *ACTIVE_STATES),
            )

    def pending_detections(self, scan_id: str) -> list[DetectionRecord]:
        return [d for d in self.detections(scan_id=scan_id, limit=100000) if d.action == PENDING_ACTION]

    def detections(
        self, scan_id: str = "", limit: int = 500, search: str = ""
    ) -> list[DetectionRecord]:
        query = "SELECT * FROM detections"
        params: list[Any] = []
        clauses: list[str] = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if search:
            clauses.append("(path LIKE ? OR signature LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            DetectionRecord(
                id=r["id"],
                scan_id=r["scan_id"],
                path=r["path"],
                signature=r["signature"],
                detected_at=r["detected_at"],
                action=r["action"],
                quarantine_id=r["quarantine_id"],
            )
            for r in rows
        ]

    def network_audits(self, limit: int = 100) -> list[NetworkAuditRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM net_audits ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_audit_from_row(row) for row in rows]

    def last_network_audit(self) -> NetworkAuditRecord | None:
        found = self.network_audits(limit=1)
        return found[0] if found else None

    def network_findings(self, audit_id: str) -> list[NetworkFindingRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM net_findings WHERE audit_id = ? ORDER BY id", (audit_id,)
            ).fetchall()
        findings = []
        for row in rows:
            try:
                evidence = json.loads(row["evidence"])
            except (json.JSONDecodeError, TypeError):
                evidence = []
            findings.append(
                NetworkFindingRecord(
                    id=row["id"],
                    audit_id=row["audit_id"],
                    check_id=row["check_id"],
                    severity=row["severity"],
                    category=row["category"],
                    title=row["title"],
                    summary=row["summary"],
                    recommendation=row["recommendation"],
                    evidence=[str(item) for item in evidence]
                    if isinstance(evidence, list)
                    else [],
                )
            )
        return findings

    def events(self, limit: int = 200, kind: str = "") -> list[EventRecord]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if kind:
            query += " WHERE kind = ?"
            params.append(kind)
        query += " ORDER BY at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            EventRecord(id=r["id"], at=r["at"], kind=r["kind"], level=r["level"], message=r["message"])
            for r in rows
        ]

    # -- aggregates -------------------------------------------------------

    def statistics(self) -> dict[str, Any]:
        """Headline numbers for the dashboard."""
        with self._connect() as connection:
            scans = connection.execute(
                "SELECT COUNT(*) c, COALESCE(SUM(scanned),0) f, COALESCE(SUM(duration),0) d "
                "FROM scans WHERE state IN ('completed', 'interrupted')"
            ).fetchone()
            threats = connection.execute("SELECT COUNT(*) c FROM detections").fetchone()
            recent = connection.execute(
                "SELECT COUNT(*) c FROM detections WHERE detected_at > ?",
                ((datetime.now(UTC) - timedelta(days=30)).isoformat(timespec="seconds"),),
            ).fetchone()
        return {
            "scan_count": scans["c"],
            "files_scanned": scans["f"],
            "total_seconds": scans["d"],
            "threats_total": threats["c"],
            "threats_last_30_days": recent["c"],
        }

    # -- maintenance ------------------------------------------------------

    def prune(self, keep_days: int = 365) -> int:
        """Delete scans older than ``keep_days``. Returns rows removed."""
        cutoff = (datetime.now(UTC) - timedelta(days=keep_days)).isoformat(
            timespec="seconds"
        )
        with self._connect() as connection:
            removed = connection.execute("DELETE FROM scans WHERE started_at < ?", (cutoff,)).rowcount
            connection.execute("DELETE FROM detections WHERE detected_at < ?", (cutoff,))
            connection.execute("DELETE FROM events WHERE at < ?", (cutoff,))
            connection.execute("DELETE FROM net_audits WHERE started_at < ?", (cutoff,))
        return removed

    def clear(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                "DELETE FROM detections; DELETE FROM scans; DELETE FROM events;"
                "DELETE FROM net_findings; DELETE FROM net_audits;"
            )


def _audit_from_row(row: sqlite3.Row) -> NetworkAuditRecord:
    return NetworkAuditRecord(
        id=row["id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"] or "",
        duration=row["duration"],
        score=row["score"],
        grade=row["grade"],
        headline=row["headline"],
        hostname=row["hostname"],
        platform=row["platform"],
        listening=row["listening"],
        exposed=row["exposed"],
        critical=row["critical"],
        high=row["high"],
        medium=row["medium"],
        low=row["low"],
    )


def _scan_from_row(row: sqlite3.Row) -> ScanRecord:
    try:
        targets = json.loads(row["targets"])
        if not isinstance(targets, list):
            targets = []
    except (json.JSONDecodeError, TypeError):
        targets = []
    return ScanRecord(
        id=row["id"],
        kind=row["kind"],
        targets=[str(t) for t in targets],
        started_at=row["started_at"],
        finished_at=row["finished_at"] or "",
        state=row["state"],
        scanned=row["scanned"],
        infected=row["infected"],
        errors=row["errors"],
        duration=row["duration"],
        engine_version=row["engine_version"],
        database_version=row["database_version"],
        data_scanned_mb=row["data_scanned_mb"],
        owner_pid=row["owner_pid"],
        updated_at=row["updated_at"],
    )
