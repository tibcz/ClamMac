"""The quarantine store: isolating suspect files without destroying them.

Deleting a detection outright is the wrong default. Signatures produce false
positives, and the file that got flagged is sometimes the only copy of
something the user needs. So ClamMac moves detections into a private store,
strips every permission bit off the stored copy so nothing can run or read it
by accident, and keeps enough metadata to put it back exactly where it came
from.

The store lives in ClamMac's support directory with mode 0700. The stored
files are given mode 0000: on macOS the owner can still change that back, so
this is a guard against accident, not a security boundary against the user --
but it does mean nothing gets executed, indexed, or opened by a helpful
previewer while it sits there.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import paths
from .log import get_logger

log = get_logger(__name__)

__all__ = ["QuarantineError", "QuarantineEntry", "Quarantine"]

_INDEX_NAME = "index.json"
_STORE_NAME = "store"


class QuarantineError(Exception):
    """A quarantine operation could not be completed."""


@dataclass
class QuarantineEntry:
    """One isolated file."""

    entry_id: str
    original_path: str
    signature: str
    quarantined_at: str
    size: int = 0
    sha256: str = ""
    original_mode: int = 0o644
    scan_id: str = ""
    note: str = ""
    restored: bool = False

    @property
    def name(self) -> str:
        return Path(self.original_path).name

    @property
    def when(self) -> datetime:
        try:
            return datetime.fromisoformat(self.quarantined_at)
        except ValueError:
            return datetime.now(timezone.utc)

    @property
    def display_path(self) -> str:
        return paths.shorten(self.original_path)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "QuarantineEntry":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in raw.items() if k in known})


@dataclass
class Quarantine:
    """A directory of isolated files plus a JSON index describing them."""

    root: Path = field(default_factory=paths.quarantine_dir)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.store.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass

    @property
    def store(self) -> Path:
        return self.root / _STORE_NAME

    @property
    def index_path(self) -> Path:
        return self.root / _INDEX_NAME

    # -- index ------------------------------------------------------------

    def _read_index(self) -> list[QuarantineEntry]:
        if not self.index_path.is_file():
            return []
        try:
            raw = json.loads(self.index_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("quarantine index unreadable: %s", exc)
            return []
        if not isinstance(raw, list):
            return []
        entries: list[QuarantineEntry] = []
        for item in raw:
            try:
                entries.append(QuarantineEntry.from_dict(item))
            except (TypeError, ValueError):
                continue
        return entries

    def _write_index(self, entries: list[QuarantineEntry]) -> None:
        payload = json.dumps([e.to_dict() for e in entries], indent=2)
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.root, prefix=".index-", suffix=".tmp", delete=False
        )
        try:
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, self.index_path)
            self.index_path.chmod(0o600)
        except OSError as exc:
            log.error("could not write quarantine index: %s", exc)
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def entries(self, *, include_restored: bool = False) -> list[QuarantineEntry]:
        """Everything in the store, newest first."""
        with self._lock:
            found = self._read_index()
        if not include_restored:
            found = [e for e in found if not e.restored]
        return sorted(found, key=lambda e: e.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> QuarantineEntry | None:
        for entry in self.entries(include_restored=True):
            if entry.entry_id == entry_id:
                return entry
        return None

    def payload_path(self, entry: QuarantineEntry) -> Path:
        return self.store / entry.entry_id

    def count(self) -> int:
        return len(self.entries())

    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries())

    # -- operations -------------------------------------------------------

    def add(
        self,
        source: Path,
        signature: str,
        *,
        scan_id: str = "",
        note: str = "",
    ) -> QuarantineEntry:
        """Move ``source`` into the store and record where it came from."""
        source = Path(source)
        if not source.exists():
            raise QuarantineError(f"{source} no longer exists")
        if source.is_dir():
            raise QuarantineError("directories cannot be quarantined")
        if self._is_inside_store(source):
            raise QuarantineError("that file is already in quarantine")

        try:
            stat = source.stat()
        except OSError as exc:
            raise QuarantineError(f"could not inspect {source}: {exc}") from exc

        entry_id = uuid.uuid4().hex
        destination = self.store / entry_id
        digest = _digest(source)

        try:
            # shutil.move falls back to copy+unlink across filesystems, which
            # is what happens when the detection is on a mounted volume.
            shutil.move(str(source), str(destination))
        except (OSError, shutil.Error) as exc:
            raise QuarantineError(
                f"could not move {source.name} into quarantine: {exc}"
            ) from exc

        try:
            destination.chmod(0o000)
        except OSError:
            pass

        entry = QuarantineEntry(
            entry_id=entry_id,
            original_path=str(source),
            signature=signature,
            quarantined_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            size=stat.st_size,
            sha256=digest,
            original_mode=stat.st_mode & 0o7777,
            scan_id=scan_id,
            note=note,
        )
        with self._lock:
            current = self._read_index()
            current.append(entry)
            self._write_index(current)
        log.info("quarantined %s (%s)", source, signature)
        return entry

    def restore(self, entry_id: str, destination: Path | None = None) -> Path:
        """Put a quarantined file back, and forget about it."""
        entry = self.get(entry_id)
        if entry is None:
            raise QuarantineError("that quarantine entry no longer exists")
        payload = self.payload_path(entry)
        if not payload.exists():
            raise QuarantineError("the quarantined file is missing from the store")

        target = Path(destination) if destination else Path(entry.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target = _unique_name(target)

        try:
            payload.chmod(0o600)
            shutil.move(str(payload), str(target))
            target.chmod(entry.original_mode or 0o644)
        except (OSError, shutil.Error) as exc:
            raise QuarantineError(f"could not restore {entry.name}: {exc}") from exc

        with self._lock:
            current = self._read_index()
            self._write_index([e for e in current if e.entry_id != entry_id])
        log.warning("restored %s from quarantine to %s", entry.name, target)
        return target

    def delete(self, entry_id: str, *, shred: bool = False) -> None:
        """Remove a quarantined file permanently."""
        entry = self.get(entry_id)
        if entry is None:
            raise QuarantineError("that quarantine entry no longer exists")
        payload = self.payload_path(entry)
        if payload.exists():
            try:
                payload.chmod(0o600)
                if shred:
                    _overwrite(payload)
                payload.unlink()
            except OSError as exc:
                raise QuarantineError(f"could not delete {entry.name}: {exc}") from exc

        with self._lock:
            current = self._read_index()
            self._write_index([e for e in current if e.entry_id != entry_id])
        log.info("deleted quarantined file %s (%s)", entry.name, entry.signature)

    def delete_many(self, entry_ids: list[str], *, shred: bool = False) -> tuple[int, list[str]]:
        """Delete several entries. Returns (deleted, failure messages)."""
        deleted = 0
        problems: list[str] = []
        for entry_id in entry_ids:
            try:
                self.delete(entry_id, shred=shred)
                deleted += 1
            except QuarantineError as exc:
                problems.append(str(exc))
        return deleted, problems

    def empty(self, *, shred: bool = False) -> int:
        """Delete everything. Returns how many entries were removed."""
        ids = [e.entry_id for e in self.entries()]
        deleted, _ = self.delete_many(ids, shred=shred)
        return deleted

    def verify(self) -> list[QuarantineEntry]:
        """Find index entries whose stored file has gone missing."""
        return [e for e in self.entries() if not self.payload_path(e).exists()]

    def prune_missing(self) -> int:
        """Drop index entries with no file behind them."""
        with self._lock:
            current = self._read_index()
            kept = [e for e in current if (self.store / e.entry_id).exists()]
            removed = len(current) - len(kept)
            if removed:
                self._write_index(kept)
        return removed

    # -- helpers ----------------------------------------------------------

    def _is_inside_store(self, candidate: Path) -> bool:
        try:
            candidate.resolve().relative_to(self.root.resolve())
        except (ValueError, OSError):
            return False
        return True


def _digest(path: Path) -> str:
    """SHA-256 of a file, so a restore can be checked against what was stored."""
    sha = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                sha.update(chunk)
    except OSError:
        return ""
    return sha.hexdigest()


def _overwrite(path: Path, passes: int = 1) -> None:
    """Overwrite a file's bytes before unlinking it.

    On the flash storage every modern Mac uses, wear levelling means this
    cannot guarantee the original bytes are gone -- it is offered as a
    best-effort gesture, not a promise, and the interface says so.
    """
    try:
        size = path.stat().st_size
        with path.open("r+b") as handle:
            for _ in range(passes):
                handle.seek(0)
                remaining = size
                while remaining > 0:
                    block = min(remaining, 1 << 20)
                    handle.write(os.urandom(block))
                    remaining -= block
                handle.flush()
                os.fsync(handle.fileno())
    except OSError as exc:
        log.debug("could not overwrite %s: %s", path, exc)


def _unique_name(target: Path) -> Path:
    """Find a free filename next to ``target`` rather than clobbering it."""
    stem, suffix = target.stem, target.suffix
    for index in range(1, 1000):
        candidate = target.with_name(f"{stem} (restored {index}){suffix}")
        if not candidate.exists():
            return candidate
    return target.with_name(f"{stem} (restored {uuid.uuid4().hex[:8]}){suffix}")
