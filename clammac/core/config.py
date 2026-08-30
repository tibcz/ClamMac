"""User settings: the schema, the defaults, and how they persist.

Settings live in one JSON file under ClamMac's support directory. Loading is
deliberately forgiving -- an unknown key is ignored and a malformed value falls
back to its default -- so that a settings file written by a newer build, or
hand-edited into nonsense, can never stop the application from starting.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, get_args, get_origin, get_type_hints

from . import paths
from .log import get_logger

log = get_logger(__name__)

__all__ = [
    "Exclusions",
    "Frequency",
    "InterfaceSettings",
    "ProtectionSettings",
    "ScanDepth",
    "ScanSettings",
    "ScheduleSettings",
    "Settings",
    "Theme",
    "ThreatAction",
    "UpdateSettings",
    "load",
    "save",
]


class ThreatAction(str, Enum):
    """What to do when the scanner reports an infected file."""

    REPORT = "report"
    QUARANTINE = "quarantine"
    DELETE = "delete"

    @property
    def label(self) -> str:
        return {
            ThreatAction.REPORT: "Report only",
            ThreatAction.QUARANTINE: "Move to Quarantine",
            ThreatAction.DELETE: "Delete immediately",
        }[self]


class ScanDepth(str, Enum):
    """Preset bundles of engine limits, from cautious to exhaustive."""

    FAST = "fast"
    BALANCED = "balanced"
    THOROUGH = "thorough"

    @property
    def label(self) -> str:
        return {
            ScanDepth.FAST: "Fast",
            ScanDepth.BALANCED: "Balanced",
            ScanDepth.THOROUGH: "Thorough",
        }[self]


class Theme(str, Enum):
    SYSTEM = "system"
    LIGHT = "light"
    DARK = "dark"

    @property
    def label(self) -> str:
        return {Theme.SYSTEM: "Match System", Theme.LIGHT: "Light", Theme.DARK: "Dark"}[self]


class Frequency(str, Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

    @property
    def label(self) -> str:
        return self.value.capitalize()

    @property
    def seconds(self) -> int:
        return {
            Frequency.HOURLY: 3600,
            Frequency.DAILY: 86400,
            Frequency.WEEKLY: 604800,
            Frequency.MONTHLY: 2592000,
        }[self]


@dataclass
class ScanSettings:
    """Engine limits and which container formats to look inside.

    The defaults mirror ClamAV's own, which are chosen to bound the work a
    hostile archive can force the scanner to do. Raising them finds more, and
    costs more; the Thorough preset does exactly that.
    """

    depth: ScanDepth = ScanDepth.BALANCED
    scan_archives: bool = True
    scan_mail: bool = True
    scan_pdf: bool = True
    scan_ole2: bool = True
    scan_html: bool = True
    scan_executables: bool = True
    scan_images: bool = True
    detect_pua: bool = False
    alert_encrypted: bool = False
    alert_broken_executables: bool = False
    heuristic_alerts: bool = True
    follow_directory_symlinks: bool = False
    follow_file_symlinks: bool = False
    cross_filesystems: bool = False
    max_file_size_mb: int = 100
    max_scan_size_mb: int = 400
    max_recursion: int = 17
    max_files: int = 10000
    on_threat: ThreatAction = ThreatAction.QUARANTINE
    low_priority: bool = True

    def apply_depth(self) -> ScanSettings:
        """Reset the numeric limits to match the chosen preset."""
        if self.depth is ScanDepth.FAST:
            self.max_file_size_mb = 25
            self.max_scan_size_mb = 100
            self.max_recursion = 8
            self.max_files = 5000
            self.scan_archives = True
            self.scan_mail = False
        elif self.depth is ScanDepth.BALANCED:
            self.max_file_size_mb = 100
            self.max_scan_size_mb = 400
            self.max_recursion = 17
            self.max_files = 10000
            self.scan_archives = True
            self.scan_mail = True
        else:
            self.max_file_size_mb = 1000
            self.max_scan_size_mb = 2000
            self.max_recursion = 32
            self.max_files = 50000
            self.scan_archives = True
            self.scan_mail = True
            self.alert_encrypted = True
            self.alert_broken_executables = True
        return self


@dataclass
class ProtectionSettings:
    """Real-time (on-access) protection."""

    enabled: bool = False
    watch_downloads: bool = True
    watch_desktop: bool = True
    watch_documents: bool = False
    watch_home: bool = False
    watch_removable: bool = True
    extra_paths: list[str] = field(default_factory=list)
    settle_seconds: float = 2.0
    max_file_size_mb: int = 64
    notify_on_clean: bool = False

    def watched_paths(self) -> list[Path]:
        """Resolve the enabled toggles into actual directories."""
        home = paths.home()
        selected: list[Path] = []
        if self.watch_home:
            selected.append(home)
        else:
            if self.watch_downloads:
                selected.append(home / "Downloads")
            if self.watch_desktop:
                selected.append(home / "Desktop")
            if self.watch_documents:
                selected.append(home / "Documents")
        if self.watch_removable and Path("/Volumes").is_dir():
            selected.append(Path("/Volumes"))
        selected.extend(Path(p).expanduser() for p in self.extra_paths)

        unique: list[Path] = []
        for candidate in selected:
            if candidate.is_dir() and candidate not in unique:
                unique.append(candidate)
        return unique


@dataclass
class UpdateSettings:
    """Virus definition updates, performed by freshclam."""

    auto_update: bool = True
    frequency: Frequency = Frequency.DAILY
    update_on_launch: bool = True
    notify_on_update: bool = False
    stale_after_days: int = 3


@dataclass
class ScheduleSettings:
    """Unattended scans."""

    enabled: bool = False
    frequency: Frequency = Frequency.WEEKLY
    hour: int = 3
    minute: int = 0
    weekday: int = 6  # Sunday, matching Python's Monday=0 convention
    day_of_month: int = 1
    target: str = "quick"  # "quick", "full", or an explicit path
    only_when_idle: bool = False


@dataclass
class InterfaceSettings:
    theme: Theme = Theme.SYSTEM
    show_menu_bar_item: bool = True
    launch_at_login: bool = False
    start_minimised: bool = False
    close_to_menu_bar: bool = True
    notifications: bool = True
    sound_on_threat: bool = True
    confirm_before_delete: bool = True
    completed_first_run: bool = False


@dataclass
class Exclusions:
    """Things the user has told ClamMac to leave alone.

    Exclusions are a footgun -- every one of them is a place malware could
    hide -- so the UI shows the count prominently and the defaults are empty.
    """

    paths: list[str] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    skip_larger_than_mb: int = 0  # 0 means no size-based exclusion

    def excluded(self, candidate: Path) -> bool:
        text = str(candidate)
        for raw in self.paths:
            prefix = str(Path(raw).expanduser())
            if text == prefix or text.startswith(prefix.rstrip("/") + "/"):
                return True
        suffix = candidate.suffix.lower().lstrip(".")
        return bool(suffix) and suffix in {e.lower().lstrip(".") for e in self.extensions}


@dataclass
class Settings:
    """The whole settings document."""

    version: int = 1
    scan: ScanSettings = field(default_factory=ScanSettings)
    protection: ProtectionSettings = field(default_factory=ProtectionSettings)
    updates: UpdateSettings = field(default_factory=UpdateSettings)
    schedule: ScheduleSettings = field(default_factory=ScheduleSettings)
    interface: InterfaceSettings = field(default_factory=InterfaceSettings)
    exclusions: Exclusions = field(default_factory=Exclusions)
    engine_path: str = ""
    engine_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _plain(asdict(self))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Settings:
        return _build(cls, raw)


# --------------------------------------------------------------------------
# serialisation helpers
# --------------------------------------------------------------------------


def _plain(value: Any) -> Any:
    """Convert enums to their values so json can write them."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _coerce(target: Any, value: Any, fallback: Any) -> Any:
    """Best-effort conversion of a loaded value into the declared type."""
    try:
        if isinstance(target, type) and issubclass(target, Enum):
            return target(value)
        if target is bool:
            return bool(value)
        if target is int:
            return int(value)
        if target is float:
            return float(value)
        if target is str:
            return str(value)
        origin = get_origin(target)
        if origin in (list, tuple):
            args = get_args(target)
            inner = args[0] if args else str
            if not isinstance(value, (list, tuple)):
                return fallback
            return [_coerce(inner, item, item) for item in value]
        if is_dataclass(target):
            return _build(target, value if isinstance(value, dict) else {})
    except (ValueError, TypeError, KeyError):
        return fallback
    return value


_HINT_CACHE: dict[Any, dict[str, Any]] = {}


def _hints(cls: Any) -> dict[str, Any]:
    """Resolve a dataclass's annotations, which ``from __future__ import
    annotations`` leaves as strings."""
    cached = _HINT_CACHE.get(cls)
    if cached is None:
        try:
            cached = get_type_hints(cls)
        except Exception:
            cached = {}
        _HINT_CACHE[cls] = cached
    return cached


def _build(cls: Any, raw: dict[str, Any]) -> Any:
    """Instantiate a dataclass from a dict, defaulting anything unusable."""
    instance = cls()
    if not isinstance(raw, dict):
        return instance
    known = {f.name for f in fields(cls)}
    hints = _hints(cls)
    for key, value in raw.items():
        if key not in known:
            continue
        current = getattr(instance, key)
        declared = hints.get(key) or type(current)
        setattr(instance, key, _coerce(declared, value, current))
    return instance


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------


def load(path: Path | None = None) -> Settings:
    """Read settings from disk, falling back to defaults on any problem."""
    target = path or paths.config_file()
    if not target.is_file():
        return Settings()
    try:
        raw = json.loads(target.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("settings file unreadable (%s); using defaults", exc)
        return Settings()
    if not isinstance(raw, dict):
        return Settings()
    return Settings.from_dict(raw)


def save(settings: Settings, path: Path | None = None) -> None:
    """Write settings atomically so a crash cannot truncate the file."""
    target = path or paths.config_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(settings.to_dict(), indent=2, sort_keys=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=target.parent, prefix=".settings-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(payload)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, target)
        target.chmod(0o600)
    except OSError as exc:
        log.error("could not save settings: %s", exc)
        try:
            os.unlink(handle.name)
        except OSError:
            pass
