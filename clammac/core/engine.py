"""Finding the ClamAV tools, and turning settings into command lines.

ClamMac never assumes where ClamAV lives. It looks in every place one
realistically ends up -- its own managed copy, the official installer's
prefix, both Homebrew prefixes, MacPorts, and finally ``PATH`` -- and confirms
each candidate by running it rather than by trusting that the file exists.

This module also owns the generated ``freshclam.conf`` and ``clamd.conf``.
ClamAV's own sample configs are installed inert (every line commented out, plus
a deliberate ``Example`` line that makes the tools refuse to start), so ClamMac
writes its own minimal configs pointing at its own directories.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import paths
from .config import ScanSettings, Settings
from .log import get_logger

log = get_logger(__name__)

__all__ = [
    "SEARCH_PREFIXES",
    "DatabaseInfo",
    "EngineInfo",
    "EngineNotFound",
    "EngineTools",
    "build_scan_command",
    "database_info",
    "discover",
    "write_clamd_conf",
    "write_freshclam_conf",
]

#: Directories searched for an engine, in the order they are preferred.
SEARCH_PREFIXES: tuple[Path, ...] = (
    Path("/usr/local/clamav/bin"),  # the official installer package
    Path("/opt/homebrew/bin"),  # Homebrew on Apple silicon
    Path("/usr/local/bin"),  # Homebrew on Intel
    Path("/opt/local/bin"),  # MacPorts
    Path("/usr/bin"),
)

_VERSION_PATTERN = re.compile(
    r"ClamAV\s+(?P<engine>[0-9][0-9A-Za-z.\-]*)"
    r"(?:/(?P<db>\d+)/(?P<date>.+?))?\s*$"
)


class EngineNotFound(Exception):
    """No usable ClamAV installation could be located."""


@dataclass(frozen=True)
class EngineTools:
    """Absolute paths to the ClamAV programs ClamMac drives."""

    root: Path
    clamscan: Path
    freshclam: Path
    clamdscan: Path | None = None
    clamd: Path | None = None
    sigtool: Path | None = None
    clamconf: Path | None = None
    managed: bool = False

    @property
    def origin(self) -> str:
        """A short description of where this engine came from."""
        if self.managed:
            return "Installed by ClamMac"
        text = str(self.root)
        if "/opt/homebrew" in text or text == "/usr/local/bin":
            return "Homebrew"
        if "/opt/local" in text:
            return "MacPorts"
        if "/usr/local/clamav" in text:
            return "ClamAV installer package"
        return text

    def supports_daemon(self) -> bool:
        return self.clamd is not None and self.clamdscan is not None


@dataclass(frozen=True)
class EngineInfo:
    """What ``clamscan --version`` reported."""

    tools: EngineTools
    engine_version: str
    database_version: int = 0
    database_date: datetime | None = None
    raw: str = ""

    @property
    def has_database(self) -> bool:
        return self.database_version > 0


@dataclass(frozen=True)
class DatabaseInfo:
    """The state of the signature databases on disk."""

    directory: Path
    files: tuple[Path, ...] = ()
    total_bytes: int = 0
    newest: datetime | None = None
    signature_count: int = 0

    @property
    def present(self) -> bool:
        return bool(self.files)

    def age_days(self) -> float | None:
        if self.newest is None:
            return None
        delta = datetime.now(UTC) - self.newest
        return delta.total_seconds() / 86400.0

    def is_stale(self, threshold_days: int) -> bool:
        age = self.age_days()
        return age is None or age > threshold_days


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------


def _candidate_roots(explicit: str = "") -> list[Path]:
    """Directories that might hold ClamAV binaries, most preferred first."""
    roots: list[Path] = []

    if explicit:
        given = Path(explicit).expanduser()
        # Accept either the engine root or its bin directory.
        roots.extend([given / "bin", given])

    managed = paths.engine_dir()
    current = managed / "current"
    if current.exists():
        roots.append(current / "bin")
    if managed.is_dir():
        versions = sorted(
            (p for p in managed.iterdir() if p.is_dir() and not p.is_symlink()),
            reverse=True,
        )
        roots.extend(p / "bin" for p in versions)

    roots.extend(SEARCH_PREFIXES)

    on_path = shutil.which("clamscan")
    if on_path:
        roots.append(Path(on_path).parent)

    seen: list[Path] = []
    for root in roots:
        if root not in seen:
            seen.append(root)
    return seen


def _probe(clamscan: Path, timeout: int = 30) -> str | None:
    """Run ``clamscan --version`` and return its first line, or None."""
    try:
        result = subprocess.run(
            [str(clamscan), "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_clean_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("probe of %s failed: %s", clamscan, exc)
        return None
    output = (result.stdout or result.stderr or "").strip()
    if not output or "ClamAV" not in output:
        return None
    return output.splitlines()[0].strip()


def _tools_at(root: Path, *, managed: bool) -> EngineTools | None:
    clamscan = root / "clamscan"
    freshclam = root / "freshclam"
    if not clamscan.is_file() or not os.access(clamscan, os.X_OK):
        return None

    def maybe(*names: str) -> Path | None:
        for name in names:
            for base in (root, root.parent / "sbin"):
                candidate = base / name
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return candidate
        return None

    return EngineTools(
        root=root,
        clamscan=clamscan,
        freshclam=freshclam if freshclam.is_file() else clamscan,
        clamdscan=maybe("clamdscan"),
        clamd=maybe("clamd"),
        sigtool=maybe("sigtool"),
        clamconf=maybe("clamconf"),
        managed=managed,
    )


def discover(settings: Settings | None = None) -> EngineInfo | None:
    """Locate a working ClamAV installation, or return None.

    Every candidate is confirmed by executing it. A directory containing a
    ``clamscan`` that cannot actually start -- a broken Homebrew link, an
    engine whose libraries have moved -- is skipped rather than reported.
    """
    explicit = settings.engine_path if settings else ""
    managed_root = paths.engine_dir()

    for root in _candidate_roots(explicit):
        tools = _tools_at(root, managed=_is_within(root, managed_root))
        if tools is None:
            continue
        banner = _probe(tools.clamscan)
        if banner is None:
            log.debug("candidate %s exists but did not run", root)
            continue
        info = _parse_version(tools, banner)
        log.info("using ClamAV %s from %s", info.engine_version, root)
        return info

    return None


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
    except (ValueError, OSError):
        return False
    return True


def _parse_version(tools: EngineTools, banner: str) -> EngineInfo:
    match = _VERSION_PATTERN.search(banner)
    if not match:
        return EngineInfo(tools=tools, engine_version=banner, raw=banner)
    db_version = int(match.group("db") or 0)
    db_date = None
    raw_date = match.group("date")
    if raw_date:
        db_date = _parse_clamav_date(raw_date.strip())
    return EngineInfo(
        tools=tools,
        engine_version=match.group("engine"),
        database_version=db_version,
        database_date=db_date,
        raw=banner,
    )


def _parse_clamav_date(text: str) -> datetime | None:
    """ClamAV prints dates in a couple of shapes depending on the tool."""
    for pattern in ("%a %b %d %H:%M:%S %Y", "%d %b %Y %H-%M %z", "%a %b  %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _clean_env() -> dict[str, str]:
    """A child environment with our own dynamic-loader meddling removed."""
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("DYLD_", "LD_")) or key in {
            "PYTHONHOME",
            "PYTHONPATH",
            "QT_PLUGIN_PATH",
            "QT_QPA_PLATFORM_PLUGIN_PATH",
        }:
            env.pop(key, None)
    return env


# --------------------------------------------------------------------------
# database inspection
# --------------------------------------------------------------------------

_DB_SUFFIXES = (".cvd", ".cld", ".hdb", ".hsb", ".ndb", ".ldb", ".mdb", ".cbc", ".ign2")


def database_info(directory: Path | None = None) -> DatabaseInfo:
    """Summarise the signature databases sitting in ``directory``."""
    target = directory or paths.database_dir()
    if not target.is_dir():
        return DatabaseInfo(directory=target)

    files: list[Path] = []
    total = 0
    newest: datetime | None = None
    for item in sorted(target.iterdir()):
        if not item.is_file() or item.suffix.lower() not in _DB_SUFFIXES:
            continue
        files.append(item)
        try:
            stat = item.stat()
        except OSError:
            continue
        total += stat.st_size
        stamp = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
        if newest is None or stamp > newest:
            newest = stamp

    return DatabaseInfo(
        directory=target,
        files=tuple(files),
        total_bytes=total,
        newest=newest,
    )


# --------------------------------------------------------------------------
# command construction
# --------------------------------------------------------------------------


def _yesno(value: bool) -> str:
    return "yes" if value else "no"


def build_scan_command(
    tools: EngineTools,
    targets: list[Path],
    settings: Settings,
    *,
    database: Path | None = None,
    recursive: bool = True,
) -> list[str]:
    """Assemble the ``clamscan`` command line for a scan.

    Note what is *not* here: ``--remove``, ``--move`` and ``--copy``. ClamMac
    handles detections itself so that a file is only ever touched after the
    scan has reported it, the user's chosen action has been applied, and the
    move has been recorded. Letting the scanner delete files directly would
    make that unauditable and unrecoverable.
    """
    scan: ScanSettings = settings.scan
    db = database or paths.database_dir()

    command = [
        str(tools.clamscan),
        f"--database={db}",
        "--stdout",
        # Keep per-file output: it is what drives the live progress display.
        f"--max-filesize={scan.max_file_size_mb}M",
        f"--max-scansize={scan.max_scan_size_mb}M",
        f"--max-recursion={scan.max_recursion}",
        f"--max-files={scan.max_files}",
        f"--scan-archive={_yesno(scan.scan_archives)}",
        f"--scan-mail={_yesno(scan.scan_mail)}",
        f"--scan-pdf={_yesno(scan.scan_pdf)}",
        f"--scan-ole2={_yesno(scan.scan_ole2)}",
        f"--scan-html={_yesno(scan.scan_html)}",
        f"--scan-pe={_yesno(scan.scan_executables)}",
        f"--scan-elf={_yesno(scan.scan_executables)}",
        f"--scan-image={_yesno(scan.scan_images)}",
        f"--detect-pua={_yesno(scan.detect_pua)}",
        f"--alert-encrypted={_yesno(scan.alert_encrypted)}",
        f"--alert-broken={_yesno(scan.alert_broken_executables)}",
        f"--heuristic-alerts={_yesno(scan.heuristic_alerts)}",
        f"--cross-fs={_yesno(scan.cross_filesystems)}",
        f"--follow-dir-symlinks={2 if scan.follow_directory_symlinks else 0}",
        f"--follow-file-symlinks={2 if scan.follow_file_symlinks else 0}",
    ]
    if recursive:
        command.append("--recursive")

    for pattern in _exclusion_patterns(settings):
        command.append(f"--exclude={pattern}")
        command.append(f"--exclude-dir={pattern}")

    # ClamMac's own quarantine must never be rescanned; it is full of things
    # the scanner already flagged, and rescanning it would loop forever.
    command.append(f"--exclude-dir=^{re.escape(str(paths.quarantine_dir()))}")

    command.extend(str(t) for t in targets)
    return command


def _exclusion_patterns(settings: Settings) -> list[str]:
    """Turn the user's exclusions into the POSIX regexes clamscan expects."""
    patterns: list[str] = []
    for raw in settings.exclusions.paths:
        expanded = str(Path(raw).expanduser())
        if expanded:
            patterns.append("^" + re.escape(expanded))
    for extension in settings.exclusions.extensions:
        cleaned = extension.strip().lstrip(".")
        if cleaned:
            patterns.append(rf"\.{re.escape(cleaned)}$")
    return patterns


def scan_environment(settings: Settings) -> dict[str, str]:
    """Environment for a scan process."""
    return _clean_env()


def nice_prefix(settings: Settings) -> list[str]:
    """Wrap the scanner in ``nice`` when the user asked for low priority.

    A full scan reads every file on the disk. Left at normal priority that
    makes the whole machine feel broken, which is the most common reason
    people turn scanning off entirely.
    """
    if settings.scan.low_priority and Path("/usr/bin/nice").exists():
        return ["/usr/bin/nice", "-n", "10"]
    return []


# --------------------------------------------------------------------------
# generated configuration files
# --------------------------------------------------------------------------


def write_freshclam_conf(database: Path | None = None) -> Path:
    """Write a minimal freshclam.conf pointing at ClamMac's database folder."""
    db = database or paths.database_dir()
    db.mkdir(parents=True, exist_ok=True)
    target = paths.runtime_dir() / "freshclam.conf"
    target.parent.mkdir(parents=True, exist_ok=True)
    body = f"""# Generated by ClamMac. Edits will be overwritten.
DatabaseDirectory {db}
UpdateLogFile {paths.logs_dir() / "freshclam.log"}
LogTime yes
LogVerbose no
LogFileMaxSize 2M
DatabaseOwner {_current_user()}
DNSDatabaseInfo current.cvd.clamav.net
DatabaseMirror database.clamav.net
MaxAttempts 3
ScriptedUpdates yes
CompressLocalDatabase no
Foreground yes
ConnectTimeout 30
ReceiveTimeout 0
TestDatabases yes
"""
    target.write_text(body, encoding="utf-8")
    return target


def write_clamd_conf(database: Path | None = None, *, settings: Settings | None = None) -> Path:
    """Write a clamd.conf for ClamMac's private, user-owned daemon."""
    db = database or paths.database_dir()
    runtime = paths.runtime_dir()
    runtime.mkdir(parents=True, exist_ok=True)
    scan = settings.scan if settings else ScanSettings()
    target = runtime / "clamd.conf"
    body = f"""# Generated by ClamMac. Edits will be overwritten.
DatabaseDirectory {db}
LocalSocket {runtime / "clamd.sock"}
LocalSocketMode 600
PidFile {runtime / "clamd.pid"}
LogFile {paths.logs_dir() / "clamd.log"}
LogTime yes
LogFileMaxSize 4M
LogVerbose no
Foreground yes
User {_current_user()}
MaxThreads 4
MaxQueue 100
IdleTimeout 30
MaxDirectoryRecursion {scan.max_recursion}
FollowDirectorySymlinks {_yesno(scan.follow_directory_symlinks)}
FollowFileSymlinks {_yesno(scan.follow_file_symlinks)}
CrossFilesystems {_yesno(scan.cross_filesystems)}
MaxFileSize {scan.max_file_size_mb}M
MaxScanSize {scan.max_scan_size_mb}M
MaxFiles {scan.max_files}
MaxRecursion {scan.max_recursion}
ScanArchive {_yesno(scan.scan_archives)}
ScanMail {_yesno(scan.scan_mail)}
ScanPDF {_yesno(scan.scan_pdf)}
ScanOLE2 {_yesno(scan.scan_ole2)}
ScanHTML {_yesno(scan.scan_html)}
ScanPE {_yesno(scan.scan_executables)}
ScanELF {_yesno(scan.scan_executables)}
DetectPUA {_yesno(scan.detect_pua)}
AlertEncrypted {_yesno(scan.alert_encrypted)}
AlertBrokenExecutables {_yesno(scan.alert_broken_executables)}
HeuristicAlerts {_yesno(scan.heuristic_alerts)}
ExcludePath ^{re.escape(str(paths.quarantine_dir()))}
"""
    target.write_text(body, encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return target


def _current_user() -> str:
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER", "nobody")
