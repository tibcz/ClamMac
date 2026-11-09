"""Feeding a scan to every core at once.

``clamscan`` is single-threaded: a full scan of a home folder keeps one core
busy and leaves the rest idle, which on a ten-core Mac means hours instead of
minutes. Running one ``clamscan`` per core is no answer either, because each
copy loads the whole signature database for itself, well over a gigabyte
apiece.

``clamd`` holds one copy of the database and scans on as many threads as it is
given. ClamMac walks the targets itself, here, and hands clamd one file at a
time from several connections at once. Walking in ClamMac rather than letting
clamd recurse is what keeps the live display honest: clamd only reports
detections when it walks a directory, while asking about each file gets a
verdict per file, so the counter, the current path and the progress bar keep
working exactly as they do for a single-core scan.

The walk follows the same rules ``clamscan`` applies to the same settings:
exclusions and the quarantine are skipped, symlinks are followed only when the
user asked, other filesystems are entered only when the user asked, and only
regular files are ever handed over (a FIFO would hang a scanner thread
forever).
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

from . import paths
from .config import Settings
from .log import get_logger

log = get_logger(__name__)

__all__ = ["iter_scan_files", "worker_count"]

#: Never start more scanner threads than this, however large the machine.
MAX_WORKERS = 16


def worker_count() -> int:
    """How many files to scan at once on this machine.

    On Apple silicon only the performance cores are counted: the efficiency
    cores are left for the rest of the system, so a full scan does not make
    the machine feel broken while it runs.
    """
    performance = _sysctl_int("hw.perflevel0.physicalcpu")
    if performance > 0:
        return max(1, min(MAX_WORKERS, performance))
    total = os.cpu_count() or 1
    return max(1, min(MAX_WORKERS, total - 1 if total > 2 else total))


def _sysctl_int(name: str) -> int:
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", name],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return int(result.stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def iter_scan_files(
    targets: list[Path],
    settings: Settings,
    *,
    should_stop: Callable[[], bool] | None = None,
    on_error: Callable[[str, str], None] | None = None,
) -> Iterator[str]:
    """Yield every regular file a scan of ``targets`` should look at.

    ``on_error(path, detail)`` hears about directories that could not be
    opened, which a scan reports rather than skipping in silence.
    """
    scan = settings.scan
    exclusions = settings.exclusions
    quarantine = str(paths.quarantine_dir())

    def skipped(path: str) -> bool:
        if path == quarantine or path.startswith(quarantine + "/"):
            return True
        return exclusions.excluded(Path(path))

    for target in targets:
        root = str(target)
        if skipped(root):
            continue
        try:
            # A target the user named is followed even if it is a symlink,
            # as clamscan does: /tmp is one on macOS.
            info = os.stat(root)
        except OSError as exc:
            if on_error is not None:
                on_error(root, exc.strerror or str(exc))
            continue
        if stat.S_ISREG(info.st_mode):
            yield root
            continue
        if not stat.S_ISDIR(info.st_mode):
            continue

        root_device = info.st_dev
        seen = {(info.st_dev, info.st_ino)}
        stack = [root]
        while stack:
            if should_stop is not None and should_stop():
                return
            directory = stack.pop()
            try:
                entries = os.scandir(directory)
            except OSError as exc:
                if on_error is not None:
                    on_error(directory, f"Can't open directory: {exc.strerror or exc}")
                continue
            with entries:
                for entry in entries:
                    path = entry.path
                    if skipped(path):
                        continue
                    try:
                        if entry.is_symlink():
                            yielded = _follow_link(path, scan, root_device, seen, stack)
                            if yielded:
                                yield path
                        elif entry.is_dir(follow_symlinks=False):
                            child = entry.stat(follow_symlinks=False)
                            if not scan.cross_filesystems and child.st_dev != root_device:
                                continue
                            key = (child.st_dev, child.st_ino)
                            if key not in seen:
                                seen.add(key)
                                stack.append(path)
                        elif entry.is_file(follow_symlinks=False):
                            yield path
                    except OSError:
                        continue


def _follow_link(path: str, scan, root_device: int, seen: set, stack: list[str]) -> bool:
    """Deal with a symlink met while walking. True means: scan it as a file."""
    try:
        info = os.stat(path)
    except OSError:
        return False  # dangling
    if stat.S_ISDIR(info.st_mode):
        if not scan.follow_directory_symlinks:
            return False
        if not scan.cross_filesystems and info.st_dev != root_device:
            return False
        key = (info.st_dev, info.st_ino)
        # The seen set is what stops a link pointing back up the tree from
        # walking forever.
        if key not in seen:
            seen.add(key)
            stack.append(path)
        return False
    return stat.S_ISREG(info.st_mode) and scan.follow_file_symlinks
