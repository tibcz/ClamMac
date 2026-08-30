"""A dependency-free reader for Apple flat installer packages (``.pkg``).

ClamMac needs to unpack the official ClamAV installer *without* running it and
*without* asking for administrator rights, so that a normal user can get a
working scanner by doing nothing more than clicking "Set up". macOS ships
``xar`` and ``pkgutil`` which could do this, but both are part of the optional
Command Line Tools on some systems, so ClamMac parses the format itself.

A flat package is a `xar` archive whose members are one or more component
sub-packages. Each component holds a ``Payload``: a gzip-compressed cpio
archive of the files to install.

Everything here streams. The ClamAV libraries payload expands to well over half
a gigabyte -- most of it a static archive ClamMac has no use for -- so entries
are filtered as they go past and unwanted ones are discarded without ever being
held in memory.
"""

from __future__ import annotations

import gzip
import os
import stat
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator
from xml.etree import ElementTree

__all__ = [
    "PackageError",
    "XarEntry",
    "XarArchive",
    "CpioEntry",
    "iter_cpio",
    "extract_payload",
]

_XAR_MAGIC = 0x78617221  # 'xar!'
_XAR_HEADER = struct.Struct(">IHHQQI")

_CPIO_NEWC = (b"070701", b"070702")
_CPIO_ODC = b"070707"
_CPIO_TRAILER = "TRAILER!!!"

_COPY_CHUNK = 1 << 20


class PackageError(Exception):
    """Raised when a package is malformed or uses a shape we do not support."""


# --------------------------------------------------------------------------
# xar container
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class XarEntry:
    """One member of a xar archive's table of contents."""

    path: str
    offset: int
    length: int
    size: int
    encoding: str | None

    @property
    def is_gzip(self) -> bool:
        return self.encoding == "application/x-gzip"


class _SectionReader:
    """A read-only, forward-only view of a byte range inside a file."""

    def __init__(self, fh: BinaryIO, start: int, length: int) -> None:
        self._fh = fh
        self._pos = 0
        self._length = length
        self._start = start
        fh.seek(start)

    def read(self, amount: int = -1) -> bytes:
        remaining = self._length - self._pos
        if remaining <= 0:
            return b""
        if amount is None or amount < 0 or amount > remaining:
            amount = remaining
        self._fh.seek(self._start + self._pos)
        data = self._fh.read(amount)
        self._pos += len(data)
        return data

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - gzip may call this
        pass


class XarArchive:
    """Reads the table of contents of a xar archive and extracts members."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._fh: BinaryIO | None = None
        self._heap = 0
        self.entries: list[XarEntry] = []

    def __enter__(self) -> "XarArchive":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def open(self) -> None:
        fh = self.path.open("rb")
        self._fh = fh
        raw = fh.read(_XAR_HEADER.size)
        if len(raw) < _XAR_HEADER.size:
            raise PackageError("file is too short to be a xar archive")
        magic, header_size, _version, toc_len, toc_raw_len, _alg = _XAR_HEADER.unpack(raw)
        if magic != _XAR_MAGIC:
            raise PackageError("not a xar archive (bad magic)")
        if header_size < _XAR_HEADER.size:
            raise PackageError("implausible xar header size")
        fh.seek(header_size)
        try:
            toc = zlib.decompress(fh.read(toc_len))
        except zlib.error as exc:  # pragma: no cover - corrupt input
            raise PackageError(f"could not decompress xar table of contents: {exc}") from exc
        if toc_raw_len and len(toc) != toc_raw_len:
            raise PackageError("xar table of contents has an unexpected length")
        self._heap = header_size + toc_len
        self.entries = list(self._parse_toc(toc))

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    @staticmethod
    def _parse_toc(toc: bytes) -> Iterator[XarEntry]:
        root = ElementTree.fromstring(toc)
        table = root.find("toc")
        if table is None:
            raise PackageError("xar archive has no <toc> element")

        def walk(node: ElementTree.Element, prefix: str) -> Iterator[XarEntry]:
            for element in node.findall("file"):
                name = element.findtext("name") or ""
                full = f"{prefix}/{name}" if prefix else name
                data = element.find("data")
                if data is not None:
                    encoding = data.find("encoding")
                    yield XarEntry(
                        path=full,
                        offset=int(data.findtext("offset") or 0),
                        length=int(data.findtext("length") or 0),
                        size=int(data.findtext("size") or 0),
                        encoding=encoding.get("style") if encoding is not None else None,
                    )
                yield from walk(element, full)

        yield from walk(table, "")

    def find(self, path: str) -> XarEntry | None:
        for entry in self.entries:
            if entry.path == path:
                return entry
        return None

    def component_payloads(self) -> list[XarEntry]:
        """Every component sub-package payload, in table-of-contents order."""
        return [e for e in self.entries if e.path.endswith("/Payload")]

    def read(self, entry: XarEntry) -> bytes:
        """Read a member fully into memory. Only for small members."""
        if self._fh is None:
            raise PackageError("archive is not open")
        self._fh.seek(self._heap + entry.offset)
        blob = self._fh.read(entry.length)
        if entry.is_gzip:
            return zlib.decompress(blob)
        return blob

    def stream(self, entry: XarEntry) -> BinaryIO:
        """A file-like object over a member, transparently decompressed."""
        if self._fh is None:
            raise PackageError("archive is not open")
        section = _SectionReader(self._fh, self._heap + entry.offset, entry.length)
        head = self._peek(entry)
        if head[:2] == b"\x1f\x8b":
            return gzip.GzipFile(fileobj=section)  # type: ignore[arg-type]
        if entry.is_gzip:
            return gzip.GzipFile(fileobj=section)  # type: ignore[arg-type]
        return section  # type: ignore[return-value]

    def _peek(self, entry: XarEntry, amount: int = 4) -> bytes:
        assert self._fh is not None
        self._fh.seek(self._heap + entry.offset)
        return self._fh.read(amount)


# --------------------------------------------------------------------------
# cpio payloads
# --------------------------------------------------------------------------


@dataclass
class CpioEntry:
    """A single archive member. ``data`` is present only for wanted files."""

    name: str
    mode: int
    size: int
    mtime: int
    data: bytes | None = None

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def is_file(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def link_target(self) -> str:
        if not self.is_symlink or self.data is None:
            return ""
        return self.data.decode("utf-8", "replace")

    @property
    def permissions(self) -> int:
        return stat.S_IMODE(self.mode)


def _read_exactly(fh: BinaryIO, amount: int) -> bytes:
    """Read exactly ``amount`` bytes, tolerating short reads from gzip."""
    chunks: list[bytes] = []
    remaining = amount
    while remaining > 0:
        chunk = fh.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _skip(fh: BinaryIO, amount: int) -> None:
    """Discard ``amount`` bytes without holding them all in memory."""
    while amount > 0:
        chunk = fh.read(min(amount, _COPY_CHUNK))
        if not chunk:
            return
        amount -= len(chunk)


def iter_cpio(
    fh: BinaryIO,
    *,
    want: Callable[[str, int], bool] | None = None,
) -> Iterator[CpioEntry]:
    """Yield members of a cpio stream, reading data only for wanted entries.

    ``want`` is called with the member's name and mode. When it returns False
    the member's payload is skipped rather than read, which is what keeps the
    peak memory cost of unpacking ClamAV to a few megabytes instead of half a
    gigabyte. Directories and symlinks are always materialised: they are tiny
    and the caller needs them to rebuild the tree.
    """
    while True:
        magic = _read_exactly(fh, 6)
        if len(magic) < 6:
            return
        if magic in _CPIO_NEWC:
            header = _read_exactly(fh, 104)
            if len(header) < 104:
                raise PackageError("truncated cpio header")
            fields = [int(header[i * 8 : (i + 1) * 8], 16) for i in range(13)]
            mode, size, namesize = fields[1], fields[6], fields[11]
            mtime = fields[5]
            raw_name = _read_exactly(fh, namesize)
            _skip(fh, (-(110 + namesize)) % 4)
            data_pad = (-size) % 4
        elif magic == _CPIO_ODC:
            header = _read_exactly(fh, 70)
            if len(header) < 70:
                raise PackageError("truncated cpio header")
            mode = int(header[12:18], 8)
            mtime = int(header[32:43], 8)
            namesize = int(header[53:59], 8)
            size = int(header[59:70], 8)
            raw_name = _read_exactly(fh, namesize)
            data_pad = 0
        else:
            raise PackageError(f"unsupported cpio format {magic!r}")

        name = raw_name.rstrip(b"\x00").decode("utf-8", "replace")
        if name == _CPIO_TRAILER:
            return

        entry = CpioEntry(name=name, mode=mode, size=size, mtime=mtime)
        needed = entry.is_symlink or (
            entry.is_file and (want is None or want(name, mode))
        )
        if needed:
            entry.data = _read_exactly(fh, size)
        else:
            _skip(fh, size)
        _skip(fh, data_pad)
        yield entry


def extract_payload(
    fh: BinaryIO,
    destination: Path,
    *,
    strip_prefix: str = "",
    want: Callable[[str, int], bool] | None = None,
    on_file: Callable[[Path, CpioEntry], None] | None = None,
) -> list[Path]:
    """Unpack a cpio payload onto disk beneath ``destination``.

    ``strip_prefix`` removes a leading path component (the ClamAV payload is
    rooted at ``./usr/local/clamav``, which ClamMac flattens away). Members
    that escape ``destination`` -- via ``..`` or an absolute path -- are
    refused outright rather than trusted; a package is untrusted input until
    its digest has been checked, and even afterwards this costs nothing.
    """
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    deferred_links: list[tuple[Path, str]] = []

    for entry in iter_cpio(fh, want=want):
        relative = _normalise(entry.name, strip_prefix)
        if relative is None:
            continue
        target = _safe_join(destination, relative)
        if target is None:
            raise PackageError(f"package member escapes the destination: {entry.name}")

        if entry.is_dir:
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)

        if entry.is_symlink:
            deferred_links.append((target, entry.link_target))
            continue

        if entry.data is None:
            continue

        if target.is_symlink() or target.exists():
            target.unlink()
        target.write_bytes(entry.data)
        perms = entry.permissions or 0o644
        # Anything the package marked executable stays executable for the
        # owner; nothing ClamMac unpacks is group- or world-writable.
        target.chmod(perms & 0o755)
        written.append(target)
        if on_file is not None:
            on_file(target, entry)

    for link, link_target in deferred_links:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(link_target)
        written.append(link)

    return written


def _normalise(name: str, strip_prefix: str) -> str | None:
    """Turn a cpio member name into a destination-relative path."""
    cleaned = name
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.lstrip("/")
    if strip_prefix:
        prefix = strip_prefix.strip("/")
        if cleaned == prefix:
            return None
        if not cleaned.startswith(prefix + "/"):
            return None
        cleaned = cleaned[len(prefix) + 1 :]
    if not cleaned or cleaned == ".":
        return None
    return cleaned


def _safe_join(root: Path, relative: str) -> Path | None:
    """Join and confirm the result stays inside ``root``."""
    if relative.startswith("/"):
        return None
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate
