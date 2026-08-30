"""Just enough Mach-O surgery to make the ClamAV engine relocatable.

The ClamAV programs published for macOS load their libraries through
``@rpath`` and carry a single, *absolute* run-path: ``/usr/local/clamav/lib``.
That is fine when the installer package is run as root, but ClamMac unpacks the
engine into the user's Application Support folder, where that path does not
exist.

The usual escape hatch -- ``DYLD_LIBRARY_PATH`` -- is not available: the
binaries are signed with the hardened runtime and no
``com.apple.security.cs.allow-dyld-environment-variables`` entitlement, so
macOS strips ``DYLD_*`` out of the environment before the process starts.

So ClamMac rewrites the run-path in place. ``/usr/local/clamav/lib`` is 21
bytes; ``@loader_path/../lib`` is 19. The replacement is shorter, so it fits in
the space the original occupies with room for the terminating padding, and the
load command's size -- and therefore every file offset after it -- is
unchanged. Nothing moves; only bytes inside one string change.

Editing the file invalidates its code signature, so the caller must re-sign
afterwards (``codesign --force --sign -``). That is handled in
``provisioner.py``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CLAMAV_INSTALL_RPATH",
    "PORTABLE_RPATH",
    "MachOError",
    "SliceInfo",
    "is_macho",
    "read_linked_dylibs",
    "read_rpaths",
    "rewrite_rpath",
]

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE

LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD

_DYLIB_COMMANDS = frozenset(
    {LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB}
)

#: The run-path baked into the official ClamAV macOS package.
CLAMAV_INSTALL_RPATH = "/usr/local/clamav/lib"

#: What ClamMac replaces it with. Resolved relative to the loading binary, so
#: it works from ``bin/``, ``sbin/`` and from one library to another in
#: ``lib/`` -- all three sit one level below the engine root.
PORTABLE_RPATH = "@loader_path/../lib"


class MachOError(Exception):
    """Raised when a file is not a Mach-O image we can safely edit."""


@dataclass(frozen=True)
class SliceInfo:
    """One architecture inside a (possibly universal) Mach-O file."""

    offset: int
    size: int
    cputype: int
    endian: str
    is_64: bool

    @property
    def arch(self) -> str:
        names = {
            0x01000007: "x86_64",
            0x0100000C: "arm64",
            0x00000007: "i386",
            0x0000000C: "arm",
        }
        return names.get(self.cputype, f"cputype-{self.cputype}")


def is_macho(path: Path) -> bool:
    """Cheap check: does this file start with a Mach-O or universal magic?"""
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    if len(head) < 4:
        return False
    value = struct.unpack(">I", head)[0]
    return value in (FAT_MAGIC, FAT_MAGIC_64, MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64)


def _slices(blob: bytes | bytearray) -> list[SliceInfo]:
    """Enumerate the architecture slices in a Mach-O or universal binary."""
    if len(blob) < 8:
        raise MachOError("file is too short to be Mach-O")
    big = struct.unpack_from(">I", blob, 0)[0]

    if big in (FAT_MAGIC, FAT_MAGIC_64):
        wide = big == FAT_MAGIC_64
        count = struct.unpack_from(">I", blob, 4)[0]
        if count > 64:
            raise MachOError("implausible number of architectures")
        out: list[SliceInfo] = []
        cursor = 8
        for _ in range(count):
            if wide:
                cputype, _sub, offset, size, _align, _res = struct.unpack_from(
                    ">2i2Q2I", blob, cursor
                )
                cursor += 32
            else:
                cputype, _sub, offset, size, _align = struct.unpack_from(
                    ">2i3I", blob, cursor
                )
                cursor += 20
            if offset + size > len(blob):
                raise MachOError("architecture slice runs past end of file")
            out.append(_describe(blob, offset, size, cputype))
        return out

    return [_describe(blob, 0, len(blob), None)]


def _describe(blob: bytes | bytearray, offset: int, size: int, cputype: int | None) -> SliceInfo:
    magic_be = struct.unpack_from(">I", blob, offset)[0]
    magic_le = struct.unpack_from("<I", blob, offset)[0]
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        endian, magic = "<", magic_le
    elif magic_be in (MH_MAGIC, MH_MAGIC_64):
        endian, magic = ">", magic_be
    else:
        raise MachOError("slice does not begin with a Mach-O header")
    is_64 = magic == MH_MAGIC_64
    if cputype is None:
        cputype = struct.unpack_from(endian + "i", blob, offset + 4)[0]
    return SliceInfo(offset=offset, size=size, cputype=cputype, endian=endian, is_64=is_64)


def _iter_load_commands(blob: bytes | bytearray, sl: SliceInfo):
    """Yield ``(command, size, absolute_offset)`` for each load command."""
    header = 32 if sl.is_64 else 28
    ncmds, sizeofcmds = struct.unpack_from(sl.endian + "2I", blob, sl.offset + 16)
    if sizeofcmds > sl.size:
        raise MachOError("load commands claim to be larger than the slice")
    cursor = sl.offset + header
    limit = sl.offset + header + sizeofcmds
    for _ in range(ncmds):
        if cursor + 8 > limit:
            raise MachOError("load command table is truncated")
        cmd, cmdsize = struct.unpack_from(sl.endian + "2I", blob, cursor)
        if cmdsize < 8 or cursor + cmdsize > limit:
            raise MachOError("load command has an implausible size")
        yield cmd, cmdsize, cursor
        cursor += cmdsize


def _lc_string(blob: bytes | bytearray, sl: SliceInfo, cursor: int, cmdsize: int) -> tuple[int, str]:
    """Decode an ``lc_str``: returns its absolute offset and its value."""
    str_offset = struct.unpack_from(sl.endian + "I", blob, cursor + 8)[0]
    if str_offset < 8 or str_offset >= cmdsize:
        raise MachOError("load command string offset is out of range")
    start = cursor + str_offset
    raw = bytes(blob[start : cursor + cmdsize])
    return start, raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def read_rpaths(path: Path) -> dict[str, list[str]]:
    """Map architecture name to the list of ``LC_RPATH`` entries it carries."""
    blob = path.read_bytes()
    result: dict[str, list[str]] = {}
    for sl in _slices(blob):
        found: list[str] = []
        for cmd, cmdsize, cursor in _iter_load_commands(blob, sl):
            if cmd == LC_RPATH:
                found.append(_lc_string(blob, sl, cursor, cmdsize)[1])
        result[sl.arch] = found
    return result


def read_linked_dylibs(path: Path) -> dict[str, list[str]]:
    """Map architecture name to the libraries that slice loads."""
    blob = path.read_bytes()
    result: dict[str, list[str]] = {}
    for sl in _slices(blob):
        found: list[str] = []
        for cmd, cmdsize, cursor in _iter_load_commands(blob, sl):
            if cmd in _DYLIB_COMMANDS and cmd != LC_ID_DYLIB:
                found.append(_lc_string(blob, sl, cursor, cmdsize)[1])
        result[sl.arch] = found
    return result


def rewrite_rpath(
    path: Path,
    old: str = CLAMAV_INSTALL_RPATH,
    new: str = PORTABLE_RPATH,
) -> int:
    """Replace an ``LC_RPATH`` value in place, across every architecture.

    Returns the number of run-path entries changed; zero means the file did not
    reference ``old`` and was left untouched. The file's length and every load
    command's size are preserved, so no offset in the image moves.

    Raises ``MachOError`` if ``new`` cannot fit in the space ``old`` occupies,
    which would require relocating the load commands -- deliberately out of
    scope here.
    """
    new_bytes = new.encode("utf-8")
    old_bytes = old.encode("utf-8")
    if len(new_bytes) > len(old_bytes):
        raise MachOError(
            f"replacement run-path {new!r} ({len(new_bytes)} bytes) does not fit "
            f"in {old!r} ({len(old_bytes)} bytes)"
        )

    blob = bytearray(path.read_bytes())
    changes = 0
    for sl in _slices(blob):
        for cmd, cmdsize, cursor in _iter_load_commands(blob, sl):
            if cmd != LC_RPATH:
                continue
            start, value = _lc_string(blob, sl, cursor, cmdsize)
            if value != old:
                continue
            end = cursor + cmdsize
            # Overwrite the whole tail of the command so no trailing bytes of
            # the previous value survive; the string is NUL-terminated and the
            # remainder is padding, exactly as the linker emitted it.
            blob[start:end] = new_bytes + b"\x00" * (end - start - len(new_bytes))
            changes += 1

    if changes:
        path.write_bytes(bytes(blob))
    return changes
