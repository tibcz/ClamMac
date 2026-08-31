"""Shared fixtures.

The interesting ones build synthetic Mach-O images and Apple flat packages in
memory. Committing real binaries as fixtures would mean checking a hundred
megabytes of someone else's signed code into the repository; constructing them
here keeps the tests fast, hermetic, and readable -- and the builders double as
documentation of the formats ClamMac parses.
"""

from __future__ import annotations

import gzip
import struct
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_CLAMSCAN = FIXTURES / "fake_clamscan.py"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point every ClamMac path at a throwaway directory.

    Autouse: a test that accidentally wrote to the real Application Support
    folder would be both surprising and destructive.
    """
    monkeypatch.setenv("CLAMMAC_HOME", str(tmp_path / "clammac-home"))
    from clammac.core import paths

    paths.ensure_tree()
    return tmp_path


@pytest.fixture
def settings():
    from clammac.core.config import Settings

    return Settings()


@pytest.fixture
def engine_tools():
    """An EngineTools pointing at the stub scanner."""
    from clammac.core.engine import EngineTools

    return EngineTools(
        root=FAKE_CLAMSCAN.parent,
        clamscan=FAKE_CLAMSCAN,
        freshclam=FAKE_CLAMSCAN,
        clamd=FAKE_CLAMSCAN,
        clamdscan=FAKE_CLAMSCAN,
    )


@pytest.fixture
def sample_tree(tmp_path):
    """A directory with clean files, one detection, and one unreadable file."""
    root = tmp_path / "tree"
    (root / "nested").mkdir(parents=True)
    for index in range(6):
        (root / f"clean{index}.txt").write_text("harmless\n")
    (root / "nested" / "totally-infected.exe").write_text("payload\n")
    (root / "nested" / "unreadable.bin").write_text("locked\n")
    return root


# --------------------------------------------------------------------------
# Mach-O builder
# --------------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_RPATH = 0x8000001C
LC_LOAD_DYLIB = 0x0C
CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C


def _load_command(cmd: int, payload: bytes) -> bytes:
    """Build one load command whose string starts right after the header."""
    # cmd, cmdsize, str_offset, then the NUL-terminated string, 8-byte aligned.
    header = 12
    size = header + len(payload) + 1
    size += (-size) % 8
    body = struct.pack("<3I", cmd, size, header) + payload + b"\x00"
    return body + b"\x00" * (size - len(body))


def build_thin_macho(
    *,
    cputype: int = CPU_X86_64,
    rpaths: tuple[str, ...] = ("/usr/local/clamav/lib",),
    dylibs: tuple[str, ...] = ("@rpath/libclamav.12.dylib",),
    padding: int = 512,
) -> bytes:
    """A minimal but structurally valid 64-bit Mach-O image."""
    commands = b"".join(_load_command(LC_RPATH, p.encode()) for p in rpaths)
    commands += b"".join(_load_command(LC_LOAD_DYLIB, d.encode()) for d in dylibs)
    ncmds = len(rpaths) + len(dylibs)
    header = struct.pack(
        "<7I",
        MH_MAGIC_64,
        cputype,
        3,  # cpusubtype
        2,  # MH_EXECUTE
        ncmds,
        len(commands),
        0x00200085,  # flags
    ) + struct.pack("<I", 0)  # reserved
    return header + commands + b"\x00" * padding


def build_fat_macho(
    *,
    rpaths: tuple[str, ...] = ("/usr/local/clamav/lib",),
    architectures: tuple[int, ...] = (CPU_X86_64, CPU_ARM64),
    **thin_kwargs,
) -> bytes:
    """A universal binary wrapping several thin images, page aligned."""
    slices = [
        build_thin_macho(cputype=arch, rpaths=rpaths, **thin_kwargs) for arch in architectures
    ]
    align = 0x4000
    header_size = 8 + 20 * len(slices)
    offset = header_size + (-header_size % align)

    entries, blob, cursor = b"", b"", offset
    for arch, image in zip(architectures, slices, strict=True):
        entries += struct.pack(">2i3I", arch, 3, cursor, len(image), 14)
        padded = image + b"\x00" * ((-len(image)) % align)
        blob += padded
        cursor += len(padded)

    head = struct.pack(">2I", FAT_MAGIC, len(slices)) + entries
    return head + b"\x00" * (offset - len(head)) + blob


@pytest.fixture
def macho_factory(tmp_path):
    """Write synthetic Mach-O files to disk and return their paths."""
    counter = {"n": 0}

    def make(fat: bool = True, **kwargs) -> Path:
        counter["n"] += 1
        data = build_fat_macho(**kwargs) if fat else build_thin_macho(**kwargs)
        target = tmp_path / f"macho{counter['n']}"
        target.write_bytes(data)
        return target

    return make


# --------------------------------------------------------------------------
# Apple flat package builder
# --------------------------------------------------------------------------


def build_cpio(entries: list[tuple[str, int, bytes]]) -> bytes:
    """Build a newc-format cpio archive from (name, mode, data) triples."""
    out = b""
    for index, (name, mode, data) in enumerate(entries, start=1):
        raw_name = name.encode() + b"\x00"
        fields = [
            index,        # ino
            mode,
            0, 0, 1,      # uid, gid, nlink
            0,            # mtime
            len(data),
            0, 0, 0, 0,   # dev/rdev
            len(raw_name),
            0,            # check
        ]
        header = b"070701" + b"".join(b"%08x" % value for value in fields)
        block = header + raw_name
        block += b"\x00" * ((-len(block)) % 4)
        block += data
        block += b"\x00" * ((-len(data)) % 4)
        out += block

    trailer_name = b"TRAILER!!!\x00"
    fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer_name), 0]
    header = b"070701" + b"".join(b"%08x" % value for value in fields)
    block = header + trailer_name
    block += b"\x00" * ((-len(block)) % 4)
    return out + block


def build_flat_package(components: dict[str, list[tuple[str, int, bytes]]]) -> bytes:
    """Build a xar archive holding one gzipped cpio payload per component."""
    heap, files = b"", []
    for name, entries in components.items():
        payload = gzip.compress(build_cpio(entries))
        files.append((f"{name}.pkg/Payload", len(heap), len(payload)))
        heap += payload

    members = "".join(
        f"<file id='{index}'><name>{path.split('/')[0]}</name><type>directory</type>"
        f"<file id='{index}00'><name>Payload</name><type>file</type>"
        f"<data><offset>{offset}</offset><length>{length}</length>"
        f"<size>{length}</size>"
        f"<encoding style='application/octet-stream'/></data></file></file>"
        for index, (path, offset, length) in enumerate(files, start=1)
    )
    toc = f"<?xml version='1.0'?><xar><toc>{members}</toc></xar>".encode()
    compressed = zlib.compress(toc)

    header = struct.pack(">IHHQQI", 0x78617221, 28, 1, len(compressed), len(toc), 1)
    return header + compressed + heap


@pytest.fixture
def package_factory(tmp_path):
    """Write a synthetic .pkg containing a ClamAV-shaped payload."""

    def make(name: str = "test.pkg", *, components=None) -> Path:
        if components is None:
            prefix = "./usr/local/clamav"
            components = {
                "programs": [
                    (".", 0o040755, b""),
                    (f"{prefix}/bin", 0o040755, b""),
                    (f"{prefix}/bin/clamscan", 0o100755, build_fat_macho()),
                    (f"{prefix}/bin/freshclam", 0o100755, build_fat_macho()),
                    (f"{prefix}/sbin", 0o040755, b""),
                    (f"{prefix}/sbin/clamd", 0o100755, build_fat_macho()),
                    (f"{prefix}/etc", 0o040755, b""),
                    (f"{prefix}/etc/clamd.conf.sample", 0o100644, b"# sample\n"),
                ],
                "libraries": [
                    (f"{prefix}/lib", 0o040755, b""),
                    (f"{prefix}/lib/libclamav.12.1.0.dylib", 0o100755, build_fat_macho()),
                    (f"{prefix}/lib/libclamav.12.dylib", 0o120755, b"libclamav.12.1.0.dylib"),
                    (f"{prefix}/lib/libclamav_rust.a", 0o100644, b"X" * 4096),
                    (f"{prefix}/include", 0o040755, b""),
                    (f"{prefix}/include/clamav.h", 0o100644, b"/* header */"),
                ],
            }
        target = tmp_path / name
        target.write_bytes(build_flat_package(components))
        return target

    return make
