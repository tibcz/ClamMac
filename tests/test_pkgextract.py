"""Reading Apple flat packages without Apple's tools."""

from __future__ import annotations

import io
import stat

import pytest
from conftest import build_cpio

from clammac.core.pkgextract import (
    PackageError,
    XarArchive,
    extract_payload,
    iter_cpio,
)


class TestXar:
    def test_reads_the_table_of_contents(self, package_factory):
        with XarArchive(package_factory()) as archive:
            payloads = archive.component_payloads()
        assert len(payloads) == 2
        assert all(p.path.endswith("/Payload") for p in payloads)

    def test_rejects_a_file_that_is_not_a_xar(self, tmp_path):
        bogus = tmp_path / "nope.pkg"
        bogus.write_bytes(b"this is not a package at all")
        with pytest.raises(PackageError, match="bad magic"):
            XarArchive(bogus).open()

    def test_rejects_a_truncated_file(self, tmp_path):
        short = tmp_path / "short.pkg"
        short.write_bytes(b"xar!")
        with pytest.raises(PackageError, match="too short"):
            XarArchive(short).open()

    def test_streams_a_payload(self, package_factory):
        with XarArchive(package_factory()) as archive:
            payload = archive.component_payloads()[0]
            with archive.stream(payload) as handle:
                names = [entry.name for entry in iter_cpio(handle)]
        assert any(name.endswith("bin/clamscan") for name in names)


class TestCpio:
    def test_parses_files_directories_and_symlinks(self):
        raw = build_cpio(
            [
                ("./dir", 0o040755, b""),
                ("./dir/file.txt", 0o100644, b"hello"),
                ("./dir/link", 0o120777, b"file.txt"),
            ]
        )
        entries = list(iter_cpio(io.BytesIO(raw)))
        assert [e.name for e in entries] == ["./dir", "./dir/file.txt", "./dir/link"]
        assert entries[0].is_dir
        assert entries[1].is_file and entries[1].data == b"hello"
        assert entries[2].is_symlink and entries[2].link_target == "file.txt"

    def test_stops_at_the_trailer(self):
        raw = build_cpio([("./a", 0o100644, b"x")]) + b"trailing rubbish"
        assert len(list(iter_cpio(io.BytesIO(raw)))) == 1

    def test_want_skips_payloads_without_reading_them(self):
        raw = build_cpio(
            [("./keep.txt", 0o100644, b"K" * 100), ("./skip.bin", 0o100644, b"S" * 100)]
        )
        entries = {e.name: e for e in iter_cpio(io.BytesIO(raw), want=lambda n, m: "keep" in n)}
        assert entries["./keep.txt"].data == b"K" * 100
        assert entries["./skip.bin"].data is None
        # The size is still reported even though the bytes were discarded.
        assert entries["./skip.bin"].size == 100

    def test_rejects_an_unknown_format(self):
        with pytest.raises(PackageError, match="unsupported cpio format"):
            list(iter_cpio(io.BytesIO(b"999999" + b"\x00" * 200)))


class TestExtract:
    def test_flattens_the_prefix_and_rebuilds_symlinks(self, tmp_path):
        prefix = "./usr/local/clamav"
        raw = build_cpio(
            [
                (f"{prefix}/bin", 0o040755, b""),
                (f"{prefix}/bin/clamscan", 0o100755, b"binary"),
                (f"{prefix}/lib", 0o040755, b""),
                (f"{prefix}/lib/lib.1.dylib", 0o100755, b"library"),
                (f"{prefix}/lib/lib.dylib", 0o120777, b"lib.1.dylib"),
            ]
        )
        destination = tmp_path / "engine"
        extract_payload(io.BytesIO(raw), destination, strip_prefix="usr/local/clamav")

        assert (destination / "bin" / "clamscan").read_bytes() == b"binary"
        assert (destination / "lib" / "lib.dylib").is_symlink()
        assert (destination / "lib" / "lib.dylib").readlink().name == "lib.1.dylib"
        assert not (destination / "usr").exists()

    def test_preserves_the_executable_bit(self, tmp_path):
        raw = build_cpio([("./bin/tool", 0o100755, b"x"), ("./data.txt", 0o100644, b"y")])
        destination = tmp_path / "out"
        extract_payload(io.BytesIO(raw), destination)
        assert destination.joinpath("bin/tool").stat().st_mode & stat.S_IXUSR
        assert not destination.joinpath("data.txt").stat().st_mode & stat.S_IXUSR

    def test_nothing_extracted_is_group_or_world_writable(self, tmp_path):
        raw = build_cpio([("./wide", 0o100777, b"x")])
        destination = tmp_path / "out"
        extract_payload(io.BytesIO(raw), destination)
        mode = destination.joinpath("wide").stat().st_mode
        assert not mode & (stat.S_IWGRP | stat.S_IWOTH)

    @pytest.mark.parametrize("name", ["../escape.txt", "./bin/../../escape.txt"])
    def test_refuses_members_that_escape_the_destination(self, tmp_path, name):
        """A package is untrusted input; path traversal must not be possible."""
        raw = build_cpio([(name, 0o100644, b"owned")])
        destination = tmp_path / "out"
        with pytest.raises(PackageError, match="escapes the destination"):
            extract_payload(io.BytesIO(raw), destination)
        assert not (tmp_path / "escape.txt").exists()

    def test_anchors_absolute_members_inside_the_destination(self, tmp_path):
        """An absolute member name is made relative rather than obeyed.

        This is the behaviour tar has without -P: a package claiming to write
        /etc/passwd lands harmlessly under the destination instead.
        """
        raw = build_cpio([("/etc/passwd", 0o100644, b"owned")])
        destination = tmp_path / "out"
        extract_payload(io.BytesIO(raw), destination)
        assert (destination / "etc" / "passwd").read_bytes() == b"owned"

    def test_filter_excludes_unwanted_members(self, tmp_path):
        from clammac.core.provisioner import PAYLOAD_PREFIX, EngineProvisioner

        prefix = "./usr/local/clamav"
        raw = build_cpio(
            [
                (f"{prefix}/lib/libclamav.dylib", 0o100755, b"keep"),
                (f"{prefix}/lib/libclamav_rust.a", 0o100644, b"X" * 4096),
                (f"{prefix}/include/clamav.h", 0o100644, b"header"),
                (f"{prefix}/bin/clamsubmit", 0o100755, b"unused tool"),
            ]
        )
        destination = tmp_path / "out"
        extract_payload(
            io.BytesIO(raw),
            destination,
            strip_prefix=PAYLOAD_PREFIX,
            want=EngineProvisioner._wanted,
        )
        assert (destination / "lib" / "libclamav.dylib").exists()
        # The 462 MB static archive is the whole reason the filter exists.
        assert not (destination / "lib" / "libclamav_rust.a").exists()
        assert not (destination / "include" / "clamav.h").exists()
        assert not (destination / "bin" / "clamsubmit").exists()

    def test_extraction_is_repeatable(self, tmp_path):
        raw = build_cpio([("./a.txt", 0o100644, b"first")])
        destination = tmp_path / "out"
        extract_payload(io.BytesIO(raw), destination)
        extract_payload(io.BytesIO(raw), destination)
        assert (destination / "a.txt").read_bytes() == b"first"
