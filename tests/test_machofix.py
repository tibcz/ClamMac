"""Rewriting the run-path of a Mach-O image in place."""

from __future__ import annotations

import pytest
from conftest import CPU_ARM64, CPU_X86_64

from clammac.core.machofix import (
    CLAMAV_INSTALL_RPATH,
    PORTABLE_RPATH,
    MachOError,
    is_macho,
    read_linked_dylibs,
    read_rpaths,
    rewrite_rpath,
)


def test_the_replacement_fits_in_the_original():
    """The whole approach depends on this, so assert it rather than assume it."""
    assert len(PORTABLE_RPATH) <= len(CLAMAV_INSTALL_RPATH)


class TestReading:
    def test_recognises_thin_and_fat_images(self, macho_factory):
        assert is_macho(macho_factory(fat=False))
        assert is_macho(macho_factory(fat=True))

    def test_ignores_other_files(self, tmp_path):
        plain = tmp_path / "notes.txt"
        plain.write_text("just some text")
        assert not is_macho(plain)
        assert not is_macho(tmp_path / "missing")

    def test_reads_rpaths_from_every_architecture(self, macho_factory):
        found = read_rpaths(macho_factory(fat=True))
        assert set(found) == {"x86_64", "arm64"}
        assert all(paths == [CLAMAV_INSTALL_RPATH] for paths in found.values())

    def test_reads_linked_libraries(self, macho_factory):
        image = macho_factory(dylibs=("@rpath/libclamav.12.dylib", "/usr/lib/libSystem.B.dylib"))
        assert read_linked_dylibs(image)["x86_64"] == [
            "@rpath/libclamav.12.dylib",
            "/usr/lib/libSystem.B.dylib",
        ]


class TestRewriting:
    def test_rewrites_every_architecture(self, macho_factory):
        image = macho_factory(fat=True)
        assert rewrite_rpath(image) == 2
        assert read_rpaths(image) == {"x86_64": [PORTABLE_RPATH], "arm64": [PORTABLE_RPATH]}

    def test_file_size_is_unchanged(self, macho_factory):
        """Nothing may move: offsets elsewhere in the image depend on it."""
        image = macho_factory(fat=True)
        before = image.stat().st_size
        rewrite_rpath(image)
        assert image.stat().st_size == before

    def test_only_the_run_path_bytes_change(self, macho_factory):
        image = macho_factory(fat=False)
        before = image.read_bytes()
        rewrite_rpath(image)
        after = image.read_bytes()
        assert len(before) == len(after)
        differing = [i for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b]
        # Confined to one contiguous run no longer than the original string.
        assert differing
        assert max(differing) - min(differing) < len(CLAMAV_INSTALL_RPATH)

    def test_the_image_still_parses_afterwards(self, macho_factory):
        image = macho_factory(fat=True)
        rewrite_rpath(image)
        assert read_linked_dylibs(image)["arm64"] == ["@rpath/libclamav.12.dylib"]

    def test_is_idempotent(self, macho_factory):
        image = macho_factory(fat=True)
        assert rewrite_rpath(image) == 2
        assert rewrite_rpath(image) == 0

    def test_leaves_unrelated_run_paths_alone(self, macho_factory):
        image = macho_factory(fat=False, rpaths=("/opt/homebrew/lib",))
        assert rewrite_rpath(image) == 0
        assert read_rpaths(image)["x86_64"] == ["/opt/homebrew/lib"]

    def test_rewrites_only_the_matching_entry(self, macho_factory):
        image = macho_factory(fat=False, rpaths=("/opt/other/lib", CLAMAV_INSTALL_RPATH))
        assert rewrite_rpath(image) == 1
        assert read_rpaths(image)["x86_64"] == ["/opt/other/lib", PORTABLE_RPATH]

    def test_refuses_a_replacement_that_does_not_fit(self, macho_factory):
        image = macho_factory(fat=False)
        with pytest.raises(MachOError, match="does not fit"):
            rewrite_rpath(image, CLAMAV_INSTALL_RPATH, "/a/very/much/longer/replacement/path/lib")

    def test_rejects_a_file_that_is_not_macho(self, tmp_path):
        plain = tmp_path / "text"
        plain.write_text("not mach-o at all, but long enough to read")
        with pytest.raises(MachOError):
            rewrite_rpath(plain)

    def test_handles_a_three_architecture_image(self, macho_factory):
        image = macho_factory(fat=True, architectures=(CPU_X86_64, CPU_ARM64, 0x0000000C))
        assert rewrite_rpath(image) == 3
