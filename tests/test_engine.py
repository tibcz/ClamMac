"""Locating ClamAV, and turning settings into a command line."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from clammac.core import engine
from clammac.core.config import Settings


class TestVersionParsing:
    def test_full_banner(self):
        tools = engine.EngineTools(Path("/x"), Path("/x/clamscan"), Path("/x/freshclam"))
        info = engine._parse_version(tools, "ClamAV 1.5.4/27700/Fri Aug 28 08:25:07 2026")
        assert info.engine_version == "1.5.4"
        assert info.database_version == 27700
        assert info.database_date.tzinfo is UTC
        assert info.has_database

    def test_banner_without_a_database(self):
        tools = engine.EngineTools(Path("/x"), Path("/x/clamscan"), Path("/x/freshclam"))
        info = engine._parse_version(tools, "ClamAV 1.5.4")
        assert info.engine_version == "1.5.4"
        assert not info.has_database

    def test_unrecognisable_banner_is_kept_verbatim(self):
        tools = engine.EngineTools(Path("/x"), Path("/x/clamscan"), Path("/x/freshclam"))
        info = engine._parse_version(tools, "something else entirely")
        assert info.engine_version == "something else entirely"


class TestCommandBuilding:
    def _command(self, settings, targets=None):
        tools = engine.EngineTools(Path("/x"), Path("/x/clamscan"), Path("/x/freshclam"))
        return engine.build_scan_command(tools, targets or [Path("/scan/me")], settings)

    def test_includes_the_database_and_the_target(self, settings):
        command = self._command(settings)
        assert command[0] == "/x/clamscan"
        assert any(part.startswith("--database=") for part in command)
        assert command[-1] == "/scan/me"

    def test_never_lets_the_scanner_touch_files_itself(self, settings):
        """ClamMac applies the user's chosen action, with a record of it."""
        command = " ".join(self._command(settings))
        assert "--remove" not in command
        assert "--move" not in command
        assert "--copy" not in command

    def test_always_excludes_the_quarantine(self, settings):
        """Rescanning quarantine would re-flag files already dealt with."""
        import re

        from clammac.core import paths

        command = " ".join(self._command(settings))
        assert f"--exclude-dir=^{re.escape(str(paths.quarantine_dir()))}" in command

    def test_limits_come_from_settings(self, settings):
        settings.scan.max_file_size_mb = 42
        settings.scan.max_recursion = 7
        command = self._command(settings)
        assert "--max-filesize=42M" in command
        assert "--max-recursion=7" in command

    @pytest.mark.parametrize("enabled", [True, False])
    def test_format_toggles_are_passed_through(self, settings, enabled):
        settings.scan.scan_archives = enabled
        assert f"--scan-archive={'yes' if enabled else 'no'}" in self._command(settings)

    def test_path_exclusions_become_anchored_regexes(self, settings):
        settings.exclusions.paths = ["/private/stuff"]
        command = self._command(settings)
        assert "--exclude=^/private/stuff" in command
        assert "--exclude-dir=^/private/stuff" in command

    def test_regex_metacharacters_in_paths_are_escaped(self, settings):
        """An unescaped '.' or '+' would silently widen the exclusion."""
        settings.exclusions.paths = ["/a+b/c.d"]
        command = " ".join(self._command(settings))
        assert r"/a\+b/c\.d" in command

    def test_extension_exclusions_anchor_at_the_end(self, settings):
        settings.exclusions.extensions = ["iso"]
        assert r"--exclude=\.iso$" in self._command(settings)

    def test_multiple_targets_all_appear(self, settings):
        command = self._command(settings, [Path("/a"), Path("/b")])
        assert command[-2:] == ["/a", "/b"]


class TestGeneratedConfigs:
    def test_freshclam_conf_points_at_our_database(self, tmp_path):
        written = engine.write_freshclam_conf(tmp_path / "db")
        body = written.read_text()
        assert f"DatabaseDirectory {tmp_path / 'db'}" in body
        # ClamAV ships its sample with an "Example" line that makes the tools
        # refuse to start; ours must not carry it over.
        assert "\nExample" not in body

    def test_clamd_conf_is_private_and_uses_our_socket(self, tmp_path, settings):
        written = engine.write_clamd_conf(tmp_path / "db", settings=settings)
        assert written.stat().st_mode & 0o077 == 0
        body = written.read_text()
        assert "LocalSocket " in body
        assert "LocalSocketMode 600" in body
        assert "\nExample" not in body

    def test_clamd_conf_reflects_scan_settings(self, tmp_path, settings):
        settings.scan.detect_pua = True
        settings.scan.max_files = 1234
        body = engine.write_clamd_conf(tmp_path / "db", settings=settings).read_text()
        assert "DetectPUA yes" in body
        assert "MaxFiles 1234" in body


class TestDatabaseInfo:
    def test_absent_directory(self, tmp_path):
        info = engine.database_info(tmp_path / "nothing")
        assert not info.present
        assert info.age_days() is None
        assert info.is_stale(3)

    def test_counts_only_database_files(self, tmp_path):
        (tmp_path / "daily.cvd").write_bytes(b"x" * 100)
        (tmp_path / "main.cvd").write_bytes(b"y" * 200)
        (tmp_path / "notes.txt").write_text("ignore me")
        info = engine.database_info(tmp_path)
        assert len(info.files) == 2
        assert info.total_bytes == 300
        assert not info.is_stale(3)


class TestEnvironment:
    def test_dynamic_loader_variables_are_stripped(self, monkeypatch):
        """Qt's own DYLD settings must not leak into the scanner."""
        monkeypatch.setenv("DYLD_LIBRARY_PATH", "/qt/lib")
        monkeypatch.setenv("QT_PLUGIN_PATH", "/qt/plugins")
        monkeypatch.setenv("PATH", "/usr/bin")
        cleaned = engine._clean_env()
        assert "DYLD_LIBRARY_PATH" not in cleaned
        assert "QT_PLUGIN_PATH" not in cleaned
        assert cleaned["PATH"] == "/usr/bin"


class TestDiscovery:
    def test_returns_none_when_nothing_is_installed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(engine, "SEARCH_PREFIXES", (tmp_path / "nowhere",))
        monkeypatch.setattr(engine.shutil, "which", lambda _: None)
        assert engine.discover(Settings()) is None

    def test_skips_a_clamscan_that_cannot_run(self, monkeypatch, tmp_path):
        """A broken Homebrew link must be stepped over, not reported."""
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        broken = fake_bin / "clamscan"
        broken.write_text("#!/bin/sh\nexit 127\n")
        broken.chmod(0o755)
        (fake_bin / "freshclam").write_text("")

        monkeypatch.setattr(engine, "SEARCH_PREFIXES", (fake_bin,))
        monkeypatch.setattr(engine.shutil, "which", lambda _: None)
        assert engine.discover(Settings()) is None
