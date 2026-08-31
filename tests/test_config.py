"""Settings: defaults, round-tripping, and refusing to break on bad input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clammac.core import config
from clammac.core.config import (
    Exclusions,
    Frequency,
    ScanDepth,
    Settings,
    Theme,
    ThreatAction,
)


class TestRoundTrip:
    def test_defaults_survive_a_save_and_load(self, tmp_path):
        target = tmp_path / "settings.json"
        config.save(Settings(), target)
        assert config.load(target).to_dict() == Settings().to_dict()

    def test_enums_come_back_as_enums(self, tmp_path):
        target = tmp_path / "settings.json"
        original = Settings()
        original.scan.on_threat = ThreatAction.DELETE
        original.interface.theme = Theme.DARK
        original.updates.frequency = Frequency.WEEKLY
        config.save(original, target)

        loaded = config.load(target)
        assert loaded.scan.on_threat is ThreatAction.DELETE
        assert loaded.interface.theme is Theme.DARK
        assert loaded.updates.frequency is Frequency.WEEKLY

    def test_saved_file_is_readable_json_with_plain_values(self, tmp_path):
        target = tmp_path / "settings.json"
        config.save(Settings(), target)
        raw = json.loads(target.read_text())
        assert raw["scan"]["on_threat"] == "quarantine"
        assert raw["interface"]["theme"] == "system"

    def test_settings_file_is_not_world_readable(self, tmp_path):
        target = tmp_path / "settings.json"
        config.save(Settings(), target)
        assert target.stat().st_mode & 0o077 == 0


class TestResilience:
    """A bad settings file must never stop the application from starting."""

    def test_missing_file_gives_defaults(self, tmp_path):
        assert config.load(tmp_path / "absent.json").scan.depth is ScanDepth.BALANCED

    @pytest.mark.parametrize("body", ["{ not json", "[]", "null", '"a string"', ""])
    def test_malformed_files_give_defaults(self, tmp_path, body):
        target = tmp_path / "settings.json"
        target.write_text(body)
        assert config.load(target).to_dict() == Settings().to_dict()

    def test_unknown_keys_are_ignored(self, tmp_path):
        target = tmp_path / "settings.json"
        target.write_text(json.dumps({"nonsense": 1, "scan": {"invented": True}}))
        assert config.load(target).scan.depth is ScanDepth.BALANCED

    def test_wrong_types_fall_back_per_field(self, tmp_path):
        target = tmp_path / "settings.json"
        target.write_text(
            json.dumps(
                {
                    "scan": {"max_files": "not a number", "depth": "invented", "max_recursion": 9},
                    "exclusions": {"paths": "not a list"},
                }
            )
        )
        loaded = config.load(target)
        assert loaded.scan.max_files == Settings().scan.max_files
        assert loaded.scan.depth is ScanDepth.BALANCED
        assert loaded.exclusions.paths == []
        # A field that *is* valid alongside broken ones still applies.
        assert loaded.scan.max_recursion == 9

    def test_numeric_strings_are_coerced(self, tmp_path):
        target = tmp_path / "settings.json"
        target.write_text(json.dumps({"scan": {"max_files": "7000"}}))
        assert config.load(target).scan.max_files == 7000


class TestDepthPresets:
    def test_thorough_raises_every_limit_above_fast(self):
        fast = Settings().scan
        fast.depth = ScanDepth.FAST
        fast.apply_depth()
        thorough = Settings().scan
        thorough.depth = ScanDepth.THOROUGH
        thorough.apply_depth()

        assert thorough.max_file_size_mb > fast.max_file_size_mb
        assert thorough.max_scan_size_mb > fast.max_scan_size_mb
        assert thorough.max_recursion > fast.max_recursion
        assert thorough.max_files > fast.max_files
        assert thorough.alert_encrypted and not fast.alert_encrypted


class TestExclusions:
    def test_matches_a_folder_and_everything_under_it(self, tmp_path):
        rules = Exclusions(paths=[str(tmp_path / "Music")])
        assert rules.excluded(tmp_path / "Music")
        assert rules.excluded(tmp_path / "Music" / "album" / "track.flac")

    def test_does_not_match_a_sibling_with_a_shared_prefix(self, tmp_path):
        """~/Music must not exclude ~/MusicVideos."""
        rules = Exclusions(paths=[str(tmp_path / "Music")])
        assert not rules.excluded(tmp_path / "MusicVideos" / "clip.mp4")

    @pytest.mark.parametrize("name", ["film.mp4", "FILM.MP4", "clip.Mp4"])
    def test_extension_matching_ignores_case(self, name):
        assert Exclusions(extensions=["mp4"]).excluded(Path("/x") / name)

    def test_leading_dots_on_extensions_are_accepted(self):
        assert Exclusions(extensions=[".iso"]).excluded(Path("/x/disk.iso"))

    def test_nothing_is_excluded_by_default(self):
        assert not Exclusions().excluded(Path("/anywhere/at/all.exe"))

    def test_expands_a_tilde(self):
        rules = Exclusions(paths=["~/Music"])
        assert rules.excluded(Path.home() / "Music" / "x.flac")


class TestProtectionPaths:
    def test_home_supersedes_the_individual_folders(self, monkeypatch, tmp_path):
        monkeypatch.setattr("clammac.core.paths.home", lambda: tmp_path)
        (tmp_path / "Downloads").mkdir()
        (tmp_path / "Desktop").mkdir()

        settings = Settings().protection
        settings.watch_home = True
        settings.watch_removable = False
        assert settings.watched_paths() == [tmp_path]

    def test_skips_folders_that_do_not_exist(self, monkeypatch, tmp_path):
        monkeypatch.setattr("clammac.core.paths.home", lambda: tmp_path)
        (tmp_path / "Downloads").mkdir()

        settings = Settings().protection
        settings.watch_removable = False
        assert settings.watched_paths() == [tmp_path / "Downloads"]

    def test_does_not_repeat_a_folder_listed_twice(self, monkeypatch, tmp_path):
        monkeypatch.setattr("clammac.core.paths.home", lambda: tmp_path)
        (tmp_path / "Downloads").mkdir()

        settings = Settings().protection
        settings.watch_removable = False
        settings.extra_paths = [str(tmp_path / "Downloads")]
        assert settings.watched_paths() == [tmp_path / "Downloads"]


class TestRemovedSettings:
    """Three settings were declared but never read by anything.

    A setting the code never consults is worse than absent: it looks like a
    knob, saves and reloads like a knob, and does nothing. ``sound_on_threat``
    was the same and got an implementation instead; these three had no
    plausible one, so they went.
    """

    @pytest.mark.parametrize(
        ("owner", "name"),
        [
            ("schedule", "only_when_idle"),
            ("interface", "start_minimised"),
            ("exclusions", "skip_larger_than_mb"),
        ],
    )
    def test_the_setting_is_gone(self, owner, name):
        section = getattr(config.Settings(), owner)
        assert not hasattr(section, name)

    def test_an_old_settings_file_still_loads(self, tmp_path):
        """Removing a field must not break a file written by 1.0.0."""
        target = tmp_path / "settings.json"
        target.write_text(
            json.dumps(
                {
                    "schedule": {"only_when_idle": True, "hour": 4},
                    "interface": {"start_minimised": True, "notifications": False},
                    "exclusions": {"skip_larger_than_mb": 500, "extensions": ["iso"]},
                }
            )
        )
        settings = config.load(target)
        assert settings.schedule.hour == 4
        assert settings.interface.notifications is False
        assert settings.exclusions.extensions == ["iso"]
