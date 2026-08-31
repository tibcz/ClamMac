"""Notifications, and the sound the settings screen has always promised."""

from __future__ import annotations

import pytest

from clammac.core.notifications import Notification, Notifier, Urgency


@pytest.fixture
def notifier():
    return Notifier()


class TestSoundOnThreat:
    """The settings screen offers "Play a sound when a threat is found".

    It used to be stored and then consulted by nothing at all, so the
    checkbox did nothing whichever way it was set. These pin the wiring.
    """

    def _capture(self, notifier, monkeypatch):
        played: list[str] = []
        monkeypatch.setattr(
            "clammac.core.notifications._play_alert",
            lambda *a, **k: played.append("alert") or True,
        )
        # A backend that succeeds, so the osascript path is not taken.
        notifier.set_backend(lambda _n: True)
        return played

    def test_a_detection_makes_a_noise(self, notifier, monkeypatch):
        played = self._capture(notifier, monkeypatch)
        notifier.set_sound_enabled(True)
        notifier.threat("Threat blocked", "eicar.com was detected.")
        assert played == ["alert"]

    def test_turning_the_setting_off_silences_it(self, notifier, monkeypatch):
        played = self._capture(notifier, monkeypatch)
        notifier.set_sound_enabled(False)
        notifier.threat("Threat blocked", "eicar.com was detected.")
        assert played == []

    @pytest.mark.parametrize("urgency", [Urgency.INFO, Urgency.WARNING])
    def test_ordinary_notifications_stay_quiet(self, notifier, monkeypatch, urgency):
        """Only a detection is worth interrupting someone audibly."""
        played = self._capture(notifier, monkeypatch)
        notifier.set_sound_enabled(True)
        notifier.post(Notification("Definitions updated", "All current.", urgency))
        assert played == []

    def test_the_sound_is_not_played_twice(self, notifier, monkeypatch):
        """osascript carries the sound itself, so it must not also be played.

        When no backend is installed the notification goes out through
        osascript, which is asked for the sound inline.
        """
        played: list[str] = []
        scripts: list[str] = []
        monkeypatch.setattr(
            "clammac.core.notifications._play_alert",
            lambda *a, **k: played.append("alert") or True,
        )
        monkeypatch.setattr(
            "clammac.core.notifications._post_via_osascript",
            lambda n, sound=False: scripts.append(sound) or True,
        )
        notifier.set_sound_enabled(True)
        notifier.threat("Threat blocked", "eicar.com was detected.")
        assert scripts == [True], "osascript should be asked to carry the sound"
        assert played == [], "and the alert should not also be played separately"

    def test_a_failing_backend_falls_through_with_the_sound(self, notifier, monkeypatch):
        scripts: list[bool] = []
        monkeypatch.setattr(
            "clammac.core.notifications._post_via_osascript",
            lambda n, sound=False: scripts.append(sound) or True,
        )
        notifier.set_backend(lambda _n: False)
        notifier.set_sound_enabled(True)
        notifier.threat("Threat blocked", "eicar.com was detected.")
        assert scripts == [True]

    def test_notifications_off_means_nothing_at_all(self, notifier, monkeypatch):
        played = self._capture(notifier, monkeypatch)
        notifier.set_enabled(False)
        notifier.set_sound_enabled(True)
        assert notifier.threat("Threat blocked", "x") is False
        assert played == []

    def test_the_default_is_on(self, notifier):
        assert notifier.sound_enabled is True


class TestServiceWiring:
    """The setting has to reach the notifier, not just the settings file."""

    def test_saving_settings_applies_the_sound_preference(self, monkeypatch):
        from clammac.core import service as service_module

        applied: list[bool] = []
        monkeypatch.setattr(
            service_module.notifier, "set_sound_enabled", lambda v: applied.append(v)
        )
        monkeypatch.setattr(service_module.notifier, "set_enabled", lambda v: None)
        monkeypatch.setattr(service_module.paths, "is_macos", lambda: False)

        app = service_module.AppService.__new__(service_module.AppService)
        app.settings = service_module.Settings()
        app.settings.interface.sound_on_threat = False
        app.watcher = None
        app._status_listeners = []
        monkeypatch.setattr(service_module.config_module, "save", lambda *a, **k: None)
        monkeypatch.setattr(app, "notify_status", lambda: None)

        app.save_settings()
        assert applied == [False]
