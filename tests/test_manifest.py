"""The pinned list of installable ClamAV builds."""

from __future__ import annotations

import json

import pytest

from clammac.core.manifest import EngineRelease, Manifest, load_manifest

VALID_DIGEST = "a" * 64


def _release(version="1.0.0", **overrides):
    payload = {
        "version": version,
        "url": f"https://example.invalid/clamav-{version}.pkg",
        "sha256": VALID_DIGEST,
        "size": 1000,
    }
    payload.update(overrides)
    return payload


class TestParsing:
    def test_reads_a_release(self):
        release = EngineRelease.from_dict(_release("1.5.4"))
        assert release.version == "1.5.4"
        assert release.filename == "clamav-1.5.4.pkg"

    @pytest.mark.parametrize("missing", ["version", "url", "sha256"])
    def test_requires_the_essential_fields(self, missing):
        payload = _release()
        del payload[missing]
        with pytest.raises(ValueError, match="missing"):
            EngineRelease.from_dict(payload)

    @pytest.mark.parametrize("digest", ["short", "z" * 64, "A" * 63])
    def test_rejects_a_malformed_digest(self, digest):
        with pytest.raises(ValueError, match="malformed sha256"):
            EngineRelease.from_dict(_release(sha256=digest))

    def test_normalises_digest_case(self):
        assert EngineRelease.from_dict(_release(sha256="A" * 64)).sha256 == "a" * 64

    def test_one_bad_entry_does_not_poison_the_manifest(self):
        manifest = Manifest.from_dict(
            {"releases": [_release("1.0.0"), {"version": "broken"}, _release("2.0.0")]}
        )
        assert [r.version for r in manifest.releases] == ["1.0.0", "2.0.0"]

    def test_mirrors_follow_the_primary_url(self):
        release = EngineRelease.from_dict(
            _release(mirrors=["https://mirror.invalid/a.pkg"])
        )
        assert release.download_urls[0] == release.url
        assert len(release.download_urls) == 2


class TestSelection:
    def test_newest_uses_numeric_ordering(self):
        manifest = Manifest.from_dict(
            {"releases": [_release("1.9.0"), _release("1.10.0"), _release("1.2.0")]}
        )
        assert manifest.newest().version == "1.10.0"

    def test_the_default_wins_over_the_newest(self):
        manifest = Manifest.from_dict(
            {"default": "1.2.0", "releases": [_release("1.9.0"), _release("1.2.0")]}
        )
        assert manifest.preferred().version == "1.2.0"

    def test_an_unknown_default_falls_back_to_the_newest(self):
        manifest = Manifest.from_dict({"default": "9.9.9", "releases": [_release("1.2.0")]})
        assert manifest.preferred().version == "1.2.0"

    def test_an_empty_manifest_has_nothing_to_prefer(self):
        assert Manifest().preferred() is None


class TestMerging:
    """A downloaded manifest may add versions but never redefine a digest."""

    def test_a_remote_manifest_cannot_change_a_pinned_digest(self):
        local = Manifest.from_dict({"releases": [_release("1.0.0", sha256="a" * 64)]})
        remote = Manifest.from_dict({"releases": [_release("1.0.0", sha256="b" * 64)]})
        merged = local.merged_with(remote)
        assert merged.get("1.0.0").sha256 == "a" * 64

    def test_a_remote_manifest_may_add_a_version(self):
        local = Manifest.from_dict({"releases": [_release("1.0.0")]})
        remote = Manifest.from_dict({"releases": [_release("2.0.0")]})
        merged = local.merged_with(remote)
        assert {r.version for r in merged.releases} == {"1.0.0", "2.0.0"}

    def test_the_default_only_moves_forward(self):
        local = Manifest.from_dict({"default": "2.0.0", "releases": [_release("2.0.0")]})
        remote = Manifest.from_dict(
            {"default": "1.0.0", "releases": [_release("1.0.0"), _release("2.0.0")]}
        )
        assert local.merged_with(remote).default == "2.0.0"


class TestBundledManifest:
    """The manifest that actually ships has to be usable."""

    def test_loads_and_has_a_preferred_release(self):
        preferred = load_manifest().preferred()
        assert preferred is not None
        assert preferred.version

    def test_every_shipped_release_is_well_formed(self):
        for release in load_manifest().releases:
            assert len(release.sha256) == 64
            assert release.size > 0
            assert release.source_url, f"{release.version} has no source URL"
            for url in release.download_urls:
                assert url.startswith("https://"), f"{release.version} has a non-HTTPS URL"

    def test_a_cached_remote_manifest_is_folded_in(self, tmp_path):
        cached = tmp_path / "engine_manifest.json"
        cached.write_text(json.dumps({"releases": [_release("99.0.0")]}))
        merged = load_manifest(cached)
        assert merged.get("99.0.0") is not None
        # ...and the shipped entries are still there.
        assert len(merged.releases) > 1

    def test_a_corrupt_cache_is_ignored(self, tmp_path):
        cached = tmp_path / "engine_manifest.json"
        cached.write_text("{ not json")
        assert load_manifest(cached).preferred() is not None


class TestFilenameIsConfinedToTheCache:
    """The filename becomes a path under ClamMac's cache directory.

    A manifest can be fetched over the network, so a name carrying ``..`` or a
    separator would let a hostile or corrupted one steer the download outside
    the cache -- and the write happens before the digest check can reject it.
    Only a bare final component is ever accepted.
    """

    @pytest.mark.parametrize(
        "hostile",
        [
            "../../../../Library/LaunchAgents/evil.plist",
            "/etc/cron.d/evil",
            "..",
            ".",
            "",
            "   ",
            "sub/dir/clamav.pkg",
            "back\\slash.pkg",
        ],
    )
    def test_a_traversing_filename_never_survives_as_one(self, hostile):
        payload = _release("9.9.9", filename=hostile)
        try:
            release = EngineRelease.from_dict(payload)
        except ValueError:
            return  # rejected outright, which is the other acceptable outcome
        assert "/" not in release.filename
        assert "\\" not in release.filename
        assert release.filename not in {"", ".", ".."}

    def test_a_traversing_filename_cannot_escape_the_cache(self, tmp_path):
        from pathlib import Path

        payload = _release("9.9.9", filename="../../escaped.pkg")
        try:
            release = EngineRelease.from_dict(payload)
        except ValueError:
            return
        target = (tmp_path / release.filename).resolve()
        assert target.parent == Path(tmp_path).resolve()

    def test_a_malformed_entry_does_not_poison_the_whole_manifest(self):
        manifest = Manifest.from_dict(
            {"releases": [_release("9.9.9", filename="../evil"), _release("1.2.3")]}
        )
        assert manifest.get("1.2.3") is not None

    def test_an_ordinary_filename_is_untouched(self):
        release = EngineRelease.from_dict(
            _release("1.5.4", filename="clamav-1.5.4.macos.universal.pkg")
        )
        assert release.filename == "clamav-1.5.4.macos.universal.pkg"


class TestManifestRefresh:
    """An old build must not be frozen on the engine it shipped with.

    The refresh is best-effort in both directions: it must pick up a newer
    release when it can, and it must never turn a network problem into a
    failed install.
    """

    def _provisioner(self, monkeypatch, payload, *, boom=None):
        from clammac.core import provisioner as provisioner_module

        class _Response:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, _n=-1):
                return payload

        def fake_urlopen(request, timeout=0):
            if boom is not None:
                raise boom
            return _Response()

        monkeypatch.setattr(provisioner_module.urllib.request, "urlopen", fake_urlopen)
        return provisioner_module.EngineProvisioner()

    def test_a_newer_release_becomes_preferred(self, monkeypatch):
        payload = json.dumps(
            {"default": "99.0.0", "releases": [_release("99.0.0")]}
        ).encode()
        provisioner = self._provisioner(monkeypatch, payload)
        assert provisioner.try_refresh_manifest() is True
        preferred = provisioner.manifest.preferred()
        assert preferred is not None and preferred.version == "99.0.0"

    def test_the_shipped_releases_survive_the_refresh(self, monkeypatch):
        payload = json.dumps({"releases": [_release("99.0.0")]}).encode()
        provisioner = self._provisioner(monkeypatch, payload)
        provisioner.try_refresh_manifest()
        assert provisioner.manifest.get("1.5.4") is not None

    def test_a_remote_manifest_cannot_redefine_a_shipped_digest(self, monkeypatch):
        """The whole point of merging local-first."""
        payload = json.dumps(
            {"releases": [_release("1.5.4", sha256="b" * 64)]}
        ).encode()
        provisioner = self._provisioner(monkeypatch, payload)
        provisioner.try_refresh_manifest()
        shipped = provisioner.manifest.get("1.5.4")
        assert shipped is not None
        assert shipped.sha256 != "b" * 64

    def test_a_network_failure_is_not_an_error(self, monkeypatch):
        provisioner = self._provisioner(monkeypatch, b"", boom=OSError("no route to host"))
        assert provisioner.try_refresh_manifest() is False
        assert provisioner.manifest.preferred() is not None

    def test_junk_is_rejected_rather_than_cached(self, monkeypatch, tmp_path):
        from clammac.core import paths

        provisioner = self._provisioner(monkeypatch, b"<html>captive portal</html>")
        assert provisioner.try_refresh_manifest() is False
        assert not (paths.cache_dir() / "engine_manifest.json").exists()
        assert provisioner.manifest.preferred() is not None

    def test_an_empty_manifest_is_rejected(self, monkeypatch):
        from clammac.core import paths

        provisioner = self._provisioner(monkeypatch, json.dumps({"releases": []}).encode())
        assert provisioner.try_refresh_manifest() is False
        assert not (paths.cache_dir() / "engine_manifest.json").exists()

    def test_a_non_https_manifest_url_is_refused(self, monkeypatch):
        from clammac.core.provisioner import EngineProvisioner, ProvisionError

        with pytest.raises(ProvisionError):
            EngineProvisioner().refresh_manifest("http://example.invalid/manifest.json")

    def test_install_refreshes_before_choosing(self, monkeypatch, tmp_path):
        """The refresh has to actually be wired into the install path.

        This is the whole point of the change: without it the code exists but
        is never reached, and every build stays pinned to the engine list it
        shipped with.
        """
        from clammac.core import provisioner as provisioner_module

        called: list[str] = []
        provisioner = provisioner_module.EngineProvisioner()
        monkeypatch.setattr(
            provisioner, "try_refresh_manifest", lambda *a, **k: called.append("refresh") or True
        )
        monkeypatch.setattr(
            provisioner, "fetch_package", lambda release: (_ for _ in ()).throw(RuntimeError("stop"))
        )
        with pytest.raises(RuntimeError, match="stop"):
            provisioner.install()
        assert called == ["refresh"]

    def test_an_explicit_release_skips_the_refresh(self, monkeypatch):
        """Reinstalling a specific pinned version needs no network at all."""
        from clammac.core import provisioner as provisioner_module

        called: list[str] = []
        provisioner = provisioner_module.EngineProvisioner()
        monkeypatch.setattr(
            provisioner, "try_refresh_manifest", lambda *a, **k: called.append("refresh") or True
        )
        monkeypatch.setattr(
            provisioner, "fetch_package", lambda release: (_ for _ in ()).throw(RuntimeError("stop"))
        )
        chosen = provisioner.manifest.preferred()
        with pytest.raises(RuntimeError, match="stop"):
            provisioner.install(chosen)
        assert called == []
