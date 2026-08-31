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
