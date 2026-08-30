"""The list of ClamAV engine builds ClamMac knows how to install.

ClamMac will not download a package it has no digest for. The digests live in
``clammac/resources/engine_manifest.json``, which ships inside the application
bundle, so a fresh install can provision itself without first trusting anything
fetched at runtime.

A newer manifest can optionally be fetched from the ClamMac repository so that
an old build can still install a current engine, but it is treated as a
*suggestion*: it can only add releases, and every release it adds still has to
carry a digest that the download is checked against. That check happens in
``provisioner.py`` and is not optional.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import paths

__all__ = ["EngineRelease", "Manifest", "load_manifest", "MANIFEST_UPDATE_URL"]

#: Where a newer manifest may be fetched from, if the user opts in.
MANIFEST_UPDATE_URL = (
    "https://raw.githubusercontent.com/tibcz/ClamMac/main/clammac/resources/engine_manifest.json"
)

_RESOURCE_NAME = "engine_manifest.json"


@dataclass(frozen=True)
class EngineRelease:
    """One installable ClamAV build."""

    version: str
    filename: str
    url: str
    sha256: str
    size: int = 0
    series: str = ""
    mirrors: tuple[str, ...] = ()
    signature_url: str = ""
    source_url: str = ""
    release_notes: str = ""

    @property
    def download_urls(self) -> tuple[str, ...]:
        """Primary URL first, then any mirrors."""
        return (self.url, *self.mirrors)

    @property
    def version_tuple(self) -> tuple[int, ...]:
        out: list[int] = []
        for part in self.version.split("."):
            digits = "".join(c for c in part if c.isdigit())
            out.append(int(digits) if digits else 0)
        return tuple(out)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EngineRelease":
        missing = [k for k in ("version", "url", "sha256") if not raw.get(k)]
        if missing:
            raise ValueError(f"engine release is missing {', '.join(missing)}")
        digest = str(raw["sha256"]).strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"engine release {raw['version']} has a malformed sha256")
        return cls(
            version=str(raw["version"]),
            filename=str(raw.get("filename") or Path(str(raw["url"])).name),
            url=str(raw["url"]),
            sha256=digest,
            size=int(raw.get("size") or 0),
            series=str(raw.get("series") or ""),
            mirrors=tuple(str(m) for m in raw.get("mirrors", ())),
            signature_url=str(raw.get("signature_url") or ""),
            source_url=str(raw.get("source_url") or ""),
            release_notes=str(raw.get("release_notes") or ""),
        )


@dataclass
class Manifest:
    """A parsed engine manifest."""

    default: str = ""
    updated: str = ""
    releases: list[EngineRelease] = field(default_factory=list)

    def get(self, version: str) -> EngineRelease | None:
        for release in self.releases:
            if release.version == version:
                return release
        return None

    def newest(self) -> EngineRelease | None:
        if not self.releases:
            return None
        return max(self.releases, key=lambda r: r.version_tuple)

    def preferred(self) -> EngineRelease | None:
        """The release ClamMac installs when the user does not pick one."""
        if self.default:
            chosen = self.get(self.default)
            if chosen is not None:
                return chosen
        return self.newest()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Manifest":
        releases: list[EngineRelease] = []
        for item in raw.get("releases", ()):
            try:
                releases.append(EngineRelease.from_dict(item))
            except (ValueError, TypeError):
                # One malformed entry must not make the whole manifest unusable.
                continue
        return cls(
            default=str(raw.get("default") or ""),
            updated=str(raw.get("updated") or ""),
            releases=releases,
        )

    def merged_with(self, other: "Manifest") -> "Manifest":
        """Combine two manifests, preferring entries already known locally.

        A downloaded manifest may *add* engine versions but may never redefine
        the digest of one that shipped with the application. That keeps a
        compromised or stale remote manifest from silently pointing an existing
        pinned version at a different file.
        """
        known = {r.version: r for r in self.releases}
        for release in other.releases:
            known.setdefault(release.version, release)
        merged = sorted(known.values(), key=lambda r: r.version_tuple, reverse=True)
        default = self.default
        if other.default and other.default in known:
            candidate = known[other.default]
            current = known.get(self.default)
            if current is None or candidate.version_tuple > current.version_tuple:
                default = other.default
        return Manifest(default=default, updated=other.updated or self.updated, releases=merged)


def _resource_candidates() -> Iterable[Path]:
    """Places the bundled manifest might live, in priority order."""
    here = Path(__file__).resolve().parent.parent / "resources" / _RESOURCE_NAME
    yield here
    yield paths.bundle_dir() / "clammac" / "resources" / _RESOURCE_NAME
    yield paths.bundle_dir() / "resources" / _RESOURCE_NAME
    yield paths.bundle_dir() / _RESOURCE_NAME


def load_manifest(extra: Path | None = None) -> Manifest:
    """Load the bundled manifest, then fold in a cached remote one if present."""
    base = Manifest()
    for candidate in _resource_candidates():
        if candidate.is_file():
            try:
                base = Manifest.from_dict(json.loads(candidate.read_text("utf-8")))
                break
            except (OSError, json.JSONDecodeError, TypeError):
                continue

    cached = extra if extra is not None else paths.cache_dir() / _RESOURCE_NAME
    if cached.is_file():
        try:
            remote = Manifest.from_dict(json.loads(cached.read_text("utf-8")))
            base = base.merged_with(remote)
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return base
