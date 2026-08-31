#!/usr/bin/env python3
"""Check every engine release in the manifest is real and correctly pinned.

Downloads each pinned ClamAV package, confirms it matches the recorded
SHA-256 and size, and confirms ClamMac's own extractor can read it and finds
clamscan where it expects to. Meant for CI and for whenever the manifest gains
a new version.

    python3 scripts/verify-manifest.py            # check every release
    python3 scripts/verify-manifest.py --version 1.5.4
    python3 scripts/verify-manifest.py --metadata-only
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from clammac.core.machofix import CLAMAV_INSTALL_RPATH, is_macho, read_rpaths  # noqa: E402
from clammac.core.manifest import EngineRelease, load_manifest  # noqa: E402
from clammac.core.pkgextract import XarArchive, extract_payload  # noqa: E402
from clammac.core.provisioner import PAYLOAD_PREFIX, EngineProvisioner  # noqa: E402


def check_metadata(release: EngineRelease) -> list[str]:
    problems: list[str] = []
    if len(release.sha256) != 64:
        problems.append("sha256 is not 64 hex characters")
    for url in release.download_urls:
        if not url.startswith("https://"):
            problems.append(f"non-HTTPS download URL: {url}")
    if release.size <= 0:
        problems.append("size is missing or not positive")
    if not release.source_url:
        problems.append("no source_url recorded (needed by fetch-clamav-source.sh)")
    return problems


def download(release: EngineRelease, destination: Path) -> Path:
    print(f"    downloading {release.filename} ({release.size / 1e6:.0f} MB)")
    target = destination / release.filename
    with (
        urllib.request.urlopen(release.url, timeout=120) as response,
        target.open("wb") as handle,
    ):
        while chunk := response.read(1 << 20):
            handle.write(chunk)
    return target


def verify(release: EngineRelease, *, metadata_only: bool) -> list[str]:
    print(f"\n==> ClamAV {release.version}")
    problems = check_metadata(release)
    for problem in problems:
        print(f"    METADATA: {problem}")
    if metadata_only:
        return problems

    with tempfile.TemporaryDirectory() as scratch:
        workspace = Path(scratch)
        package = download(release, workspace)

        actual_size = package.stat().st_size
        if actual_size != release.size:
            problems.append(f"size is {actual_size} but the manifest says {release.size}")

        digest = hashlib.sha256()
        with package.open("rb") as handle:
            while chunk := handle.read(1 << 20):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != release.sha256:
            problems.append(f"sha256 is {actual} but the manifest says {release.sha256}")
        else:
            print(f"    sha256 matches: {actual}")

        engine_root = workspace / "engine"
        with XarArchive(package) as archive:
            payloads = [p for p in archive.component_payloads() if "documentation" not in p.path]
            for payload in payloads:
                with archive.stream(payload) as stream:
                    extract_payload(
                        stream, engine_root, strip_prefix=PAYLOAD_PREFIX,
                        want=EngineProvisioner._wanted,
                    )

        for required in ("bin/clamscan", "bin/freshclam", "sbin/clamd", "lib/libclamav.dylib"):
            if not (engine_root / required).exists():
                problems.append(f"unpacked engine is missing {required}")
        if not problems:
            print(f"    unpacked cleanly, {len(list(engine_root.rglob('*')))} entries")

        # Every binary must carry the run-path ClamMac knows how to rewrite.
        images = [p for p in engine_root.rglob("*") if p.is_file() and not p.is_symlink() and is_macho(p)]
        without = [
            p.name for p in images
            if not any(CLAMAV_INSTALL_RPATH in paths for paths in read_rpaths(p).values())
        ]
        if without:
            problems.append(
                f"{len(without)} Mach-O images do not carry {CLAMAV_INSTALL_RPATH}: "
                + ", ".join(without[:5])
                + " -- the relocation step would not make these runnable"
            )
        else:
            print(f"    all {len(images)} Mach-O images carry the expected run-path")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify ClamMac's engine manifest.")
    parser.add_argument("--version", help="check only this version")
    parser.add_argument("--metadata-only", action="store_true", help="do not download anything")
    arguments = parser.parse_args()

    manifest = load_manifest()
    releases = manifest.releases
    if arguments.version:
        releases = [r for r in releases if r.version == arguments.version]
        if not releases:
            print(f"no release pinned for version {arguments.version}", file=sys.stderr)
            return 2

    if not releases:
        print("the manifest contains no releases", file=sys.stderr)
        return 2

    print(f"Checking {len(releases)} pinned release(s); default is {manifest.default}")
    failures = 0
    for release in releases:
        problems = verify(release, metadata_only=arguments.metadata_only)
        if problems:
            failures += 1
            print(f"    FAILED: {len(problems)} problem(s)")
            for problem in problems:
                print(f"      - {problem}")
        else:
            print("    OK")

    print()
    if failures:
        print(f"{failures} of {len(releases)} release(s) failed verification")
        return 1
    print(f"all {len(releases)} release(s) verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
