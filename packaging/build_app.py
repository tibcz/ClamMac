#!/usr/bin/env python3
"""Build ClamMac.app and ClamMac.dmg.

    python3 packaging/build_app.py            # .app and .dmg into dist/
    python3 packaging/build_app.py --app-only
    python3 packaging/build_app.py --skip-verify

Signing
-------
With no configuration the bundle is signed ad hoc, which is enough for macOS
to run it locally but not enough for Gatekeeper to open it without the user
explicitly allowing it the first time. The README explains that step.

To sign properly, set these before building. None of them are stored in the
repository and none are required:

    CODESIGN_IDENTITY   e.g. "Developer ID Application: Your Name (TEAMID)"
    NOTARY_PROFILE      a notarytool keychain profile name; enables notarising

The Python interpreter and Qt's libraries have to be signed before the bundle
that contains them -- a signature covers everything nested inside it, so
signing the outside first is immediately invalidated by signing the inside.
"""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from clammac.version import APP_NAME, VERSION  # noqa: E402

DIST = REPO_ROOT / "dist"
BUILD = REPO_ROOT / "build"
SPEC = REPO_ROOT / "packaging" / "ClamMac.spec"
ENTITLEMENTS = REPO_ROOT / "packaging" / "entitlements.plist"
APP_PATH = DIST / f"{APP_NAME}.app"


class BuildError(Exception):
    pass


def announce(message: str) -> None:
    print(f"\n\033[1m==>\033[0m {message}", flush=True)


def run(command: list[str], *, check: bool = True, quiet: bool = False, **kwargs) -> subprocess.CompletedProcess:
    if not quiet:
        print("    " + " ".join(str(c) for c in command), flush=True)
    result = subprocess.run([str(c) for c in command], text=True, capture_output=quiet, **kwargs)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() if quiet else ""
        raise BuildError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{detail}")
    return result


# --------------------------------------------------------------------------


def check_platform() -> None:
    if sys.platform != "darwin":
        raise BuildError(
            "ClamMac.app can only be built on macOS.\n"
            "Everything else in this project -- the tests, the linter, the icon "
            "generator -- runs anywhere."
        )


def build_icon() -> Path:
    announce("Generating the application icon")
    from packaging.make_icon import build as build_icns

    target = REPO_ROOT / "clammac" / "resources" / "ClamMac.icns"
    written = build_icns(target)
    print(f"    {written.name} ({written.stat().st_size:,} bytes)")
    return written


def detect_target_arch() -> str | None:
    """Return 'universal2' when the running Python can actually produce it."""
    import sysconfig

    if "universal2" in (sysconfig.get_platform() or ""):
        return "universal2"
    result = subprocess.run(
        ["/usr/bin/file", "-b", sys.executable], capture_output=True, text=True, check=False
    )
    if "universal binary" in result.stdout and "arm64" in result.stdout and "x86_64" in result.stdout:
        return "universal2"
    return None


def run_pyinstaller(*, clean: bool) -> Path:
    announce("Building the application bundle")
    if clean:
        for directory in (BUILD, DIST):
            shutil.rmtree(directory, ignore_errors=True)

    arch = detect_target_arch()
    if arch:
        print(f"    building a {arch} bundle")
    else:
        import platform

        print(
            f"    building for {platform.machine()} only "
            "(this Python is not universal2, so the bundle cannot be either)"
        )

    environment = dict(os.environ)
    if arch:
        environment["CLAMMAC_TARGET_ARCH"] = arch

    run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--distpath", DIST,
         "--workpath", BUILD, str(SPEC)],
        env=environment,
        cwd=REPO_ROOT,
    )
    if not APP_PATH.is_dir():
        raise BuildError(f"PyInstaller did not produce {APP_PATH}")

    size = sum(f.stat().st_size for f in APP_PATH.rglob("*") if f.is_file() and not f.is_symlink())
    print(f"    {APP_PATH.name} is {size / 1e6:.0f} MB")
    return APP_PATH


def verify_plist() -> None:
    """Confirm the keys the app depends on actually made it into Info.plist."""
    announce("Checking Info.plist")
    plist_path = APP_PATH / "Contents" / "Info.plist"
    with plist_path.open("rb") as handle:
        plist = plistlib.load(handle)

    required = [
        "CFBundleIdentifier",
        "CFBundleShortVersionString",
        "LSMinimumSystemVersion",
        "NSDownloadsFolderUsageDescription",
        "NSDesktopFolderUsageDescription",
        "NSDocumentsFolderUsageDescription",
        "NSRemovableVolumesUsageDescription",
    ]
    missing = [key for key in required if key not in plist]
    if missing:
        raise BuildError(
            "Info.plist is missing " + ", ".join(missing) + ".\n"
            "The usage descriptions are not optional: without them macOS cannot "
            "show the permission prompt, so scans of those folders silently "
            "read nothing."
        )
    print(f"    version {plist['CFBundleShortVersionString']}, "
          f"minimum macOS {plist['LSMinimumSystemVersion']}, all usage strings present")


def sign(identity: str | None) -> None:
    announce("Signing")
    codesign = "/usr/bin/codesign"

    # Sign nested code before the bundle that contains it: an outer signature
    # covers everything inside, so signing the inside afterwards breaks it.
    nested = sorted(
        [p for p in APP_PATH.rglob("*") if p.is_file() and not p.is_symlink()
         and (p.suffix in {".so", ".dylib"} or ".framework" in str(p))],
        key=lambda p: len(p.parts),
        reverse=True,
    )

    if identity:
        base = [codesign, "--force", "--timestamp", "--options", "runtime",
                "--entitlements", str(ENTITLEMENTS), "--sign", identity]
        print(f"    signing with {identity}")
    else:
        base = [codesign, "--force", "--timestamp=none", "--sign", "-"]
        print("    no CODESIGN_IDENTITY set, signing ad hoc")

    for index, item in enumerate(nested):
        run([*base, str(item)], quiet=True, check=False)
        if index and index % 200 == 0:
            print(f"    ... {index}/{len(nested)} nested items")
    print(f"    signed {len(nested)} nested items")

    run([*base, str(APP_PATH)], quiet=True)
    run([codesign, "--verify", "--deep", "--strict", "--verbose=1", str(APP_PATH)], quiet=True)
    print("    signature verifies")


def notarize(profile: str) -> None:
    announce("Notarising")
    archive = DIST / f"{APP_NAME}-notarize.zip"
    run(["/usr/bin/ditto", "-c", "-k", "--keepParent", str(APP_PATH), str(archive)])
    run(["/usr/bin/xcrun", "notarytool", "submit", str(archive),
         "--keychain-profile", profile, "--wait"])
    run(["/usr/bin/xcrun", "stapler", "staple", str(APP_PATH)])
    archive.unlink(missing_ok=True)
    print("    notarised and stapled")


def smoke_test() -> None:
    """Start the built app once and check it reports its version.

    Cheap, and it catches the failure that matters most: a bundle that looks
    complete but cannot import its own extension modules.
    """
    announce("Checking the bundle runs")
    executable = APP_PATH / "Contents" / "MacOS" / APP_NAME
    result = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, timeout=120, check=False
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0 or APP_NAME not in output:
        raise BuildError(
            f"the built application did not start.\nexit status {result.returncode}\n{output}"
        )
    print(f"    {output}")


def build_dmg() -> Path:
    announce("Building the disk image")
    # Name the architecture when the bundle is not universal, so someone with
    # two Macs cannot end up running the wrong download on the wrong one.
    import platform

    suffix = "" if detect_target_arch() == "universal2" else f"-{platform.machine()}"
    dmg = DIST / f"{APP_NAME}-{VERSION}{suffix}.dmg"
    dmg.unlink(missing_ok=True)

    staging = DIST / "dmg-staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)

    run(["/usr/bin/ditto", str(APP_PATH), str(staging / APP_PATH.name)], quiet=True)
    (staging / "Applications").symlink_to("/Applications")
    shutil.copy2(REPO_ROOT / "LICENSE", staging / "LICENSE.txt")
    (staging / "Read me first.txt").write_text(_first_run_note(), encoding="utf-8")

    run([
        "/usr/bin/hdiutil", "create",
        "-volname", f"{APP_NAME} {VERSION}",
        "-srcfolder", str(staging),
        "-ov", "-format", "UDZO", "-imagekey", "zlib-level=9",
        str(dmg),
    ], quiet=True)
    shutil.rmtree(staging, ignore_errors=True)

    print(f"    {dmg.name} ({dmg.stat().st_size / 1e6:.0f} MB)")
    return dmg


def _first_run_note() -> str:
    return f"""{APP_NAME} {VERSION}
{'=' * (len(APP_NAME) + len(VERSION) + 1)}

INSTALLING

Drag {APP_NAME} onto the Applications folder in this window.


FIRST LAUNCH

This build is not signed with an Apple Developer ID, so macOS will refuse to
open it the first time. That is Gatekeeper's default treatment of every
unsigned application, not a judgement about this one.

To open it the first time, do either of these once:

  * Right-click (or Control-click) {APP_NAME} in Applications, choose Open,
    then click Open in the dialog that appears; or

  * Try to open it normally, then go to System Settings > Privacy & Security,
    scroll down to the Security section, and click "Open Anyway".

After that it opens by double-clicking like anything else.

If you would rather not take that on trust, the complete source is at
https://github.com/tibcz/ClamMac and `make dmg` builds this same disk image.


WHAT HAPPENS ON FIRST RUN

{APP_NAME} does not include the ClamAV scanning engine. On first launch it
offers to download the official ClamAV installer package published by the
ClamAV project, checks it against a SHA-256 digest built into {APP_NAME}, and
unpacks it into {APP_NAME}'s own folder inside your home directory.

This does not ask for your password, and nothing is installed system-wide.

If you already have ClamAV from Homebrew, MacPorts, or the official installer,
{APP_NAME} finds it and downloads nothing.


LICENCE

{APP_NAME} is free software under the GNU General Public License version 3 or
later. See LICENSE.txt.

{APP_NAME} is an independent project. It is not affiliated with, endorsed by,
or derived from Cisco Systems, Inc. or the ClamAV project. ClamAV is a
registered trademark of Cisco Systems, Inc.
"""


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Build {APP_NAME}.app and its disk image.")
    parser.add_argument("--app-only", action="store_true", help="skip the disk image")
    parser.add_argument("--no-clean", action="store_true", help="reuse previous build output")
    parser.add_argument("--skip-verify", action="store_true", help="skip the launch check")
    parser.add_argument("--icon-only", action="store_true", help="only regenerate the icon")
    arguments = parser.parse_args()

    started = time.monotonic()
    try:
        if arguments.icon_only:
            build_icon()
            return 0

        check_platform()
        build_icon()
        run_pyinstaller(clean=not arguments.no_clean)
        verify_plist()
        sign(os.environ.get("CODESIGN_IDENTITY") or None)

        profile = os.environ.get("NOTARY_PROFILE")
        if profile:
            notarize(profile)

        if not arguments.skip_verify:
            smoke_test()

        if not arguments.app_only:
            dmg = build_dmg()
            announce(f"Done in {time.monotonic() - started:.0f}s")
            print(f"\n    {dmg}\n")
        else:
            announce(f"Done in {time.monotonic() - started:.0f}s")
            print(f"\n    {APP_PATH}\n")
        return 0

    except BuildError as exc:
        print(f"\n\033[31mBuild failed:\033[0m {exc}\n", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
