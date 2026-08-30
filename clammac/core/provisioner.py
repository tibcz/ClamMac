"""Obtaining a working ClamAV engine, without demanding an admin password.

The strategy, in order:

1. **Use what is already there.** Homebrew, MacPorts, the official installer
   package and a previous ClamMac install all leave a usable ``clamscan``
   somewhere predictable. If one works, nothing is downloaded.

2. **Private install.** Download the official ClamAV installer package, check
   it against a pinned SHA-256, unpack it into ClamMac's own Application
   Support folder, rewrite the absolute run-path so the binaries can find
   their libraries where they now live, re-sign them ad hoc, and then *prove
   it works* by running ``clamscan --version``. No administrator rights are
   involved at any point.

3. **Assisted system install.** Only if step 2 fails its own verification does
   ClamMac offer to run Apple's installer on the package, which puts ClamAV at
   ``/usr/local/clamav`` where its built-in run-path already points. This is
   the one path that asks for a password, and the user is told exactly why.

Each step verifies by execution rather than assumption, so a failure in one
degrades into the next instead of leaving a half-installed engine behind.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import paths
from .log import get_logger
from .machofix import (
    CLAMAV_INSTALL_RPATH,
    PORTABLE_RPATH,
    MachOError,
    is_macho,
    rewrite_rpath,
)
from .manifest import MANIFEST_UPDATE_URL, EngineRelease, Manifest, load_manifest
from .pkgextract import PackageError, XarArchive, extract_payload

log = get_logger(__name__)

__all__ = [
    "PAYLOAD_PREFIX",
    "EngineProvisioner",
    "Progress",
    "ProvisionCancelled",
    "ProvisionError",
    "Stage",
]

#: Everything in the ClamAV payload lives under this prefix; ClamMac flattens
#: it so the engine root contains bin/, sbin/, lib/ and etc/ directly.
PAYLOAD_PREFIX = "usr/local/clamav"

#: Build-time leftovers with no runtime purpose. Skipping the Rust static
#: archive alone takes the install from about 530 MB down to about 90 MB.
_SKIP_SUFFIXES = (".a", ".h", ".pc", ".la")

#: Tools ClamMac never invokes. clamsubmit alone is 14 MB.
_SKIP_NAMES = ("clamsubmit",)

_USER_AGENT = "ClamMac engine provisioner (+https://github.com/tibcz/ClamMac)"
_CHUNK = 1 << 18


class Stage(str, Enum):
    RESOLVING = "resolving"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    UNPACKING = "unpacking"
    RELOCATING = "relocating"
    SIGNING = "signing"
    TESTING = "testing"
    DONE = "done"


@dataclass(frozen=True)
class Progress:
    stage: Stage
    message: str
    fraction: float = -1.0  # negative means indeterminate

    @property
    def percent(self) -> int:
        return max(0, min(100, int(self.fraction * 100)))


class ProvisionError(Exception):
    """Provisioning failed in a way the user needs to be told about."""


class ProvisionCancelled(ProvisionError):
    """The user stopped the install."""


ProgressFn = Callable[[Progress], None]
CancelFn = Callable[[], bool]


class EngineProvisioner:
    """Downloads and installs a private copy of the ClamAV engine."""

    def __init__(
        self,
        *,
        on_progress: ProgressFn | None = None,
        should_cancel: CancelFn | None = None,
        manifest: Manifest | None = None,
    ) -> None:
        self._on_progress = on_progress
        self._should_cancel = should_cancel
        self.manifest = manifest if manifest is not None else load_manifest()

    # -- plumbing ---------------------------------------------------------

    def _emit(self, stage: Stage, message: str, fraction: float = -1.0) -> None:
        if self._on_progress is not None:
            self._on_progress(Progress(stage, message, fraction))

    def _check_cancel(self) -> None:
        if self._should_cancel is not None and self._should_cancel():
            raise ProvisionCancelled("installation cancelled")

    # -- public API -------------------------------------------------------

    def install(self, release: EngineRelease | None = None) -> Path:
        """Provision an engine and return the directory it was installed to."""
        self._emit(Stage.RESOLVING, "Choosing a ClamAV release")
        chosen = release or self.manifest.preferred()
        if chosen is None:
            raise ProvisionError(
                "No ClamAV release is listed in ClamMac's manifest, so there is "
                "nothing it can safely download."
            )

        package = self.fetch_package(chosen)
        root = paths.engine_dir() / chosen.version
        self.unpack(package, root)
        self.make_relocatable(root)
        self.sign(root)
        version = self.verify(root)
        log.info("engine %s provisioned at %s", version, root)
        self._emit(Stage.DONE, f"ClamAV {version} is ready", 1.0)
        self._mark_current(root)
        return root

    # -- step 1: fetch ----------------------------------------------------

    def fetch_package(self, release: EngineRelease) -> Path:
        """Download (or reuse) the installer package and verify its digest."""
        cache = paths.cache_dir()
        cache.mkdir(parents=True, exist_ok=True)
        target = cache / release.filename

        if target.is_file():
            self._emit(Stage.VERIFYING, "Checking the cached download")
            if self._digest(target) == release.sha256:
                log.info("reusing verified cached package %s", target.name)
                return target
            log.warning("cached package %s failed verification, refetching", target.name)
            target.unlink(missing_ok=True)

        last_error: Exception | None = None
        for url in release.download_urls:
            self._check_cancel()
            if not url.lower().startswith("https://"):
                log.warning("refusing non-HTTPS engine source %s", url)
                continue
            try:
                self._download(url, target, expected_size=release.size)
                break
            except ProvisionCancelled:
                raise
            except Exception as exc:
                last_error = exc
                log.warning("download from %s failed: %s", url, exc)
                target.unlink(missing_ok=True)
        else:
            raise ProvisionError(
                "Could not download the ClamAV installer package. Check your "
                f"internet connection and try again. Last error: {last_error}"
            )

        self._emit(Stage.VERIFYING, "Verifying the download", 0.0)
        actual = self._digest(target)
        if actual != release.sha256:
            target.unlink(missing_ok=True)
            raise ProvisionError(
                "The downloaded ClamAV package did not match its expected "
                "checksum, so ClamMac discarded it without opening it.\n\n"
                f"Expected: {release.sha256}\nActually got: {actual}"
            )
        self._emit(Stage.VERIFYING, "Checksum verified", 1.0)
        return target

    def _download(self, url: str, target: Path, *, expected_size: int = 0) -> None:
        temp = target.with_suffix(target.suffix + ".part")
        temp.unlink(missing_ok=True)
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        self._emit(Stage.DOWNLOADING, "Contacting the ClamAV download server", 0.0)

        with urllib.request.urlopen(request, timeout=60) as response:
            declared = response.headers.get("Content-Length")
            total = int(declared) if declared and declared.isdigit() else expected_size
            written = 0
            started = time.monotonic()
            with temp.open("wb") as handle:
                while True:
                    self._check_cancel()
                    chunk = response.read(_CHUNK)
                    if not chunk:
                        break
                    handle.write(chunk)
                    written += len(chunk)
                    if total:
                        elapsed = max(time.monotonic() - started, 0.001)
                        rate = written / elapsed / 1e6
                        self._emit(
                            Stage.DOWNLOADING,
                            f"Downloading ClamAV — {written / 1e6:.0f} of "
                            f"{total / 1e6:.0f} MB ({rate:.1f} MB/s)",
                            written / total,
                        )
                    else:
                        self._emit(
                            Stage.DOWNLOADING,
                            f"Downloading ClamAV — {written / 1e6:.0f} MB",
                        )
        if expected_size and written != expected_size:
            temp.unlink(missing_ok=True)
            raise ProvisionError(
                f"Download was {written} bytes but {expected_size} were expected."
            )
        temp.replace(target)

    def _digest(self, path: Path) -> str:
        digest = hashlib.sha256()
        size = path.stat().st_size or 1
        seen = 0
        with path.open("rb") as handle:
            while True:
                self._check_cancel()
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
                seen += len(chunk)
                self._emit(Stage.VERIFYING, "Verifying the download", seen / size)
        return digest.hexdigest()

    # -- step 2: unpack ---------------------------------------------------

    @staticmethod
    def _wanted(name: str, _mode: int) -> bool:
        if name.endswith(_SKIP_SUFFIXES):
            return False
        return Path(name).name not in _SKIP_NAMES

    def unpack(self, package: Path, root: Path) -> Path:
        """Expand the installer package into ``root``, flattening its prefix."""
        self._emit(Stage.UNPACKING, "Unpacking the ClamAV engine", 0.0)
        staging = root.with_name(root.name + ".incoming")
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)

        try:
            with XarArchive(package) as archive:
                payloads = archive.component_payloads()
                if not payloads:
                    raise ProvisionError("The ClamAV package contains no installable payload.")
                # Documentation is manpages and HTML; ClamMac shows neither.
                payloads = [p for p in payloads if "documentation" not in p.path] or payloads
                for index, payload in enumerate(payloads):
                    self._check_cancel()
                    self._emit(
                        Stage.UNPACKING,
                        f"Unpacking component {index + 1} of {len(payloads)}",
                        index / len(payloads),
                    )
                    with archive.stream(payload) as stream:
                        extract_payload(
                            stream,
                            staging,
                            strip_prefix=PAYLOAD_PREFIX,
                            want=self._wanted,
                        )
        except PackageError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise ProvisionError(f"The ClamAV package could not be read: {exc}") from exc

        _prune_empty_dirs(staging)
        if not (staging / "bin" / "clamscan").exists():
            shutil.rmtree(staging, ignore_errors=True)
            raise ProvisionError(
                "The ClamAV package did not contain clamscan where ClamMac "
                "expected it. The package layout may have changed."
            )

        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        staging.replace(root)
        self._emit(Stage.UNPACKING, "Unpacked", 1.0)
        return root

    # -- step 3: relocate -------------------------------------------------

    def make_relocatable(self, root: Path) -> int:
        """Point every binary's run-path at its own directory, not /usr/local."""
        self._emit(Stage.RELOCATING, "Adapting the engine to its new location", 0.0)
        images = list(_iter_images(root))
        changed = 0
        for index, image in enumerate(images):
            self._check_cancel()
            try:
                changed += rewrite_rpath(image, CLAMAV_INSTALL_RPATH, PORTABLE_RPATH)
            except MachOError as exc:
                # A binary we cannot adapt is not fatal on its own; the
                # verification step decides whether the engine actually works.
                log.warning("could not adapt %s: %s", image.name, exc)
            self._emit(
                Stage.RELOCATING,
                "Adapting the engine to its new location",
                (index + 1) / max(len(images), 1),
            )
        log.info("rewrote %d run-path entries across %d images", changed, len(images))
        return changed

    # -- step 4: re-sign --------------------------------------------------

    def sign(self, root: Path) -> bool:
        """Re-sign the edited binaries ad hoc so macOS will run them.

        Editing a Mach-O image invalidates its signature, and on Apple silicon
        an unsigned or badly-signed binary will not start at all. ``codesign``
        is part of the base system, not the optional developer tools, so this
        works on a machine that has never seen Xcode.
        """
        if not paths.is_macos():
            return False
        codesign = Path("/usr/bin/codesign")
        if not codesign.exists():
            log.warning("codesign is unavailable; skipping re-signing")
            return False

        images = list(_iter_images(root))
        # Libraries first, then the executables that load them.
        images.sort(key=lambda p: 0 if p.suffix == ".dylib" else 1)
        failures = 0
        for index, image in enumerate(images):
            self._check_cancel()
            _strip_quarantine(image)
            result = subprocess.run(
                [str(codesign), "--force", "--sign", "-", "--timestamp=none", str(image)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                failures += 1
                log.warning("codesign failed for %s: %s", image.name, result.stderr.strip())
            self._emit(
                Stage.SIGNING,
                "Registering the engine with macOS",
                (index + 1) / max(len(images), 1),
            )
        if failures:
            log.warning("%d of %d images could not be re-signed", failures, len(images))
        return failures == 0

    # -- step 5: prove it works -------------------------------------------

    def verify(self, root: Path) -> str:
        """Run ``clamscan --version`` and return what it reports."""
        self._emit(Stage.TESTING, "Checking that the engine runs", 0.5)
        clamscan = root / "bin" / "clamscan"
        if not clamscan.exists():
            raise ProvisionError("clamscan is missing from the unpacked engine.")
        try:
            result = subprocess.run(
                [str(clamscan), "--version"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except OSError as exc:
            raise ProvisionError(f"The unpacked engine could not be started: {exc}") from exc

        output = (result.stdout or result.stderr or "").strip()
        if result.returncode != 0 or "ClamAV" not in output:
            raise ProvisionError(
                "The unpacked ClamAV engine did not run correctly.\n\n"
                f"{output or 'No output.'}"
            )
        self._emit(Stage.TESTING, output.splitlines()[0], 1.0)
        return output.splitlines()[0]

    # -- bookkeeping ------------------------------------------------------

    @staticmethod
    def _mark_current(root: Path) -> None:
        """Point ``Engine/current`` at the freshly installed version."""
        link = paths.engine_dir() / "current"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(root, target_is_directory=True)
        except OSError as exc:  # pragma: no cover - cosmetic convenience only
            log.debug("could not update the current-engine link: %s", exc)

    def prune_old_versions(self, keep: str) -> None:
        """Delete previously installed engine versions other than ``keep``."""
        base = paths.engine_dir()
        if not base.is_dir():
            return
        for child in base.iterdir():
            if child.name in {keep, "current"} or child.is_symlink():
                continue
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)

    def discard_download_cache(self) -> int:
        """Remove cached installer packages. Returns bytes reclaimed."""
        freed = 0
        cache = paths.cache_dir()
        if not cache.is_dir():
            return 0
        for item in cache.glob("clamav-*.pkg*"):
            try:
                freed += item.stat().st_size
                item.unlink()
            except OSError:
                pass
        return freed

    def refresh_manifest(self, url: str = MANIFEST_UPDATE_URL) -> Manifest:
        """Fetch a newer engine manifest, keeping locally pinned digests."""
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read(1 << 20)
        target = paths.cache_dir() / "engine_manifest.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        self.manifest = load_manifest()
        return self.manifest


# --------------------------------------------------------------------------
# The assisted, password-requiring fallback
# --------------------------------------------------------------------------


def admin_install_command(package: Path) -> list[str]:
    """The command that installs the package system-wide via Apple's installer.

    Returned rather than run so callers can show the user exactly what will
    happen before the authentication dialog appears.
    """
    inner = f'/usr/sbin/installer -pkg {_applescript_quote(str(package))} -target /'
    script = f'do shell script "{_escape_for_applescript(inner)}" with administrator privileges'
    return ["/usr/bin/osascript", "-e", script]


def run_admin_install(package: Path, *, timeout: int = 900) -> None:
    """Install the package system-wide, prompting for an administrator."""
    if not paths.is_macos():
        raise ProvisionError("System installation is only available on macOS.")
    result = subprocess.run(
        admin_install_command(package), capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        message = (result.stderr or "").strip()
        if "-128" in message or "User canceled" in message:
            raise ProvisionCancelled("You cancelled the installation.")
        raise ProvisionError(f"The system installation did not finish: {message}")


def open_in_installer(package: Path) -> None:
    """Hand the package to Apple's Installer app so the user drives it."""
    subprocess.Popen(["/usr/bin/open", str(package)])


def _applescript_quote(value: str) -> str:
    """Single-quote a value for the shell, as seen from inside AppleScript."""
    return "'" + value.replace("'", "'\\''") + "'"


def _escape_for_applescript(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _iter_images(root: Path) -> Iterable[Path]:
    """Every real Mach-O file under ``root`` (symlinks are followed once)."""
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        if is_macho(candidate):
            yield candidate


def _strip_quarantine(path: Path) -> None:
    """Remove the Gatekeeper quarantine flag, if the file carries one."""
    remove = getattr(os, "removexattr", None)
    if remove is None:
        return
    try:
        remove(str(path), "com.apple.quarantine")
    except OSError:
        pass


def _prune_empty_dirs(root: Path) -> None:
    """Delete directories left empty by the extraction filter."""
    for directory in sorted(
        (p for p in root.rglob("*") if p.is_dir()),
        key=lambda p: len(p.parts),
        reverse=True,
    ):
        try:
            next(directory.iterdir())
        except StopIteration:
            directory.rmdir()
        except OSError:
            pass
