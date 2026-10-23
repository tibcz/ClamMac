#!/usr/bin/env python3
"""Generate ClamMac's application icon.

The artwork is ``clammac/resources/app-icon.png``, a full-bleed square.
``clammac.ui.icons.app_icon_pixmap`` sets it into the macOS icon tile (mask,
shadow, edge light), and this script writes that out at every size macOS wants.
Replace the PNG and run it again to change the icon.

``.icns`` is written directly rather than shelling out to ``iconutil``, so the
icon can be produced on any platform. That matters for continuous integration
and for anyone who wants to check the build without a Mac. When ``iconutil`` is
present it is used instead, purely because Apple's own writer is the reference.
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Chosen before Qt loads: this script never shows a window, and on a build
# machine there may be no display to connect to.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

#: OSType codes macOS accepts PNG data for, mapped to their pixel size.
#: Both the 1x and the @2x code for each logical size are emitted, which is
#: what makes the icon crisp on Retina displays without a separate asset.
ICNS_ENTRIES: tuple[tuple[bytes, int], ...] = (
    (b"icp4", 16),
    (b"icp5", 32),
    (b"ic11", 32),  # 16 @2x
    (b"ic12", 64),  # 32 @2x
    (b"ic07", 128),
    (b"ic13", 256),  # 128 @2x
    (b"ic08", 256),
    (b"ic14", 512),  # 256 @2x
    (b"ic09", 512),
    (b"ic10", 1024),  # 512 @2x
)

ICONSET_SIZES: tuple[tuple[str, int], ...] = (
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
)


def _render(size: int) -> bytes:
    """Render the icon at ``size`` and return it as PNG bytes."""
    from PySide6.QtCore import QBuffer, Qt
    from PySide6.QtGui import QGuiApplication

    from clammac.ui.icons import app_icon_pixmap

    if QGuiApplication.instance() is None:
        QGuiApplication(["make_icon"])

    # Render large and downsample: edges stay smooth at 16px this way, where
    # rendering directly at 16px would alias badly.
    pixmap = app_icon_pixmap(1024)
    if size != 1024:
        pixmap = pixmap.scaled(
            size,
            size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

    # QBuffer's default constructor owns its byte array. Passing one in --
    # QBuffer(QByteArray()) -- hands it a temporary that Python collects while
    # the buffer is still using it, which segfaults on save.
    buffer = QBuffer()
    buffer.open(QBuffer.OpenModeFlag.WriteOnly)
    if not pixmap.save(buffer, "PNG"):
        raise RuntimeError(f"could not encode the icon at {size}px")
    buffer.close()
    return bytes(buffer.data())


def write_icns(destination: Path) -> Path:
    """Write a multi-resolution ``.icns`` file."""
    chunks: list[bytes] = []
    for ostype, size in ICNS_ENTRIES:
        payload = _render(size)
        chunks.append(ostype + struct.pack(">I", len(payload) + 8) + payload)

    body = b"".join(chunks)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)
    return destination


def write_iconset(directory: Path) -> Path:
    """Write an ``.iconset`` directory, the input ``iconutil`` expects."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, size in ICONSET_SIZES:
        (directory / name).write_bytes(_render(size))
    return directory


def write_png(destination: Path, size: int = 1024) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(_render(size))
    return destination


def build(output: Path, *, prefer_iconutil: bool = True) -> Path:
    """Produce ``output`` (.icns), using iconutil when it is available."""
    iconutil = Path("/usr/bin/iconutil")
    if prefer_iconutil and iconutil.exists():
        iconset = output.with_suffix(".iconset")
        write_iconset(iconset)
        result = subprocess.run(
            [str(iconutil), "-c", "icns", str(iconset), "-o", str(output)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            for child in iconset.iterdir():
                child.unlink()
            iconset.rmdir()
            return output
        print(f"iconutil failed ({result.stderr.strip()}); writing icns directly", file=sys.stderr)

    return write_icns(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the ClamMac application icon.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=REPO_ROOT / "clammac" / "resources" / "ClamMac.icns",
        help="where to write the .icns file",
    )
    parser.add_argument("--png", type=Path, help="also write a PNG preview here")
    parser.add_argument(
        "--no-iconutil", action="store_true", help="always use the built-in writer"
    )
    arguments = parser.parse_args()

    written = build(arguments.output, prefer_iconutil=not arguments.no_iconutil)
    print(f"wrote {written} ({written.stat().st_size:,} bytes)")
    if arguments.png:
        preview = write_png(arguments.png)
        print(f"wrote {preview} ({preview.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
