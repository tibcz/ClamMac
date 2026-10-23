# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for the ClamMac application bundle.

Run through ``packaging/build_app.py`` rather than directly, so the icon is
generated and the result is signed and verified.

Two things here matter more than they look:

* The Qt exclusions. A default PySide6 bundle drags in WebEngine, Quick, 3D,
  multimedia, charts and a pile of other modules ClamMac never touches, which
  roughly triples the download for no benefit.

* The privacy usage strings. macOS gates Desktop, Documents, Downloads and
  removable volumes behind TCC. Without a usage string the prompt cannot be
  shown, so the scan silently reads nothing at all -- which for an antivirus
  is the worst possible failure: it looks like it worked and found nothing.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(SPECPATH).parent
sys.path.insert(0, str(REPO_ROOT))

from PyInstaller.utils.hooks import collect_submodules  # noqa: E402

from clammac.version import APP_ID, APP_NAME, COPYRIGHT, VERSION  # noqa: E402

ICON = REPO_ROOT / "clammac" / "resources" / "ClamMac.icns"

# Qt modules ClamMac does not use. Each one is tens of megabytes.
EXCLUDED_QT = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras",
    "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DRender",
    "PySide6.QtBluetooth", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtLocation",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtNfc",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtPdf",
    "PySide6.QtPdfWidgets", "PySide6.QtPositioning", "PySide6.QtQuick",
    "PySide6.QtQuick3D", "PySide6.QtQuickControls2", "PySide6.QtQuickWidgets",
    "PySide6.QtQml", "PySide6.QtRemoteObjects", "PySide6.QtScxml",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSpatialAudio",
    "PySide6.QtSql", "PySide6.QtStateMachine", "PySide6.QtSvgWidgets",
    "PySide6.QtTest", "PySide6.QtTextToSpeech", "PySide6.QtUiTools",
    "PySide6.QtWebChannel", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebEngineWidgets", "PySide6.QtWebSockets", "PySide6.QtXml",
    "PySide6.QtHttpServer", "PySide6.QtGraphs",
]

EXCLUDED_OTHER = [
    "tkinter", "unittest", "pydoc_data", "test", "distutils",
    "numpy", "scipy", "pandas", "matplotlib", "PIL", "setuptools", "pip",
]

DATA_FILES = [
    (str(REPO_ROOT / "clammac" / "resources" / "engine_manifest.json"), "clammac/resources"),
    (str(REPO_ROOT / "LICENSE"), "."),
    (str(REPO_ROOT / "NOTICE.md"), "."),
    (str(REPO_ROOT / "README.md"), "."),
    # Qt and PySide6 ship inside this bundle under the LGPL-3.0, and section
    # 4(b) asks that a copy of that licence travel with the combined work --
    # linking to it is not the same as supplying it. RELINKING.md goes in for
    # the same reason: it is the section 4(d) procedure, and the About box
    # tells the reader to go and read it, so it has to be there to read.
    (str(REPO_ROOT / "LICENSES" / "LGPL-3.0.txt"), "LICENSES"),
    (str(REPO_ROOT / "docs" / "RELINKING.md"), "docs"),
]
if ICON.exists():
    DATA_FILES.append((str(ICON), "clammac/resources"))
# The in-app icon (window, About box, setup) is drawn from the same artwork.
DATA_FILES.append((str(REPO_ROOT / "clammac" / "resources" / "app-icon.png"), "clammac/resources"))

analysis = Analysis(
    [str(REPO_ROOT / "clammac" / "__main__.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=DATA_FILES,
    # Collected explicitly rather than left to the import graph. Qt is only
    # imported inside run_gui(), and the interface pages are reached through
    # a tuple of classes, so a missed edge here shows up as a bundle that
    # builds cleanly and then fails to start.
    hiddenimports=[
        *collect_submodules("clammac"),
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDED_QT + EXCLUDED_OTHER,
    noarchive=False,
    optimize=1,
)

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX breaks code signing on macOS
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    # build_app.py sets this to "universal2" when the running interpreter is
    # itself universal; asking for it otherwise just fails the build.
    target_arch=os.environ.get("CLAMMAC_TARGET_ARCH") or None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON) if ICON.exists() else None,
)

collection = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)

app = BUNDLE(
    collection,
    name=f"{APP_NAME}.app",
    icon=str(ICON) if ICON.exists() else None,
    bundle_identifier=APP_ID,
    version=VERSION,
    info_plist={
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": APP_NAME,
        "CFBundleIdentifier": APP_ID,
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "CFBundlePackageType": "APPL",
        "CFBundleSignature": "????",
        "CFBundleIconFile": "ClamMac.icns",
        "LSMinimumSystemVersion": "11.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHighResolutionCapable": True,
        "NSSupportsAutomaticGraphicsSwitching": True,
        "NSRequiresAquaSystemAppearance": False,
        "NSHumanReadableCopyright": (
            f"{COPYRIGHT}. Free software under the GNU General Public License "
            "version 3 or later. Not affiliated with Cisco Systems, Inc. "
            "ClamAV is a registered trademark of Cisco Systems, Inc."
        ),
        # Why ClamMac wants access to each protected location. macOS shows
        # these verbatim in the permission prompt.
        "NSDesktopFolderUsageDescription":
            f"{APP_NAME} scans your Desktop for malicious files.",
        "NSDocumentsFolderUsageDescription":
            f"{APP_NAME} scans your Documents folder for malicious files.",
        "NSDownloadsFolderUsageDescription":
            f"{APP_NAME} scans downloaded files for malware, which is where most "
            "threats arrive.",
        "NSRemovableVolumesUsageDescription":
            f"{APP_NAME} scans external drives and disk images you connect.",
        "NSNetworkVolumesUsageDescription":
            f"{APP_NAME} scans network volumes you ask it to check.",
        "NSFileProviderDomainUsageDescription":
            f"{APP_NAME} scans files stored in cloud folders you ask it to check.",
        "NSAppleEventsUsageDescription":
            f"{APP_NAME} uses this only if you choose to install the ClamAV engine "
            "system-wide, which requires an administrator prompt.",
        # Let files be dropped onto the Dock icon to scan them.
        "CFBundleDocumentTypes": [
            {
                "CFBundleTypeName": "Any file or folder",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "None",
                "LSItemContentTypes": ["public.item", "public.folder"],
            }
        ],
    },
)
