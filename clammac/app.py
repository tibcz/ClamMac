"""Application startup, in all the modes ClamMac can be launched in.

Three of them are headless, fired by launchd: a scheduled scan, a definition
update, and a login-time start. They share every code path with the interactive
application except for Qt itself, which is never started for the first two.
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from .core import config as config_module
from .core import launchagent, paths, scheduler
from .core.log import configure, get_logger
from .core.notifications import notifier
from .core.scanner import ScanKind
from .core.service import AppService
from .version import APP_ID, APP_NAME, VERSION

log = get_logger(__name__)

__all__ = ["main", "run_definition_update", "run_gui", "run_scheduled_scan"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clammac",
        description=f"{APP_NAME} {VERSION} -- a macOS front end for the ClamAV scanning engine.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    parser.add_argument(
        "--background",
        action="store_true",
        help="start without showing the window (used by the login item)",
    )
    parser.add_argument(
        "--scheduled-scan",
        metavar="TARGET",
        help="run a scan with no interface: 'quick', 'full', or a path",
    )
    parser.add_argument(
        "--update-definitions",
        action="store_true",
        help="update the virus definitions with no interface",
    )
    parser.add_argument(
        "--scan",
        metavar="PATH",
        nargs="+",
        help="open the application and immediately scan these paths",
    )
    parser.add_argument("--verbose", action="store_true", help="log at debug level")
    return parser


# --------------------------------------------------------------------------
# headless modes
# --------------------------------------------------------------------------


def run_scheduled_scan(target: str) -> int:
    """Run a scan with no interface. Invoked by launchd."""
    service = AppService()
    if service.engine is None:
        log.error("scheduled scan skipped: no ClamAV engine is installed")
        return 2

    if target == "quick":
        kind, targets = ScanKind.SCHEDULED, paths.quick_scan_targets()
    elif target == "full":
        kind, targets = ScanKind.SCHEDULED, paths.default_scan_targets()
    else:
        candidate = Path(target).expanduser()
        if not candidate.exists():
            log.error("scheduled scan target does not exist: %s", candidate)
            return 2
        kind, targets = ScanKind.SCHEDULED, [candidate]

    log.info("starting scheduled scan of %s", ", ".join(str(t) for t in targets))
    job = service.start_scan(kind, targets)
    job.wait()
    service.shutdown()
    log.info(
        "scheduled scan finished: %d files, %d threats", job.scanned, len(job.detections)
    )
    return 1 if job.detections else 0


def run_definition_update() -> int:
    """Update definitions with no interface. Invoked by launchd."""
    service = AppService()
    if service.engine is None:
        log.error("definition update skipped: no ClamAV engine is installed")
        return 2
    job = service.update_definitions(blocking=True)
    service.shutdown()
    from .core.freshclam import UpdateOutcome

    return 0 if job.outcome is not UpdateOutcome.FAILED else 1


# --------------------------------------------------------------------------
# interactive mode
# --------------------------------------------------------------------------


def run_gui(arguments: argparse.Namespace) -> int:
    # Imported here so the headless modes never pay for loading Qt.
    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication, QSystemTrayIcon

    from .ui.icons import app_icon_pixmap
    from .ui.main_window import MainWindow
    from .ui.theme import default_font
    from .ui.tray import TrayIcon

    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setApplicationDisplayName(APP_NAME)
    application.setOrganizationDomain(APP_ID)
    application.setApplicationVersion(VERSION)
    application.setWindowIcon(QIcon(app_icon_pixmap(512)))
    application.setFont(default_font())
    # Closing the window leaves protection running in the menu bar, so the
    # application must not exit just because no window is visible.
    application.setQuitOnLastWindowClosed(False)

    service = AppService()
    window = MainWindow(service)

    if service.settings.interface.show_menu_bar_item and QSystemTrayIcon.isSystemTrayAvailable():
        window.tray = TrayIcon(window)
        window.tray.show()
        window.tray.apply_palette(window.palette_tokens)

    if not arguments.background:
        window.show()

    def after_start() -> None:
        service.notify_status()

        if not service.settings.interface.completed_first_run or service.engine is None:
            window.run_setup()
        else:
            if service.settings.protection.enabled:
                service.start_protection()
            if service.settings.updates.update_on_launch and scheduler.update_due(
                service.settings
            ).due:
                window.update_definitions()

        if paths.is_macos():
            launchagent.sync_all(service.settings)

        if arguments.scan:
            targets = [Path(p).expanduser() for p in arguments.scan]
            existing = [p for p in targets if p.exists()]
            if existing:
                window.show()
                window.start_scan(ScanKind.CUSTOM, existing)

    QTimer.singleShot(120, after_start)

    # Ctrl-C in a terminal should close the app rather than be swallowed by Qt.
    signal.signal(signal.SIGINT, lambda *_: application.quit())
    keepalive = QTimer()
    keepalive.start(400)
    keepalive.timeout.connect(lambda: None)

    application.aboutToQuit.connect(service.shutdown)
    return application.exec()


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    configure(verbose=arguments.verbose)
    paths.ensure_tree()

    settings = config_module.load()
    notifier.set_enabled(settings.interface.notifications)
    notifier.set_sound_enabled(settings.interface.sound_on_threat)

    if arguments.scheduled_scan:
        return run_scheduled_scan(arguments.scheduled_scan)
    if arguments.update_definitions:
        return run_definition_update()
    return run_gui(arguments)
