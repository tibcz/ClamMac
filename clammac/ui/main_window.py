"""The main window: sidebar, pages, and the wiring between them and the core.

This is the only place that turns core callbacks into Qt signals (via
``ServiceBridge``) and the only place that starts work. Pages ask the window to
do things; the window asks the service; results come back through the bridge
and fan out to whichever pages care.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QDragEnterEvent, QDropEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..core import paths, reports
from ..core.log import get_logger
from ..core.notifications import Notification, Urgency, notifier
from ..core.scanner import ScanKind
from ..core.service import AppService, ProtectionStatus
from ..version import APP_NAME
from .bridge import ServiceBridge
from .icons import glyph
from .pages.dashboard import DashboardPage
from .pages.history import HistoryPage
from .pages.network import NetworkPage
from .pages.protection import ProtectionPage
from .pages.quarantine import QuarantinePage
from .pages.scan import ScanPage
from .pages.schedule import SchedulePage
from .pages.settings import SettingsPage
from .pages.updates import UpdatesPage
from .theme import Metrics, palette_for, stylesheet

log = get_logger(__name__)

__all__ = ["MainWindow"]

_PAGE_CLASSES = (
    DashboardPage,
    ScanPage,
    ProtectionPage,
    NetworkPage,
    QuarantinePage,
    UpdatesPage,
    SchedulePage,
    HistoryPage,
    SettingsPage,
)


class MainWindow(QMainWindow):
    def __init__(self, service: AppService) -> None:
        super().__init__()
        self.service = service
        self.bridge = ServiceBridge()
        self.palette_tokens = palette_for(service.settings.interface.theme)
        self.tray = None

        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(940, 660)
        self.resize(1080, 760)
        self.setAcceptDrops(True)

        self._build()
        self._connect()
        self.apply_theme()

        # The service reports status changes from worker threads; route them
        # through the bridge so pages are only ever touched on this thread.
        self.service.add_status_listener(self.bridge.statusChanged.emit)
        self.service.add_threat_listener(self.bridge.threatHandled.emit)

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(Metrics.SIDEBAR_WIDTH)
        self.sidebar.setIconSize(QSize(18, 18))
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.sidebar.currentRowChanged.connect(self._page_changed)
        layout.addWidget(self.sidebar)

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)

        self.stack = QStackedWidget()
        right.addWidget(self.stack, 1)

        self.toast = QLabel("")
        self.toast.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.toast.setProperty("role", "subtitle")
        self.toast.setFixedHeight(0)
        right.addWidget(self.toast)

        layout.addLayout(right, 1)
        self.setCentralWidget(central)

        self.pages: list = []
        for page_class in _PAGE_CLASSES:
            page = page_class(self)
            self.pages.append(page)
            self.stack.addWidget(page)
            item = QListWidgetItem(page.page_title)
            item.setSizeHint(QSize(0, Metrics.ROW_HEIGHT))
            self.sidebar.addItem(item)

        self.sidebar.setCurrentRow(0)
        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(lambda: self._set_toast(""))

        self._build_menus()

    def _build_menus(self) -> None:
        menubar = self.menuBar()

        scan_menu = menubar.addMenu("&Scan")
        quick = QAction("&Quick Scan", self)
        quick.setShortcut(QKeySequence("Ctrl+1"))
        quick.triggered.connect(lambda: self.start_scan(ScanKind.QUICK))
        scan_menu.addAction(quick)

        full = QAction("&Full Scan", self)
        full.setShortcut(QKeySequence("Ctrl+2"))
        full.triggered.connect(lambda: self.start_scan(ScanKind.FULL))
        scan_menu.addAction(full)

        choose = QAction("Scan &Folder…", self)
        choose.setShortcut(QKeySequence("Ctrl+O"))
        choose.triggered.connect(self.choose_and_scan)
        scan_menu.addAction(choose)

        scan_menu.addSeparator()
        stop = QAction("&Stop Scan", self)
        stop.setShortcut(QKeySequence("Ctrl+."))
        stop.triggered.connect(self.service.stop_scan)
        scan_menu.addAction(stop)

        tools = menubar.addMenu("&Tools")
        audit = QAction("Run &Network Audit", self)
        audit.setShortcut(QKeySequence("Ctrl+3"))
        audit.triggered.connect(self.run_network_audit)
        tools.addAction(audit)

        tools.addSeparator()
        update = QAction("&Update Definitions", self)
        update.setShortcut(QKeySequence("Ctrl+U"))
        update.triggered.connect(self.update_definitions)
        tools.addAction(update)

        selftest = QAction("Run Self-&Test", self)
        selftest.triggered.connect(self.run_self_test)
        tools.addAction(selftest)

        tools.addSeparator()
        logs = QAction("Open &Log Folder", self)
        logs.triggered.connect(lambda: self.reveal(paths.logs_dir()))
        tools.addAction(logs)

        help_menu = menubar.addMenu("&Help")
        about = QAction(f"About {APP_NAME}", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)

    def _connect(self) -> None:
        self.bridge.statusChanged.connect(self._on_status)

    # -- theming ----------------------------------------------------------

    def apply_theme(self) -> None:
        self.palette_tokens = palette_for(self.service.settings.interface.theme)
        application = QApplication.instance()
        if application is not None:
            application.setStyleSheet(stylesheet(self.palette_tokens))

        for index, page in enumerate(self.pages):
            item = self.sidebar.item(index)
            item.setIcon(glyph(page.page_icon, self.palette_tokens.text_muted, 18))
            page.apply_palette(self.palette_tokens)

        if self.tray is not None:
            self.tray.apply_palette(self.palette_tokens)

    def apply_interface_settings(self) -> None:
        """React to interface toggles the settings page just changed."""
        notifier.set_enabled(self.service.settings.interface.notifications)
        if self.tray is not None:
            self.tray.setVisible(self.service.settings.interface.show_menu_bar_item)

    # -- navigation -------------------------------------------------------

    def _page_changed(self, row: int) -> None:
        if not 0 <= row < len(self.pages):
            return
        for index, page in enumerate(self.pages):
            if index != row:
                page.on_hide()
        self.stack.setCurrentIndex(row)
        self.pages[row].on_show()

    def show_page(self, page_class: type) -> None:
        for index, page in enumerate(self.pages):
            if isinstance(page, page_class):
                self.sidebar.setCurrentRow(index)
                return

    def _page(self, page_class: type):
        for page in self.pages:
            if isinstance(page, page_class):
                return page
        return None

    # -- scanning ---------------------------------------------------------

    def start_scan(self, kind: ScanKind, targets: list[Path] | None = None) -> None:
        if self.service.engine is None:
            self.run_setup()
            return

        scan_page = self._page(ScanPage)
        try:
            self.service.start_scan(
                kind,
                targets,
                on_progress=self.bridge.scanProgress.emit,
                on_detection=self.bridge.scanDetection.emit,
                on_finished=self.bridge.scanFinished.emit,
            )
        except (RuntimeError, ValueError) as exc:
            QMessageBox.information(self, "Cannot start the scan", str(exc))
            return

        self.show_page(ScanPage)
        if scan_page is not None:
            scan_page.scan_started()

    def choose_and_scan(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose a folder to scan", str(paths.home())
        )
        if chosen:
            self.start_scan(ScanKind.CUSTOM, [Path(chosen)])

    def run_self_test(self) -> None:
        if self.service.engine is None:
            self.run_setup()
            return

        def finished(job) -> None:
            found = any("eicar" in d.signature.lower() for d in job.detections)
            self.bridge.provisionFinished.emit(
                found,
                "ClamMac detected the standard EICAR test file, so scanning is working "
                "correctly."
                if found
                else "The test file was not detected. Check that the virus definitions "
                "have finished downloading.",
            )

        try:
            self.service.run_self_test(on_finished=finished)
        except (RuntimeError, ValueError) as exc:
            QMessageBox.information(self, "Cannot run the self-test", str(exc))
            return
        self.show_toast("Running self-test…")

    def export_last_scan(self) -> None:
        last = self.service.history.last_scan()
        if last is None:
            QMessageBox.information(self, "Nothing to export", "No scans have been run yet.")
            return
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Export scan report",
            str(paths.home() / "Downloads" / "ClamMac scan report.html"),
            "Web page (*.html);;Spreadsheet (*.csv);;JSON (*.json)",
        )
        if not destination:
            return
        suffix = Path(destination).suffix.lstrip(".") or "html"
        try:
            written = reports.write_report(
                Path(destination),
                [last],
                self.service.history.detections(scan_id=last.id),
                fmt=suffix,
                title=f"{last.kind.title()} scan report",
            )
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not export", str(exc))
            return
        self.show_toast(f"Exported to {written.name}")

    # -- definitions ------------------------------------------------------

    def update_definitions(self) -> None:
        if self.service.engine is None:
            self.run_setup()
            return
        page = self._page(UpdatesPage)
        self.show_page(UpdatesPage)
        if page is not None:
            page.update_started()
        job = self.service.update_definitions(
            on_progress=self.bridge.updateProgress.emit,
            on_finished=self.bridge.updateFinished.emit,
        )
        job.on_log = self.bridge.updateLog.emit

    # -- network audit ----------------------------------------------------

    def run_network_audit(self) -> None:
        """Audit the machine's network exposure.

        Deliberately does not require the engine: the audit reads the Mac's own
        configuration, so it is useful on a fresh install before ClamAV has
        even been downloaded.
        """
        page = self._page(NetworkPage)
        try:
            self.service.start_network_audit(
                on_progress=self.bridge.auditProgress.emit,
                on_finished=self.bridge.auditFinished.emit,
            )
        except RuntimeError as exc:
            QMessageBox.information(self, "Cannot start the audit", str(exc))
            return
        self.show_page(NetworkPage)
        if page is not None:
            page.audit_started()

    # -- protection -------------------------------------------------------

    def enable_protection(self) -> None:
        if self.service.engine is None:
            self.run_setup()
            return
        self.service.settings.protection.enabled = True
        self.service.save_settings()
        self.show_toast("Starting real-time protection… this takes a moment.")

        def start() -> None:
            if not self.service.start_protection():
                self.service.settings.protection.enabled = False
                self.service.save_settings()
                QMessageBox.warning(
                    self,
                    "Real-time protection could not start",
                    (self.service.watcher.detail if self.service.watcher else "")
                    or "The background scanner could not be started. The log may say why.",
                )
            self._on_status(self.service.status())

        QTimer.singleShot(50, start)

    def disable_protection(self) -> None:
        self.service.settings.protection.enabled = False
        self.service.save_settings()
        self.service.stop_protection()
        self.show_toast("Real-time protection turned off.")

    # -- setup ------------------------------------------------------------

    def run_setup(self, *, force: bool = False) -> None:
        from .setup_wizard import SetupWizard

        wizard = SetupWizard(self.service, self, force=force)
        wizard.exec()
        self.service.refresh_engine()
        self._on_status(self.service.status())
        for page in self.pages:
            page.on_show()

    # -- status and feedback ----------------------------------------------

    def _on_status(self, status: ProtectionStatus) -> None:
        dashboard = self._page(DashboardPage)
        if dashboard is not None:
            dashboard.refresh(status)
        if self.tray is not None:
            self.tray.refresh(status)

    def show_toast(self, message: str, seconds: int = 4) -> None:
        self._set_toast(message)
        self._toast_timer.start(seconds * 1000)

    def _set_toast(self, message: str) -> None:
        self.toast.setText(message)
        self.toast.setFixedHeight(30 if message else 0)

    def reveal(self, path: Path) -> None:
        """Show a folder in the Finder."""
        import subprocess

        path.mkdir(parents=True, exist_ok=True)
        if paths.is_macos():
            subprocess.Popen(["/usr/bin/open", str(path)])
        else:
            self.show_toast(str(path))

    def show_about(self) -> None:
        from .about import AboutDialog

        AboutDialog(self).exec()

    # -- drag and drop ----------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        targets = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if url.isLocalFile() and Path(url.toLocalFile()).exists()
        ]
        if targets:
            event.acceptProposedAction()
            self.start_scan(ScanKind.CUSTOM, targets)

    # -- lifecycle --------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        """Closing the window keeps protection running, unless told otherwise.

        An antivirus that stops protecting the moment its window is closed is
        not much of an antivirus, so by default ClamMac stays in the menu bar.
        """
        interface = self.service.settings.interface
        if interface.close_to_menu_bar and self.tray is not None and self.tray.isVisible():
            event.ignore()
            self.hide()
            if not getattr(self, "_explained_menu_bar", False):
                self._explained_menu_bar = True
                notifier.post(
                    Notification(
                        "ClamMac is still running",
                        "Protection continues in the background. Use the menu bar icon to "
                        "open it again, or quit from there.",
                        Urgency.INFO,
                    )
                )
            return
        event.accept()
