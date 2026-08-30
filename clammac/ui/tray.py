"""The menu bar item: status at a glance and the two actions people want most.

It also serves as the notification backend, so alerts appear under ClamMac's
own name and icon rather than through a generic scripting host.
"""

from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ..core.notifications import Notification, Urgency, notifier
from ..core.scanner import ScanKind
from ..core.service import Health, ProtectionStatus
from ..version import APP_NAME
from .icons import glyph
from .theme import Palette

__all__ = ["TrayIcon"]

_URGENCY_ICONS = {
    Urgency.INFO: QSystemTrayIcon.MessageIcon.Information,
    Urgency.WARNING: QSystemTrayIcon.MessageIcon.Warning,
    Urgency.THREAT: QSystemTrayIcon.MessageIcon.Critical,
}


class TrayIcon(QSystemTrayIcon):
    def __init__(self, window) -> None:
        super().__init__(window)
        self.window = window
        self.service = window.service
        self._palette: Palette | None = None

        self.menu = QMenu()
        self.status_action = QAction("Checking…", self.menu)
        self.status_action.setEnabled(False)
        self.menu.addAction(self.status_action)
        self.menu.addSeparator()

        open_action = QAction(f"Open {APP_NAME}", self.menu)
        open_action.triggered.connect(self._open)
        self.menu.addAction(open_action)

        quick_action = QAction("Quick Scan", self.menu)
        quick_action.triggered.connect(lambda: self._scan(ScanKind.QUICK))
        self.menu.addAction(quick_action)

        update_action = QAction("Update Definitions", self.menu)
        update_action.triggered.connect(self._update)
        self.menu.addAction(update_action)

        self.menu.addSeparator()
        self.protection_action = QAction("Turn On Real-Time Protection", self.menu)
        self.protection_action.triggered.connect(self._toggle_protection)
        self.menu.addAction(self.protection_action)

        self.menu.addSeparator()
        quit_action = QAction(f"Quit {APP_NAME}", self.menu)
        quit_action.triggered.connect(self._quit)
        self.menu.addAction(quit_action)

        self.setContextMenu(self.menu)
        self.activated.connect(self._activated)
        self.setToolTip(APP_NAME)

        notifier.set_backend(self._post)

    # -- appearance -------------------------------------------------------

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.refresh(self.service.status())

    def refresh(self, status: ProtectionStatus) -> None:
        palette = self._palette
        colour = "#8A929E"
        if palette is not None:
            colour = {
                Health.PROTECTED: palette.good,
                Health.ATTENTION: palette.warn,
                Health.AT_RISK: palette.danger,
                Health.SETTING_UP: palette.text_muted,
            }[status.health]

        name = "shield" if status.health is Health.PROTECTED else "warning"
        self.setIcon(glyph(name, colour, 18))
        self.status_action.setText(status.health.headline)
        self.setToolTip(
            f"{APP_NAME} — {status.health.headline}"
            + (f"\n{status.reasons[0]}" if status.reasons else "")
        )
        self.protection_action.setText(
            "Turn Off Real-Time Protection"
            if self.service.settings.protection.enabled
            else "Turn On Real-Time Protection"
        )

    # -- notification backend ---------------------------------------------

    def _post(self, notification: Notification) -> bool:
        if not self.isVisible() or not QSystemTrayIcon.supportsMessages():
            return False
        self.showMessage(
            notification.title,
            notification.body,
            _URGENCY_ICONS.get(notification.urgency, QSystemTrayIcon.MessageIcon.Information),
            8000,
        )
        return True

    # -- actions ----------------------------------------------------------

    def _activated(self, reason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._open()

    def _open(self) -> None:
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def _scan(self, kind: ScanKind) -> None:
        self._open()
        self.window.start_scan(kind)

    def _update(self) -> None:
        self._open()
        self.window.update_definitions()

    def _toggle_protection(self) -> None:
        if self.service.settings.protection.enabled:
            self.window.disable_protection()
        else:
            self._open()
            self.window.enable_protection()

    def _quit(self) -> None:
        from PySide6.QtWidgets import QApplication

        application = QApplication.instance()
        if application is not None:
            application.quit()
