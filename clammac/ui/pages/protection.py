"""Real-time protection: what is watched, and whether it is working."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QSpinBox,
    QVBoxLayout,
)

from ...core import paths
from ...core.watcher import WatcherState
from ..icons import glyph
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    Separator,
    SettingRow,
    button,
    caption,
    heading,
    label,
    subtitle,
)
from .base import Page

__all__ = ["ProtectionPage"]


class ProtectionPage(Page):
    page_title = "Protection"
    page_subtitle = "Check files the moment they arrive"
    page_icon = "pulse"

    def build(self) -> None:
        self._palette: Palette | None = None
        self._loading = False

        # -- the switch -------------------------------------------------
        self.toggle_card = Card(role="hero", padding=22)
        row = QHBoxLayout()
        row.setSpacing(18)

        self.state_icon = label()
        self.state_icon.setFixedSize(40, 40)
        self.state_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(self.state_icon, 0, Qt.AlignmentFlag.AlignTop)

        text_column = QVBoxLayout()
        text_column.setSpacing(4)
        self.state_heading = label("Real-time protection is off", role="heading")
        self.state_detail = subtitle("")
        text_column.addWidget(self.state_heading)
        text_column.addWidget(self.state_detail)
        row.addLayout(text_column, 1)

        self.toggle_button = button("Turn on", variant="primary", on_click=self.toggle)
        row.addWidget(self.toggle_button, 0, Qt.AlignmentFlag.AlignTop)
        self.toggle_card.add_layout(row)
        self.add(self.toggle_card)

        # -- what to watch ----------------------------------------------
        folders = Card()
        folders.add(heading("Folders to watch"))
        folders.add(
            caption(
                "Watching your whole home folder is thorough but busy. Downloads and the "
                "Desktop catch almost everything that arrives from outside."
            )
        )

        self.check_downloads = QCheckBox("Downloads")
        self.check_desktop = QCheckBox("Desktop")
        self.check_documents = QCheckBox("Documents")
        self.check_removable = QCheckBox("External drives and disk images")
        self.check_home = QCheckBox("My entire home folder")
        for widget in (
            self.check_downloads,
            self.check_desktop,
            self.check_documents,
            self.check_removable,
            self.check_home,
        ):
            widget.toggled.connect(self._save)
            folders.add(widget)
        self.check_home.toggled.connect(self._home_toggled)

        folders.add(Separator())
        folders.add(label("Additional folders", role="heading"))
        self.extra_list = QListWidget()
        self.extra_list.setMaximumHeight(120)
        self.extra_list.setAlternatingRowColors(True)
        folders.add(self.extra_list)

        extra_row = QHBoxLayout()
        extra_row.setSpacing(Metrics.GAP)
        extra_row.addWidget(button("Add folder…", on_click=self.add_folder))
        self.remove_button = button("Remove", on_click=self.remove_folder)
        extra_row.addWidget(self.remove_button)
        extra_row.addStretch(1)
        folders.add_layout(extra_row)
        self.add(folders)

        # -- behaviour ---------------------------------------------------
        behaviour = Card()
        behaviour.add(heading("Behaviour"))

        self.settle_spin = QSpinBox()
        self.settle_spin.setRange(0, 60)
        self.settle_spin.setSuffix(" seconds")
        self.settle_spin.valueChanged.connect(self._save)
        behaviour.add(
            SettingRow(
                "Wait before scanning a new file",
                self.settle_spin,
                hint="Gives downloads and copies time to finish before they are checked.",
            )
        )

        self.size_spin = QSpinBox()
        self.size_spin.setRange(1, 4096)
        self.size_spin.setSuffix(" MB")
        self.size_spin.valueChanged.connect(self._save)
        behaviour.add(
            SettingRow(
                "Skip files larger than",
                self.size_spin,
                hint="Very large files are slow to check and rarely how malware arrives.",
            )
        )
        self.add(behaviour)

        # -- activity -----------------------------------------------------
        self.activity = Card()
        self.activity.add(heading("Activity"))
        self.activity_label = subtitle("Real-time protection has not run yet.")
        self.activity.add(self.activity_label)
        self.watched_label = caption("")
        self.activity.add(self.watched_label)
        self.add(self.activity)

        self.bridge.statusChanged.connect(lambda _: self.refresh())
        self.bridge.watcherState.connect(lambda *_: self.refresh())

    # -- settings binding -------------------------------------------------

    def on_show(self) -> None:
        self.load()
        self.refresh()

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.toggle_card.shadow(palette)
        self.refresh()

    def load(self) -> None:
        self._loading = True
        protection = self.service.settings.protection
        self.check_downloads.setChecked(protection.watch_downloads)
        self.check_desktop.setChecked(protection.watch_desktop)
        self.check_documents.setChecked(protection.watch_documents)
        self.check_removable.setChecked(protection.watch_removable)
        self.check_home.setChecked(protection.watch_home)
        self.settle_spin.setValue(int(protection.settle_seconds))
        self.size_spin.setValue(protection.max_file_size_mb)
        self.extra_list.clear()
        for entry in protection.extra_paths:
            self.extra_list.addItem(QListWidgetItem(entry))
        self._home_toggled(protection.watch_home)
        self._loading = False

    def _save(self) -> None:
        if self._loading:
            return
        protection = self.service.settings.protection
        protection.watch_downloads = self.check_downloads.isChecked()
        protection.watch_desktop = self.check_desktop.isChecked()
        protection.watch_documents = self.check_documents.isChecked()
        protection.watch_removable = self.check_removable.isChecked()
        protection.watch_home = self.check_home.isChecked()
        protection.settle_seconds = float(self.settle_spin.value())
        protection.max_file_size_mb = self.size_spin.value()
        protection.extra_paths = [
            self.extra_list.item(i).text() for i in range(self.extra_list.count())
        ]
        self.service.save_settings()
        self.refresh()

    def _home_toggled(self, checked: bool) -> None:
        for widget in (self.check_downloads, self.check_desktop, self.check_documents):
            widget.setEnabled(not checked)

    # -- actions ----------------------------------------------------------

    def toggle(self) -> None:
        if self.service.settings.protection.enabled:
            self.window.disable_protection()
        else:
            self.window.enable_protection()

    def add_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Watch this folder", str(paths.home()))
        if not chosen:
            return
        existing = {self.extra_list.item(i).text() for i in range(self.extra_list.count())}
        if chosen in existing:
            return
        self.extra_list.addItem(QListWidgetItem(chosen))
        self._save()

    def remove_folder(self) -> None:
        for item in self.extra_list.selectedItems():
            self.extra_list.takeItem(self.extra_list.row(item))
        self._save()

    # -- display ----------------------------------------------------------

    def refresh(self) -> None:
        palette = self._palette or self.window.palette_tokens
        settings = self.service.settings.protection
        watcher = self.service.watcher
        state = watcher.state if watcher else WatcherState.STOPPED

        if not settings.enabled:
            colour, icon_name = palette.text_muted, "pulse"
            self.state_heading.setText("Real-time protection is off")
            self.state_detail.setText(
                "Files are only checked when you run a scan. Turning this on checks each "
                "file as it appears."
            )
            self.toggle_button.setText("Turn on")
        elif state is WatcherState.RUNNING:
            colour, icon_name = palette.good, "shield"
            self.state_heading.setText("Real-time protection is on")
            self.state_detail.setText(
                f"Watching {len(watcher.watched_paths)} folder"
                f"{'s' if len(watcher.watched_paths) != 1 else ''} for new files."
            )
            self.toggle_button.setText("Turn off")
        elif state is WatcherState.STARTING:
            colour, icon_name = palette.warn, "download"
            self.state_heading.setText("Starting…")
            self.state_detail.setText(
                "Loading the signature database into memory. This takes a moment the first time."
            )
            self.toggle_button.setText("Turn off")
        else:
            colour, icon_name = palette.danger, "warning"
            self.state_heading.setText("Real-time protection is not working")
            self.state_detail.setText(
                (watcher.detail if watcher else "") or "The background scanner could not start."
            )
            self.toggle_button.setText("Try again")

        self.state_icon.setPixmap(glyph(icon_name, colour, 36).pixmap(36, 36))

        if watcher is not None and watcher.scanned_count:
            self.activity_label.setText(
                f"{watcher.scanned_count:,} files checked since protection started, "
                f"{watcher.detection_count} threat"
                f"{'s' if watcher.detection_count != 1 else ''} caught."
            )
        elif settings.enabled:
            self.activity_label.setText("Watching. Nothing new has appeared yet.")
        else:
            self.activity_label.setText("Real-time protection has not run yet.")

        watched = settings.watched_paths()
        self.watched_label.setText(
            "Currently: " + ", ".join(paths.shorten(p, max_len=30) for p in watched)
            if watched
            else "No folders are selected."
        )
        self.remove_button.setEnabled(bool(self.extra_list.selectedItems()))
