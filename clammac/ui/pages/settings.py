"""Everything configurable, grouped by what it affects."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSpinBox,
)

from ...core import paths
from ...core.config import ScanDepth, Theme, ThreatAction
from ...core.engine import database_info
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    Separator,
    SettingRow,
    button,
    caption,
    heading,
    human_size,
    label,
    subtitle,
)
from .base import Page

__all__ = ["SettingsPage"]


class SettingsPage(Page):
    page_title = "Settings"
    page_subtitle = "How ClamMac scans, and how it behaves"
    page_icon = "gear"

    def build(self) -> None:
        self._loading = False
        self._build_scanning()
        self._build_exclusions()
        self._build_appearance()
        self._build_engine()
        self._build_about()

    # -- scanning ---------------------------------------------------------

    def _build_scanning(self) -> None:
        card = Card()
        card.add(heading("Scanning"))

        self.depth_box = QComboBox()
        for depth in ScanDepth:
            self.depth_box.addItem(depth.label, depth.value)
        self.depth_box.currentIndexChanged.connect(self._depth_changed)
        card.add(
            SettingRow(
                "Thoroughness",
                self.depth_box,
                hint="Thorough looks deeper into archives and large files, and takes longer.",
            )
        )

        self.action_box = QComboBox()
        for action in ThreatAction:
            self.action_box.addItem(action.label, action.value)
        self.action_box.currentIndexChanged.connect(self._save)
        card.add(
            SettingRow(
                "When a threat is found",
                self.action_box,
                hint="Quarantine is recommended: it isolates the file but keeps it recoverable.",
            )
        )

        self.low_priority = QCheckBox("Run scans at low priority so the Mac stays responsive")
        self.low_priority.toggled.connect(self._save)
        card.add(self.low_priority)

        card.add(Separator())
        card.add(label("Look inside", role="heading"))

        formats = QGridLayout()
        formats.setHorizontalSpacing(Metrics.GAP_WIDE)
        self.format_checks: dict[str, QCheckBox] = {}
        entries = [
            ("scan_archives", "Archives (zip, rar, 7z…)"),
            ("scan_mail", "Mail files and attachments"),
            ("scan_pdf", "PDF documents"),
            ("scan_ole2", "Office documents"),
            ("scan_html", "HTML and scripts"),
            ("scan_executables", "Programs and libraries"),
            ("scan_images", "Images"),
            ("detect_pua", "Unwanted software (may flag legitimate tools)"),
        ]
        for index, (name, text) in enumerate(entries):
            checkbox = QCheckBox(text)
            checkbox.toggled.connect(self._save)
            self.format_checks[name] = checkbox
            formats.addWidget(checkbox, index // 2, index % 2)
        card.add_layout(formats)

        card.add(Separator())
        card.add(label("Limits", role="heading"))
        card.add(
            caption(
                "These bound how much work a single hostile archive can force the scanner "
                "to do. Raising them finds more but costs time."
            )
        )

        limits = QGridLayout()
        limits.setHorizontalSpacing(Metrics.GAP_WIDE)
        limits.setVerticalSpacing(8)
        limits.setColumnStretch(1, 1)
        self.max_file = _spin(1, 8192, " MB")
        self.max_scan = _spin(1, 16384, " MB")
        self.max_recursion = _spin(1, 64, "")
        self.max_files = _spin(100, 500000, "")
        for index, (text, widget) in enumerate(
            [
                ("Largest file to scan", self.max_file),
                ("Largest total scan per container", self.max_scan),
                ("Maximum nesting depth", self.max_recursion),
                ("Maximum files per container", self.max_files),
            ]
        ):
            widget.valueChanged.connect(self._save)
            limits.addWidget(label(text, tone="muted"), index, 0)
            limits.addWidget(widget, index, 1, Qt.AlignmentFlag.AlignRight)
        card.add_layout(limits)
        self.add(card)

    # -- exclusions -------------------------------------------------------

    def _build_exclusions(self) -> None:
        card = Card()
        card.add(heading("Exclusions"))
        self.exclusion_warning = caption("")
        card.add(self.exclusion_warning)

        card.add(label("Folders and files to skip", role="heading"))
        self.exclusion_list = QListWidget()
        self.exclusion_list.setMaximumHeight(120)
        self.exclusion_list.setAlternatingRowColors(True)
        card.add(self.exclusion_list)

        row = QHBoxLayout()
        row.setSpacing(Metrics.GAP)
        row.addWidget(button("Add folder…", on_click=self.add_exclusion))
        row.addWidget(button("Remove", on_click=self.remove_exclusion))
        row.addStretch(1)
        card.add_layout(row)

        card.add(Separator())
        self.extension_field = QLineEdit()
        self.extension_field.setPlaceholderText("iso, dmg, mp4")
        self.extension_field.editingFinished.connect(self._save)
        card.add(
            SettingRow(
                "Skip these file extensions",
                self.extension_field,
                hint="Comma separated. Leave empty to scan everything.",
            )
        )
        self.add(card)

    # -- appearance and behaviour ----------------------------------------

    def _build_appearance(self) -> None:
        card = Card()
        card.add(heading("Appearance and behaviour"))

        self.theme_box = QComboBox()
        for theme in Theme:
            self.theme_box.addItem(theme.label, theme.value)
        self.theme_box.currentIndexChanged.connect(self._theme_changed)
        card.add(SettingRow("Appearance", self.theme_box))

        self.menu_bar_check = QCheckBox("Show ClamMac in the menu bar")
        self.launch_check = QCheckBox("Open ClamMac when I log in")
        self.close_check = QCheckBox("Keep running in the menu bar when the window is closed")
        self.notify_check = QCheckBox("Show notifications")
        self.sound_check = QCheckBox("Play a sound when a threat is found")
        self.confirm_check = QCheckBox("Ask before deleting quarantined files")
        for widget in (
            self.menu_bar_check,
            self.launch_check,
            self.close_check,
            self.notify_check,
            self.sound_check,
            self.confirm_check,
        ):
            widget.toggled.connect(self._save)
            card.add(widget)
        self.add(card)

    # -- engine -----------------------------------------------------------

    def _build_engine(self) -> None:
        card = Card()
        card.add(heading("Scanning engine"))
        card.add(
            caption(
                "ClamMac uses the ClamAV engine, which it installs into its own folder in "
                "your home directory. ClamAV is a separate program with its own licence."
            )
        )

        grid = QGridLayout()
        grid.setHorizontalSpacing(Metrics.GAP_WIDE)
        grid.setVerticalSpacing(8)
        grid.setColumnStretch(1, 1)
        self._engine_values: dict[str, QLabel] = {}
        for index, name in enumerate(("Version", "Installed from", "Location", "Disk used")):
            grid.addWidget(label(name, tone="muted"), index, 0)
            value = label("—")
            value.setWordWrap(True)
            self._engine_values[name] = value
            grid.addWidget(value, index, 1)
        card.add_layout(grid)

        row = QHBoxLayout()
        row.setSpacing(Metrics.GAP)
        row.addWidget(button("Reinstall engine…", on_click=self.reinstall_engine))
        row.addWidget(button("Run self-test", on_click=self.window.run_self_test))
        row.addWidget(button("Open log folder", variant="ghost", on_click=self.open_logs))
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)

    def _build_about(self) -> None:
        card = Card()
        card.add(heading("About ClamMac"))
        self.about_label = subtitle("")
        card.add(self.about_label)
        row = QHBoxLayout()
        row.setSpacing(Metrics.GAP)
        row.addWidget(button("Licences and attributions", on_click=self.window.show_about))
        row.addWidget(
            button("Reset all settings", variant="ghost", on_click=self.reset_settings)
        )
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)

    # -- binding ----------------------------------------------------------

    def on_show(self) -> None:
        self.load()

    def apply_palette(self, palette: Palette) -> None:
        self.load()

    def load(self) -> None:
        self._loading = True
        settings = self.service.settings
        scan = settings.scan
        interface = settings.interface

        self.depth_box.setCurrentIndex(max(0, self.depth_box.findData(scan.depth.value)))
        self.action_box.setCurrentIndex(max(0, self.action_box.findData(scan.on_threat.value)))
        self.low_priority.setChecked(scan.low_priority)
        for name, checkbox in self.format_checks.items():
            checkbox.setChecked(bool(getattr(scan, name)))
        self.max_file.setValue(scan.max_file_size_mb)
        self.max_scan.setValue(scan.max_scan_size_mb)
        self.max_recursion.setValue(scan.max_recursion)
        self.max_files.setValue(scan.max_files)

        self.exclusion_list.clear()
        for entry in settings.exclusions.paths:
            self.exclusion_list.addItem(QListWidgetItem(entry))
        self.extension_field.setText(", ".join(settings.exclusions.extensions))

        self.theme_box.setCurrentIndex(max(0, self.theme_box.findData(interface.theme.value)))
        self.menu_bar_check.setChecked(interface.show_menu_bar_item)
        self.launch_check.setChecked(interface.launch_at_login)
        self.close_check.setChecked(interface.close_to_menu_bar)
        self.notify_check.setChecked(interface.notifications)
        self.sound_check.setChecked(interface.sound_on_threat)
        self.confirm_check.setChecked(interface.confirm_before_delete)

        self._loading = False
        self._refresh_engine()
        self._refresh_exclusion_warning()

    def _save(self) -> None:
        if self._loading:
            return
        settings = self.service.settings
        scan = settings.scan
        interface = settings.interface

        scan.on_threat = ThreatAction(self.action_box.currentData())
        scan.low_priority = self.low_priority.isChecked()
        for name, checkbox in self.format_checks.items():
            setattr(scan, name, checkbox.isChecked())
        scan.max_file_size_mb = self.max_file.value()
        scan.max_scan_size_mb = self.max_scan.value()
        scan.max_recursion = self.max_recursion.value()
        scan.max_files = self.max_files.value()

        settings.exclusions.paths = [
            self.exclusion_list.item(i).text() for i in range(self.exclusion_list.count())
        ]
        settings.exclusions.extensions = [
            part.strip().lstrip(".")
            for part in self.extension_field.text().split(",")
            if part.strip()
        ]

        interface.show_menu_bar_item = self.menu_bar_check.isChecked()
        interface.launch_at_login = self.launch_check.isChecked()
        interface.close_to_menu_bar = self.close_check.isChecked()
        interface.notifications = self.notify_check.isChecked()
        interface.sound_on_threat = self.sound_check.isChecked()
        interface.confirm_before_delete = self.confirm_check.isChecked()

        self.service.save_settings()
        self.window.apply_interface_settings()
        self._refresh_exclusion_warning()

    def _depth_changed(self) -> None:
        if self._loading:
            return
        scan = self.service.settings.scan
        scan.depth = ScanDepth(self.depth_box.currentData())
        scan.apply_depth()
        self.service.save_settings()
        self.load()

    def _theme_changed(self) -> None:
        if self._loading:
            return
        self.service.settings.interface.theme = Theme(self.theme_box.currentData())
        self.service.save_settings()
        self.window.apply_theme()

    # -- actions ----------------------------------------------------------

    def add_exclusion(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Never scan this folder", str(paths.home())
        )
        if not chosen:
            return
        existing = {self.exclusion_list.item(i).text() for i in range(self.exclusion_list.count())}
        if chosen not in existing:
            self.exclusion_list.addItem(QListWidgetItem(chosen))
            self._save()

    def remove_exclusion(self) -> None:
        for item in self.exclusion_list.selectedItems():
            self.exclusion_list.takeItem(self.exclusion_list.row(item))
        self._save()

    def reinstall_engine(self) -> None:
        answer = QMessageBox.question(
            self,
            "Reinstall the scanning engine?",
            "ClamMac will download a fresh copy of the ClamAV engine and replace the "
            "current one.\n\nYour virus definitions, quarantine and history are not "
            "affected.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.window.run_setup(force=True)

    def open_logs(self) -> None:
        self.window.reveal(paths.logs_dir())

    def reset_settings(self) -> None:
        answer = QMessageBox.question(
            self,
            "Reset all settings?",
            "Put every setting back to its default?\n\n"
            "Your quarantine, history and virus definitions are not affected.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        from ...core.config import Settings

        keep_engine = self.service.settings.engine_path
        keep_version = self.service.settings.engine_version
        self.service.settings = Settings()
        self.service.settings.engine_path = keep_engine
        self.service.settings.engine_version = keep_version
        self.service.settings.interface.completed_first_run = True
        self.service.save_settings()
        self.window.apply_theme()
        self.load()

    # -- display ----------------------------------------------------------

    def _refresh_engine(self) -> None:
        engine = self.service.engine
        if engine is None:
            for value in self._engine_values.values():
                value.setText("Not installed")
        else:
            self._engine_values["Version"].setText(f"ClamAV {engine.engine_version}")
            self._engine_values["Installed from"].setText(engine.tools.origin)
            self._engine_values["Location"].setText(str(engine.tools.root.parent))
            database = database_info()
            engine_bytes = _directory_size(engine.tools.root.parent)
            self._engine_values["Disk used"].setText(
                f"{human_size(engine_bytes)} engine + {human_size(database.total_bytes)} definitions"
            )

        from ...version import APP_NAME, COPYRIGHT, HOMEPAGE, VERSION

        self.about_label.setText(
            f"{APP_NAME} {VERSION} — {COPYRIGHT}\n"
            "Free software under the GNU General Public License, version 3 or later.\n"
            f"{HOMEPAGE}"
        )

    def _refresh_exclusion_warning(self) -> None:
        settings = self.service.settings.exclusions
        count = len(settings.paths) + len(settings.extensions)
        if count:
            self.exclusion_warning.setText(
                f"{count} exclusion{'s' if count != 1 else ''} in effect. Excluded locations "
                "are never checked, by any scan or by real-time protection."
            )
        else:
            self.exclusion_warning.setText(
                "Nothing is excluded. Every exclusion is somewhere malware could hide, so "
                "add them sparingly."
            )


def _spin(minimum: int, maximum: int, suffix: str) -> QSpinBox:
    widget = QSpinBox()
    widget.setRange(minimum, maximum)
    widget.setSuffix(suffix)
    widget.setMaximumWidth(150)
    return widget


def _directory_size(root: Path) -> int:
    total = 0
    try:
        for item in root.rglob("*"):
            if item.is_file() and not item.is_symlink():
                try:
                    total += item.stat().st_size
                except OSError:
                    continue
    except OSError:
        pass
    return total
