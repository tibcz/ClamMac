"""Unattended scans, handed to launchd so they run whether ClamMac is open."""

from __future__ import annotations

from PySide6.QtCore import QTime
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QSpinBox,
    QTimeEdit,
)

from ...core import launchagent, paths
from ...core.config import Frequency
from ...core.scheduler import describe_schedule, describe_target, next_occurrence
from ..theme import Metrics, Palette
from ..widgets.common import Card, SettingRow, button, caption, heading, label, subtitle
from .base import Page

__all__ = ["SchedulePage"]

_WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


class SchedulePage(Page):
    page_title = "Schedule"
    page_subtitle = "Scan on a timetable, without being asked"
    page_icon = "clock"

    def build(self) -> None:
        self._loading = False
        self._custom_target = ""

        card = Card()
        header = QHBoxLayout()
        header.addWidget(heading("Scheduled scans"))
        header.addStretch(1)
        self.enable_check = QCheckBox("Enabled")
        self.enable_check.toggled.connect(self._save)
        header.addWidget(self.enable_check)
        card.add_layout(header)
        card.add(
            caption(
                "ClamMac registers the schedule with macOS, so a scan still runs at the "
                "chosen time even if ClamMac is closed. Your Mac must be awake."
            )
        )

        grid = QGridLayout()
        grid.setHorizontalSpacing(Metrics.GAP_WIDE)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 1)

        self.frequency_box = QComboBox()
        for frequency in Frequency:
            self.frequency_box.addItem(frequency.label, frequency.value)
        self.frequency_box.currentIndexChanged.connect(self._frequency_changed)
        grid.addWidget(label("How often", tone="muted"), 0, 0)
        grid.addWidget(self.frequency_box, 0, 1)

        self.time_edit = QTimeEdit()
        self.time_edit.setDisplayFormat("HH:mm")
        self.time_edit.timeChanged.connect(self._save)
        grid.addWidget(label("At", tone="muted"), 1, 0)
        grid.addWidget(self.time_edit, 1, 1)

        self.weekday_box = QComboBox()
        self.weekday_box.addItems(_WEEKDAYS)
        self.weekday_box.currentIndexChanged.connect(self._save)
        self.weekday_label = label("On", tone="muted")
        grid.addWidget(self.weekday_label, 2, 0)
        grid.addWidget(self.weekday_box, 2, 1)

        self.day_spin = QSpinBox()
        self.day_spin.setRange(1, 28)
        self.day_spin.setPrefix("Day ")
        self.day_spin.valueChanged.connect(self._save)
        self.day_label = label("On", tone="muted")
        grid.addWidget(self.day_label, 3, 0)
        grid.addWidget(self.day_spin, 3, 1)

        self.target_box = QComboBox()
        self.target_box.addItem("Quick scan", "quick")
        self.target_box.addItem("Full scan", "full")
        self.target_box.addItem("A specific folder…", "custom")
        self.target_box.currentIndexChanged.connect(self._target_changed)
        grid.addWidget(label("What to scan", tone="muted"), 4, 0)
        grid.addWidget(self.target_box, 4, 1)

        card.add_layout(grid)

        self.custom_row = QHBoxLayout()
        self.custom_label = caption("")
        self.custom_row.addWidget(self.custom_label, 1)
        self.custom_button = button("Choose…", variant="ghost", on_click=self.choose_folder)
        self.custom_row.addWidget(self.custom_button)
        card.add_layout(self.custom_row)

        self.summary = subtitle("")
        card.add(self.summary)
        self.add(card)

        # -- automatic updates -------------------------------------------
        updates = Card()
        updates.add(heading("Automatic definition updates"))
        self.auto_update_check = QCheckBox("Keep virus definitions up to date automatically")
        self.auto_update_check.toggled.connect(self._save)
        updates.add(self.auto_update_check)

        self.update_frequency = QComboBox()
        for frequency in Frequency:
            self.update_frequency.addItem(frequency.label, frequency.value)
        self.update_frequency.currentIndexChanged.connect(self._save)
        updates.add(SettingRow("Check for new definitions", self.update_frequency))

        self.update_on_launch = QCheckBox("Also check when ClamMac starts")
        self.update_on_launch.toggled.connect(self._save)
        updates.add(self.update_on_launch)
        self.add(updates)

        # -- agent status --------------------------------------------------
        self.status_card = Card()
        self.status_card.add(heading("Registered with macOS"))
        self.status_body = QLabel("")
        self.status_body.setWordWrap(True)
        self.status_body.setProperty("role", "caption")
        self.status_card.add(self.status_body)
        self.add(self.status_card)

    # -- binding -----------------------------------------------------------

    def on_show(self) -> None:
        self.load()

    def apply_palette(self, palette: Palette) -> None:
        self._refresh_summary()

    def load(self) -> None:
        self._loading = True
        schedule = self.service.settings.schedule
        updates = self.service.settings.updates

        self.enable_check.setChecked(schedule.enabled)
        self.frequency_box.setCurrentIndex(
            max(0, self.frequency_box.findData(schedule.frequency.value))
        )
        self.time_edit.setTime(QTime(schedule.hour, schedule.minute))
        self.weekday_box.setCurrentIndex(max(0, min(6, schedule.weekday)))
        self.day_spin.setValue(schedule.day_of_month)

        if schedule.target in ("quick", "full"):
            self.target_box.setCurrentIndex(self.target_box.findData(schedule.target))
            self._custom_target = ""
        else:
            self.target_box.setCurrentIndex(self.target_box.findData("custom"))
            self._custom_target = schedule.target

        self.auto_update_check.setChecked(updates.auto_update)
        self.update_frequency.setCurrentIndex(
            max(0, self.update_frequency.findData(updates.frequency.value))
        )
        self.update_on_launch.setChecked(updates.update_on_launch)

        self._loading = False
        self._frequency_changed()
        self._target_changed()

    def _save(self) -> None:
        if self._loading:
            return
        schedule = self.service.settings.schedule
        updates = self.service.settings.updates

        schedule.enabled = self.enable_check.isChecked()
        schedule.frequency = Frequency(self.frequency_box.currentData())
        time_value = self.time_edit.time()
        schedule.hour = time_value.hour()
        schedule.minute = time_value.minute()
        schedule.weekday = self.weekday_box.currentIndex()
        schedule.day_of_month = self.day_spin.value()

        chosen = self.target_box.currentData()
        schedule.target = self._custom_target if chosen == "custom" else chosen

        updates.auto_update = self.auto_update_check.isChecked()
        updates.frequency = Frequency(self.update_frequency.currentData())
        updates.update_on_launch = self.update_on_launch.isChecked()

        self.service.save_settings()
        self._refresh_summary()

    def _frequency_changed(self) -> None:
        frequency = Frequency(self.frequency_box.currentData())
        weekly = frequency is Frequency.WEEKLY
        monthly = frequency is Frequency.MONTHLY
        hourly = frequency is Frequency.HOURLY
        self.weekday_label.setVisible(weekly)
        self.weekday_box.setVisible(weekly)
        self.day_label.setVisible(monthly)
        self.day_spin.setVisible(monthly)
        self.time_edit.setEnabled(not hourly)
        self._save()

    def _target_changed(self) -> None:
        custom = self.target_box.currentData() == "custom"
        self.custom_label.setVisible(custom)
        self.custom_button.setVisible(custom)
        if custom:
            self.custom_label.setText(
                paths.shorten(self._custom_target) if self._custom_target else "No folder chosen yet"
            )
        self._save()

    def choose_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Scan this folder", str(paths.home()))
        if chosen:
            self._custom_target = chosen
            self.custom_label.setText(paths.shorten(chosen))
            self._save()

    # -- display -----------------------------------------------------------

    def _refresh_summary(self) -> None:
        schedule = self.service.settings.schedule
        if schedule.enabled:
            following = next_occurrence(schedule)
            self.summary.setText(
                f"{describe_target(schedule)} — {describe_schedule(schedule).lower()}. "
                f"Next run {following:%A %d %B at %H:%M}."
            )
        else:
            self.summary.setText("No scheduled scans. Turn this on to run scans unattended.")

        if not paths.is_macos():
            self.status_card.hide()
            return
        lines = []
        for entry in launchagent.status():
            state = "loaded" if entry.loaded else ("installed" if entry.installed else "not set up")
            lines.append(f"{entry.kind.value}: {state}")
        self.status_body.setText(
            "ClamMac registers these background jobs with macOS — " + ", ".join(lines) + "."
        )
