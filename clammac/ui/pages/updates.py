"""Virus definitions: how current they are, and updating them."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPlainTextEdit, QProgressBar

from ...core.engine import database_info
from ...core.freshclam import UpdateProgress, UpdateState
from ...core.scheduler import update_due
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    button,
    caption,
    heading,
    human_size,
    label,
    relative_time,
    subtitle,
)
from .base import Page

__all__ = ["UpdatesPage"]


class UpdatesPage(Page):
    page_title = "Definitions"
    page_subtitle = "The signatures ClamAV matches files against"
    page_icon = "download"

    def build(self) -> None:
        self.status_card = Card()
        header = QHBoxLayout()
        self.status_heading = heading("Checking…")
        header.addWidget(self.status_heading)
        header.addStretch(1)
        self.update_button = button(
            "Update now", variant="primary", on_click=self.window.update_definitions
        )
        header.addWidget(self.update_button)
        self.status_card.add_layout(header)

        self.status_detail = subtitle("")
        self.status_card.add(self.status_detail)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()
        self.status_card.add(self.progress)

        self.progress_label = caption("")
        self.progress_label.hide()
        self.status_card.add(self.progress_label)
        self.add(self.status_card)

        # -- detail grid -----------------------------------------------
        detail = Card()
        detail.add(heading("Database"))
        grid = QGridLayout()
        grid.setHorizontalSpacing(Metrics.GAP_WIDE)
        grid.setVerticalSpacing(9)
        grid.setColumnStretch(1, 1)
        self._values: dict[str, QLabel] = {}
        for index, name in enumerate(
            ("Version", "Last updated", "Next scheduled update", "Files", "Total size", "Location")
        ):
            grid.addWidget(label(name, tone="muted"), index, 0)
            value = label("—")
            self._values[name] = value
            grid.addWidget(value, index, 1)
        detail.add_layout(grid)
        self.add(detail)

        # -- log -------------------------------------------------------
        self.log_card = Card()
        self.log_card.add(heading("Update log"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(190)
        self.log_view.setPlaceholderText("Output from the last update will appear here.")
        self.log_card.add(self.log_view)
        self.add(self.log_card)

        self.bridge.updateProgress.connect(self.on_progress)
        self.bridge.updateFinished.connect(self.on_finished)
        self.bridge.updateLog.connect(self.append_log)

    # -- refresh ----------------------------------------------------------

    def on_show(self) -> None:
        self.refresh()

    def apply_palette(self, palette: Palette) -> None:
        self.refresh()

    def refresh(self) -> None:
        database = database_info()
        settings = self.service.settings
        stale = database.is_stale(settings.updates.stale_after_days)

        if not database.present:
            self.status_heading.setText("No definitions yet")
            self.status_heading.setProperty("tone", "danger")
            self.status_detail.setText(
                "ClamMac cannot detect anything until the virus definitions have been "
                "downloaded. This is about 250 MB and only needs doing once; after that "
                "only the changes are fetched."
            )
        elif stale:
            age = database.age_days() or 0
            self.status_heading.setText("Definitions are out of date")
            self.status_heading.setProperty("tone", "warn")
            self.status_detail.setText(
                f"They were last updated {int(age)} days ago. New malware appears daily, "
                "so it is worth updating now."
            )
        else:
            self.status_heading.setText("Definitions are up to date")
            self.status_heading.setProperty("tone", "good")
            self.status_detail.setText(
                f"Last updated {relative_time(database.newest).lower()}."
            )
        _repolish(self.status_heading)

        engine = self.service.engine
        self._values["Version"].setText(
            f"{engine.database_version:,}" if engine and engine.database_version else "—"
        )
        self._values["Last updated"].setText(
            relative_time(database.newest) if database.newest else "Never"
        )

        due = update_due(settings)
        if not settings.updates.auto_update:
            self._values["Next scheduled update"].setText("Automatic updates are off")
        elif due.next_run is not None:
            self._values["Next scheduled update"].setText(
                "Due now" if due.due else relative_time(due.next_run).replace(" ago", " from now")
            )
        else:
            self._values["Next scheduled update"].setText("As soon as possible")

        self._values["Files"].setText(str(len(database.files)) if database.present else "—")
        self._values["Total size"].setText(
            human_size(database.total_bytes) if database.present else "—"
        )
        self._values["Location"].setText(str(database.directory))

        self.update_button.setEnabled(self.service.engine is not None)

    # -- live -------------------------------------------------------------

    def update_started(self) -> None:
        self.log_view.clear()
        self.progress.setRange(0, 0)
        self.progress.show()
        self.progress_label.setText("Starting…")
        self.progress_label.show()
        self.update_button.setEnabled(False)

    def on_progress(self, progress: UpdateProgress) -> None:
        self.progress_label.setText(progress.message)
        if progress.fraction >= 0:
            self.progress.setRange(0, 100)
            self.progress.setValue(int(progress.fraction * 100))
        else:
            self.progress.setRange(0, 0)

    def on_finished(self, job) -> None:
        self.progress.hide()
        self.progress_label.hide()
        self.update_button.setEnabled(True)
        if job.state is UpdateState.FAILED:
            self.append_log(f"\n{job.failure}")
        self.refresh()

    def append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)


def _repolish(widget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()
