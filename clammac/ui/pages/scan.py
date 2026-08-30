"""Running a scan, and watching it happen.

The progress display is driven by the scanner's own per-file output, so the
path on screen is the file the engine is genuinely working on. When the file
count could be established up front the ring shows a real percentage; when it
could not, it spins rather than inventing one.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ...core import paths
from ...core.scanner import FileResult, JobState, ScanKind, ScanProgress
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    ProgressRing,
    button,
    caption,
    configure_table,
    elide,
    heading,
    human_duration,
    label,
    subtitle,
)
from .base import Page

__all__ = ["ScanPage"]


class ScanPage(Page):
    page_title = "Scan"
    page_subtitle = "Check a folder, a disk, or anything you drop here"
    page_icon = "search"

    def build(self) -> None:
        self._palette: Palette | None = None
        self._custom_targets: list[Path] = []

        self.setAcceptDrops(True)

        # -- choose what to scan --------------------------------------
        self.chooser = Card()
        self.chooser.add(heading("What would you like to check?"))
        row = QHBoxLayout()
        row.setSpacing(Metrics.GAP)
        self.quick_button = button(
            "Quick scan",
            variant="primary",
            tooltip="Downloads, Desktop, mail attachments and startup items",
            on_click=lambda: self.start(ScanKind.QUICK),
        )
        self.full_button = button(
            "Full scan",
            tooltip="Every file in your home folder",
            on_click=lambda: self.start(ScanKind.FULL),
        )
        self.folder_button = button("Choose folder…", on_click=self.choose_folder)
        self.files_button = button("Choose files…", on_click=self.choose_files)
        for widget in (self.quick_button, self.full_button, self.folder_button, self.files_button):
            row.addWidget(widget)
        row.addStretch(1)
        self.chooser.add_layout(row)

        self.drop_hint = caption("You can also drag files or folders onto this window.")
        self.chooser.add(self.drop_hint)
        self.add(self.chooser)

        # -- live progress ---------------------------------------------
        self.progress_card = Card(padding=22)
        progress_row = QHBoxLayout()
        progress_row.setSpacing(24)

        self.ring = ProgressRing(138)
        progress_row.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignTop)

        text_column = QVBoxLayout()
        text_column.setSpacing(6)
        self.state_label = label("Preparing…", role="heading")
        self.current_label = label("", role="mono")
        self.current_label.setWordWrap(False)
        self.counts_label = subtitle("")
        self.eta_label = caption("")
        text_column.addWidget(self.state_label)
        text_column.addWidget(self.current_label)
        text_column.addWidget(self.counts_label)
        text_column.addWidget(self.eta_label)
        text_column.addStretch(1)

        controls = QHBoxLayout()
        controls.setSpacing(Metrics.GAP)
        self.pause_button = button("Pause", on_click=self.toggle_pause)
        self.stop_button = button("Stop", variant="danger", on_click=self.stop)
        controls.addWidget(self.pause_button)
        controls.addWidget(self.stop_button)
        controls.addStretch(1)
        text_column.addLayout(controls)

        progress_row.addLayout(text_column, 1)
        self.progress_card.add_layout(progress_row)
        self.add(self.progress_card)
        self.progress_card.hide()

        # -- results ----------------------------------------------------
        self.results_card = Card()
        header = QHBoxLayout()
        self.results_heading = heading("Results")
        header.addWidget(self.results_heading)
        header.addStretch(1)
        self.export_button = button("Export report…", variant="ghost", on_click=self.export_report)
        header.addWidget(self.export_button)
        self.results_card.add_layout(header)

        self.summary_label = subtitle("")
        self.results_card.add(self.summary_label)

        self.table = QTableWidget(0, 3)
        configure_table(self.table, ["Threat", "File", "Action"], flexible=(1,))
        self.table.setMinimumHeight(180)
        self.results_card.add(self.table)
        self.add(self.results_card)
        self.results_card.hide()

        self.bridge.scanProgress.connect(self.on_progress)
        self.bridge.scanDetection.connect(self.on_detection)
        self.bridge.scanFinished.connect(self.on_finished)
        self.bridge.threatHandled.connect(self.on_threat_handled)

    # -- starting ---------------------------------------------------------

    def start(self, kind: ScanKind, targets: list[Path] | None = None) -> None:
        self.window.start_scan(kind, targets)

    def choose_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose a folder to scan", str(paths.home())
        )
        if chosen:
            self.start(ScanKind.CUSTOM, [Path(chosen)])

    def choose_files(self) -> None:
        chosen, _ = QFileDialog.getOpenFileNames(self, "Choose files to scan", str(paths.home()))
        if chosen:
            self.start(ScanKind.CUSTOM, [Path(p) for p in chosen])

    # -- drag and drop ----------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.drop_hint.setText("Release to scan these items.")

    def dragLeaveEvent(self, event) -> None:
        self.drop_hint.setText("You can also drag files or folders onto this window.")

    def dropEvent(self, event: QDropEvent) -> None:
        self.drop_hint.setText("You can also drag files or folders onto this window.")
        targets = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if url.isLocalFile() and Path(url.toLocalFile()).exists()
        ]
        if targets:
            event.acceptProposedAction()
            self.start(ScanKind.CUSTOM, targets)

    # -- controls ---------------------------------------------------------

    def toggle_pause(self) -> None:
        job = self.service.active_scan
        if job is None:
            return
        if job.state is JobState.PAUSED:
            job.resume()
        else:
            job.pause()

    def stop(self) -> None:
        self.service.stop_scan()

    def export_report(self) -> None:
        self.window.export_last_scan()

    # -- live updates -----------------------------------------------------

    def scan_started(self) -> None:
        self.table.setRowCount(0)
        self.results_card.hide()
        self.progress_card.show()
        self.summary_label.setText("")
        self.state_label.setText("Preparing…")
        self.current_label.setText("")
        self.counts_label.setText("")
        self.eta_label.setText("")
        self.pause_button.setText("Pause")
        self.pause_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self._set_buttons_enabled(False)
        self.ring.set_progress(-1.0, "", "")

    def on_progress(self, progress: ScanProgress) -> None:
        if progress.state is JobState.PREPARING:
            self.state_label.setText("Counting files…")
            self.ring.set_progress(-1.0, "", "")
            return

        if progress.state is JobState.PAUSED:
            self.state_label.setText("Paused")
            self.pause_button.setText("Resume")
        elif progress.state is JobState.RUNNING:
            self.state_label.setText("Scanning…")
            self.pause_button.setText("Pause")

        fraction = progress.fraction
        if fraction >= 0:
            self.ring.set_progress(fraction, f"{int(fraction * 100)}%", f"{progress.scanned:,}")
        else:
            self.ring.set_progress(-1.0, f"{progress.scanned:,}", "files")

        if progress.current_path:
            self.current_label.setText(elide(paths.shorten(progress.current_path, max_len=200), 74))

        pieces = [f"{progress.scanned:,} files checked"]
        if progress.infected:
            pieces.append(f"{progress.infected} infected")
        if progress.errors:
            pieces.append(f"{progress.errors} unreadable")
        pieces.append(f"{human_duration(progress.elapsed)} elapsed")
        self.counts_label.setText(" · ".join(pieces))

        eta = progress.eta_seconds
        if eta > 0:
            self.eta_label.setText(
                f"About {human_duration(eta)} remaining, at {progress.rate:.0f} files/sec"
            )
        elif progress.rate:
            self.eta_label.setText(f"{progress.rate:.0f} files per second")

    def on_detection(self, result: FileResult) -> None:
        self._add_row(result.signature, result.path, "Detected")
        self.results_card.show()
        self.results_heading.setText(f"Threats found ({self.table.rowCount()})")

    def on_threat_handled(self, result: FileResult, action: str) -> None:
        """Update the row once the configured response has been applied."""
        wording = {
            "quarantine": "Quarantined",
            "deleted": "Deleted",
            "report": "Reported only",
            "failed": "Could not be handled",
        }.get(action, action.title())
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 1)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) == result.path:
                self.table.setItem(row, 2, QTableWidgetItem(wording))
                return

    def on_finished(self, job) -> None:
        self.progress_card.hide()
        self._set_buttons_enabled(True)
        self.ring.stop()

        if job.state is JobState.CANCELLED:
            self.summary_label.setText(
                f"Scan stopped after checking {job.scanned:,} files."
            )
            self.results_heading.setText("Stopped")
        elif job.state is JobState.FAILED:
            self.summary_label.setText(job.failure or "The scan did not finish.")
            self.results_heading.setText("Scan failed")
        elif job.detections:
            count = len(job.detections)
            self.summary_label.setText(
                f"Checked {job.scanned:,} files in {human_duration(job.elapsed)}. "
                f"{count} threat{'s' if count != 1 else ''} found and dealt with according "
                f"to your settings."
            )
            self.results_heading.setText(f"Threats found ({count})")
        else:
            self.summary_label.setText(
                f"Checked {job.scanned:,} files in {human_duration(job.elapsed)}. "
                "Nothing suspicious was found."
            )
            self.results_heading.setText("No threats found")

        if job.errors:
            self.summary_label.setText(
                self.summary_label.text()
                + f" {len(job.errors)} file(s) could not be read."
            )
        self.results_card.show()

    # -- helpers ----------------------------------------------------------

    def _add_row(self, signature: str, path: str, action: str) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        signature_item = QTableWidgetItem(signature)
        palette = self._palette or self.window.palette_tokens
        signature_item.setForeground(QBrush(QColor(palette.danger)))
        self.table.setItem(row, 0, signature_item)

        path_item = QTableWidgetItem(paths.shorten(path, max_len=90))
        path_item.setData(Qt.ItemDataRole.UserRole, path)
        path_item.setToolTip(path)
        self.table.setItem(row, 1, path_item)

        self.table.setItem(row, 2, QTableWidgetItem(action))

    def _set_buttons_enabled(self, enabled: bool) -> None:
        for widget in (self.quick_button, self.full_button, self.folder_button, self.files_button):
            widget.setEnabled(enabled)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.ring.set_palette_colours(palette.surface_hover, palette.accent)

    def on_show(self) -> None:
        job = self.service.active_scan
        if job is not None and job.state.is_active:
            self.progress_card.show()
            self._set_buttons_enabled(False)
