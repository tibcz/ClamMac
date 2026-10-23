"""Everything ClamMac has scanned and found, with export."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import paths, reports
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    StatCard,
    button,
    configure_table,
    heading,
    human_duration,
    relative_time,
)
from .base import Page

__all__ = ["HistoryPage"]

_SCAN_COLUMNS = ["When", "Type", "Target", "Files", "Result", "Duration"]
_THREAT_COLUMNS = ["When", "Threat", "File", "Action"]


class HistoryPage(Page):
    page_title = "History"
    page_subtitle = "Every scan, and everything that was found"
    page_icon = "list"

    def build(self) -> None:
        self._palette: Palette | None = None

        stats_row = QHBoxLayout()
        stats_row.setSpacing(Metrics.GAP)
        self.stat_scans = StatCard("0", "Scans run")
        self.stat_files = StatCard("0", "Files checked")
        self.stat_threats = StatCard("0", "Threats found")
        self.stat_time = StatCard("0s", "Time spent scanning")
        for card in (self.stat_scans, self.stat_files, self.stat_threats, self.stat_time):
            stats_row.addWidget(card, 1)
        self.add_layout(stats_row)

        card = Card()
        header = QHBoxLayout()
        header.addWidget(heading("Records"))
        header.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search threats and paths…")
        self.search.setMaximumWidth(240)
        self.search.textChanged.connect(self._reload_threats)
        header.addWidget(self.search)
        header.addWidget(button("Export…", on_click=self.export))
        header.addWidget(button("Clear history", variant="ghost", on_click=self.clear))
        card.add_layout(header)

        self.tabs = QTabWidget()
        self.scan_table = _table(_SCAN_COLUMNS, stretch_column=2)
        self.threat_table = _table(_THREAT_COLUMNS, stretch_column=2)
        self.tabs.addTab(_wrap(self.scan_table), "Scans")
        self.tabs.addTab(_wrap(self.threat_table), "Threats")
        card.add(self.tabs)
        self.add(card)

        self.bridge.statusChanged.connect(lambda _: self.reload())

    # -- data -------------------------------------------------------------

    def on_show(self) -> None:
        self.reload()

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.reload()

    def reload(self) -> None:
        stats = self.service.history.statistics()
        self.stat_scans.set_value(f"{stats['scan_count']:,}")
        self.stat_files.set_value(f"{stats['files_scanned']:,}")
        self.stat_threats.set_value(
            f"{stats['threats_total']:,}", "danger" if stats["threats_total"] else "good"
        )
        self.stat_time.set_value(human_duration(stats["total_seconds"]))

        records = self.service.history.scans(limit=500)
        self.scan_table.setRowCount(0)
        for record in records:
            row = self.scan_table.rowCount()
            self.scan_table.insertRow(row)
            self.scan_table.setItem(row, 0, QTableWidgetItem(relative_time(record.started)))
            self.scan_table.setItem(row, 1, QTableWidgetItem(record.kind.title()))
            target = QTableWidgetItem(record.target_summary)
            target.setToolTip("\n".join(record.targets))
            self.scan_table.setItem(row, 2, target)
            self.scan_table.setItem(row, 3, QTableWidgetItem(f"{record.scanned:,}"))

            if record.in_progress:
                text, tone = "In progress", "text_muted"
            elif record.interrupted:
                text = (
                    f"Interrupted — {record.infected} found"
                    if record.infected
                    else "Interrupted"
                )
                tone = "danger" if record.infected else "warn"
            elif record.clean:
                text, tone = "Clean", "good"
            else:
                text, tone = f"{record.infected} found", "danger"
            outcome = QTableWidgetItem(text)
            if record.interrupted:
                outcome.setToolTip(
                    "ClamMac closed unexpectedly during this scan. What it had checked "
                    "and found was saved; scan again to cover the rest."
                )
            if self._palette is not None:
                from PySide6.QtGui import QBrush, QColor

                outcome.setForeground(
                    QBrush(QColor(getattr(self._palette, tone)))
                )
            self.scan_table.setItem(row, 4, outcome)
            self.scan_table.setItem(row, 5, QTableWidgetItem(human_duration(record.duration)))

        self._reload_threats()

    def _reload_threats(self) -> None:
        found = self.service.history.detections(search=self.search.text().strip(), limit=1000)
        self.threat_table.setRowCount(0)
        for record in found:
            row = self.threat_table.rowCount()
            self.threat_table.insertRow(row)
            self.threat_table.setItem(row, 0, QTableWidgetItem(relative_time(record.when)))

            signature = QTableWidgetItem(record.signature)
            if self._palette is not None:
                from PySide6.QtGui import QBrush, QColor

                signature.setForeground(QBrush(QColor(self._palette.danger)))
            self.threat_table.setItem(row, 1, signature)

            path = QTableWidgetItem(paths.shorten(record.path, max_len=80))
            path.setToolTip(record.path)
            self.threat_table.setItem(row, 2, path)
            self.threat_table.setItem(row, 3, QTableWidgetItem(record.action.title()))

    # -- actions ----------------------------------------------------------

    def export(self) -> None:
        destination, selected = QFileDialog.getSaveFileName(
            self,
            "Export history",
            str(paths.home() / "Downloads" / "ClamMac history.html"),
            "Web page (*.html);;Spreadsheet (*.csv);;JSON (*.json)",
        )
        if not destination:
            return
        fmt = "html"
        if destination.endswith(".csv") or "csv" in selected.lower():
            fmt = "csv"
        elif destination.endswith(".json") or "json" in selected.lower():
            fmt = "json"
        try:
            written = reports.write_report(
                Path(destination),
                self.service.history.scans(limit=5000),
                self.service.history.detections(limit=5000),
                fmt=fmt,
                title="ClamMac history",
            )
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not export", str(exc))
            return
        self.window.show_toast(f"Exported to {written.name}")

    def clear(self) -> None:
        answer = QMessageBox.question(
            self,
            "Clear history?",
            "Delete every scan record and detection record?\n\n"
            "Quarantined files are not affected — this only clears the log.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.service.history.clear()
            self.reload()


def _table(columns: list[str], *, stretch_column: int) -> QTableWidget:
    table = QTableWidget(0, len(columns))
    configure_table(table, columns, flexible=(stretch_column,))
    table.setMinimumHeight(320)
    return table


def _wrap(widget: QWidget) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(widget)
    return container
