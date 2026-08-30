"""Managing isolated files.

Restoring something from quarantine puts a file the scanner flagged back onto
the disk, so the confirmation says plainly what the file was detected as and
where it is going. Deleting is irreversible, so it asks too -- unless the user
has turned that off.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
)

from ...core.quarantine import QuarantineEntry, QuarantineError
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    button,
    caption,
    configure_table,
    heading,
    human_size,
    relative_time,
    subtitle,
)
from .base import Page

__all__ = ["QuarantinePage"]

_COLUMNS = ["File", "Detected as", "Came from", "Size", "Quarantined"]


class QuarantinePage(Page):
    page_title = "Quarantine"
    page_subtitle = "Files that were isolated instead of deleted"
    page_icon = "box"

    def build(self) -> None:
        self._palette: Palette | None = None

        self.card = Card()
        header = QHBoxLayout()
        self.count_label = heading("Nothing in quarantine")
        header.addWidget(self.count_label)
        header.addStretch(1)
        self.refresh_button = button("Refresh", variant="ghost", on_click=self.reload)
        header.addWidget(self.refresh_button)
        self.card.add_layout(header)

        self.card.add(
            caption(
                "Quarantined files are moved into a private folder and stripped of every "
                "permission, so nothing can open or run them. They stay recoverable until "
                "you delete them."
            )
        )

        self.table = QTableWidget(0, len(_COLUMNS))
        configure_table(self.table, _COLUMNS, flexible=(0, 2))
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setMinimumHeight(300)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.card.add(self.table)

        actions = QHBoxLayout()
        actions.setSpacing(Metrics.GAP)
        self.restore_button = button("Restore", on_click=self.restore_selected, enabled=False)
        self.delete_button = button(
            "Delete", variant="danger", on_click=self.delete_selected, enabled=False
        )
        self.empty_button = button("Empty quarantine", on_click=self.empty_all)
        actions.addWidget(self.restore_button)
        actions.addWidget(self.delete_button)
        actions.addStretch(1)
        actions.addWidget(self.empty_button)
        self.card.add_layout(actions)

        self.footer = subtitle("")
        self.card.add(self.footer)
        self.add(self.card)

        self.bridge.statusChanged.connect(lambda _: self.reload())

    # -- data -------------------------------------------------------------

    def on_show(self) -> None:
        self.reload()

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.reload()

    def reload(self) -> None:
        entries = self.service.quarantine.entries()
        self.table.setRowCount(0)

        for entry in entries:
            row = self.table.rowCount()
            self.table.insertRow(row)

            name_item = QTableWidgetItem(entry.name)
            name_item.setData(Qt.ItemDataRole.UserRole, entry.entry_id)
            name_item.setToolTip(entry.original_path)
            self.table.setItem(row, 0, name_item)

            signature_item = QTableWidgetItem(entry.signature)
            if self._palette is not None:
                from PySide6.QtGui import QBrush, QColor

                signature_item.setForeground(QBrush(QColor(self._palette.danger)))
            self.table.setItem(row, 1, signature_item)

            self.table.setItem(row, 2, QTableWidgetItem(entry.display_path))
            self.table.setItem(row, 3, QTableWidgetItem(human_size(entry.size)))
            self.table.setItem(row, 4, QTableWidgetItem(relative_time(entry.when)))

        count = len(entries)
        if count:
            total = self.service.quarantine.total_bytes()
            self.count_label.setText(f"{count} file{'s' if count != 1 else ''} in quarantine")
            self.footer.setText(f"Using {human_size(total)} of disk space.")
        else:
            self.count_label.setText("Nothing in quarantine")
            self.footer.setText("Any threats ClamMac finds will be isolated here.")

        self.empty_button.setEnabled(count > 0)
        self._selection_changed()

    # -- selection --------------------------------------------------------

    def _selected(self) -> list[QuarantineEntry]:
        ids = {
            self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
            for index in self.table.selectionModel().selectedRows()
        }
        return [e for e in self.service.quarantine.entries() if e.entry_id in ids]

    def _selection_changed(self) -> None:
        has = bool(self.table.selectionModel().selectedRows())
        self.restore_button.setEnabled(has)
        self.delete_button.setEnabled(has)

    # -- actions ----------------------------------------------------------

    def restore_selected(self) -> None:
        entries = self._selected()
        if not entries:
            return

        names = "\n".join(f"  • {e.name}  —  detected as {e.signature}" for e in entries[:8])
        if len(entries) > 8:
            names += f"\n  … and {len(entries) - 8} more"

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Restore from quarantine?")
        box.setText(
            f"Put {'this file' if len(entries) == 1 else f'these {len(entries)} files'} "
            "back where they came from?"
        )
        box.setInformativeText(
            f"{names}\n\nClamMac detected {'this' if len(entries) == 1 else 'these'} as malicious. "
            "Restore only if you are certain it was a false alarm. Real-time protection may "
            "quarantine the file again as soon as it reappears."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Ok)
        box.button(QMessageBox.StandardButton.Ok).setText("Restore")
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Ok:
            return

        restored, problems = 0, []
        for entry in entries:
            try:
                self.service.quarantine.restore(entry.entry_id)
                restored += 1
            except QuarantineError as exc:
                problems.append(str(exc))

        self.service.history.record_event(
            "quarantine", f"Restored {restored} file(s) from quarantine", "warning"
        )
        self.reload()
        self.service.notify_status()
        if problems:
            QMessageBox.warning(self, "Some files could not be restored", "\n".join(problems))

    def delete_selected(self) -> None:
        entries = self._selected()
        if not entries:
            return

        if self.service.settings.interface.confirm_before_delete:
            answer = QMessageBox.question(
                self,
                "Delete permanently?",
                f"Permanently delete {len(entries)} quarantined "
                f"file{'s' if len(entries) != 1 else ''}?\n\nThis cannot be undone.",
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        deleted, problems = self.service.quarantine.delete_many(
            [e.entry_id for e in entries], shred=True
        )
        self.service.history.record_event("quarantine", f"Deleted {deleted} quarantined file(s)")
        self.reload()
        self.service.notify_status()
        if problems:
            QMessageBox.warning(self, "Some files could not be deleted", "\n".join(problems))

    def empty_all(self) -> None:
        count = self.service.quarantine.count()
        if not count:
            return
        answer = QMessageBox.question(
            self,
            "Empty quarantine?",
            f"Permanently delete all {count} quarantined "
            f"file{'s' if count != 1 else ''}?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        removed = self.service.quarantine.empty(shred=True)
        self.service.history.record_event("quarantine", f"Emptied quarantine ({removed} files)")
        self.reload()
        self.service.notify_status()
