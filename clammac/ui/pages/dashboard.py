"""The first thing you see: are you protected, and what should you do next.

The hero answers the only question most people open an antivirus to ask. When
something is wrong it says what, and its button does the thing that fixes it,
rather than sending the user off to find the right screen themselves.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ...core.engine import database_info
from ...core.scanner import ScanKind
from ...core.service import Health, ProtectionStatus
from ...core.watcher import WatcherState
from ..icons import glyph
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    Separator,
    StatCard,
    badge,
    button,
    caption,
    heading,
    human_size,
    label,
    relative_time,
    subtitle,
)
from .base import Page

__all__ = ["DashboardPage"]

_TONES = {
    Health.PROTECTED: ("good", "shield"),
    Health.ATTENTION: ("warn", "warning"),
    Health.AT_RISK: ("danger", "warning"),
    Health.SETTING_UP: ("muted", "download"),
}


class DashboardPage(Page):
    page_title = "Overview"
    page_subtitle = "The state of your protection at a glance"
    page_icon = "shield"

    def build(self) -> None:
        self._palette: Palette | None = None
        self._hero_connection = None

        # -- hero -----------------------------------------------------
        self.hero = Card(role="hero", padding=24, spacing=Metrics.GAP)
        hero_row = QHBoxLayout()
        hero_row.setSpacing(18)

        self.hero_icon = QLabel()
        self.hero_icon.setFixedSize(52, 52)
        self.hero_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero_row.addWidget(self.hero_icon, 0, Qt.AlignmentFlag.AlignTop)

        hero_text = QVBoxLayout()
        hero_text.setSpacing(5)
        self.hero_headline = label("Checking…", role="title")
        self.hero_detail = subtitle("")
        hero_text.addWidget(self.hero_headline)
        hero_text.addWidget(self.hero_detail)
        hero_row.addLayout(hero_text, 1)

        self.hero_action = button("Quick scan", variant="primary", size="large")
        hero_row.addWidget(self.hero_action, 0, Qt.AlignmentFlag.AlignTop)
        self.hero.add_layout(hero_row)
        self.add(self.hero)

        # -- statistics ----------------------------------------------
        stats = QGridLayout()
        stats.setSpacing(Metrics.GAP)
        self.stat_last_scan = StatCard("—", "Last scan")
        self.stat_definitions = StatCard("—", "Definitions")
        self.stat_quarantine = StatCard("0", "In quarantine")
        self.stat_threats = StatCard("0", "Threats found")
        for index, card in enumerate(
            (self.stat_last_scan, self.stat_definitions, self.stat_quarantine, self.stat_threats)
        ):
            stats.addWidget(card, 0, index)
            stats.setColumnStretch(index, 1)
        self.add_layout(stats)

        # -- quick actions --------------------------------------------
        actions = Card()
        actions.add(heading("Scan now"))
        actions.add(
            caption(
                "A quick scan covers where infections actually arrive: Downloads, "
                "the Desktop, mail attachments and startup items."
            )
        )
        row = QHBoxLayout()
        row.setSpacing(Metrics.GAP)
        self.quick_button = button(
            "Quick scan", variant="primary", on_click=lambda: self._scan(ScanKind.QUICK)
        )
        self.full_button = button("Full scan", on_click=lambda: self._scan(ScanKind.FULL))
        self.choose_button = button("Choose folder…", on_click=self._scan_custom)
        row.addWidget(self.quick_button)
        row.addWidget(self.full_button)
        row.addWidget(self.choose_button)
        row.addStretch(1)
        actions.add_layout(row)
        self.add(actions)

        # -- network exposure -----------------------------------------
        network = Card()
        network_header = QHBoxLayout()
        network_header.setSpacing(Metrics.GAP)
        network_header.addWidget(heading("Network exposure"))
        self.network_badge = badge("Never audited", "muted")
        network_header.addWidget(self.network_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        network_header.addStretch(1)
        self.network_button = button(
            "Run network audit", on_click=self.window.run_network_audit
        )
        network_header.addWidget(self.network_button)
        network.add_layout(network_header)
        self.network_detail = caption(
            "Antivirus catches what arrives as a file. A great deal now arrives over a "
            "port instead — a local model server, a database, a development server left "
            "listening on every interface. The audit checks what this Mac is offering to "
            "the network, and changes nothing."
        )
        network.add(self.network_detail)
        self.add(network)

        # -- engine and protection detail -----------------------------
        detail = Card()
        detail.add(heading("Protection"))
        self.detail_grid = QGridLayout()
        self.detail_grid.setHorizontalSpacing(Metrics.GAP_WIDE)
        self.detail_grid.setVerticalSpacing(9)
        self.detail_grid.setColumnStretch(1, 1)
        detail.add_layout(self.detail_grid)
        self._detail_values: dict[str, QLabel] = {}
        for index, name in enumerate(
            ("Real-time protection", "Scanning engine", "Virus definitions", "Database size")
        ):
            self.detail_grid.addWidget(label(name, tone="muted"), index, 0)
            value = label("—", wrap=True)
            self._detail_values[name] = value
            self.detail_grid.addWidget(value, index, 1)
        self.add(detail)

        # -- recent activity ------------------------------------------
        self.activity = Card()
        self.activity.add(heading("Recent activity"))
        self.activity_body = QVBoxLayout()
        self.activity_body.setSpacing(0)
        self.activity.add_layout(self.activity_body)
        self.add(self.activity)

    # -- actions ----------------------------------------------------------

    def _scan(self, kind: ScanKind) -> None:
        self.window.start_scan(kind)

    def _scan_custom(self) -> None:
        self.window.choose_and_scan()

    # -- refresh ----------------------------------------------------------

    def on_show(self) -> None:
        self.refresh(self.service.status())

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.hero.shadow(palette)
        self.refresh(self.service.status())

    def refresh(self, status: ProtectionStatus) -> None:
        palette = self._palette or self.window.palette_tokens
        tone, icon_name = _TONES[status.health]
        colour = {
            "good": palette.good,
            "warn": palette.warn,
            "danger": palette.danger,
            "muted": palette.text_muted,
        }[tone]

        self.hero_icon.setPixmap(glyph(icon_name, colour, 46).pixmap(46, 46))
        self.hero_headline.setText(status.health.headline)
        self.hero_headline.setProperty("tone", tone)
        _repolish(self.hero_headline)

        if status.reasons:
            self.hero_detail.setText("  ".join(f"• {reason}" for reason in status.reasons[:3]))
        elif status.last_scan is not None and status.last_scan.interrupted:
            self.hero_detail.setText(
                f"The last scan {relative_time(status.last_scan.started).lower()} was "
                f"interrupted after {status.last_scan.scanned:,} files. Scan again to finish."
            )
        elif status.last_scan is not None:
            self.hero_detail.setText(
                f"Last scan {relative_time(status.last_scan.started).lower()} — "
                f"{status.last_scan.scanned:,} files checked, nothing found."
            )
        else:
            self.hero_detail.setText("Everything is set up and running.")

        self._configure_hero_action(status)

        # statistics
        last = status.last_scan
        self.stat_last_scan.set_value(
            relative_time(last.started) if last else "Never",
            "" if last else "warn",
        )
        if status.database_age_days is None:
            self.stat_definitions.set_value("None", "danger")
        else:
            days = status.database_age_days
            text = "Today" if days < 1 else f"{int(days)}d old"
            self.stat_definitions.set_value(text, "warn" if status.database_stale else "good")
        self.stat_quarantine.set_value(
            f"{status.quarantine_count:,}", "warn" if status.quarantine_count else ""
        )
        self.stat_threats.set_value(
            f"{status.threats_total:,}", "danger" if status.threats_total else "good"
        )

        self._refresh_network(status)

        # detail grid
        realtime = status.realtime
        realtime_text = realtime.label
        if realtime is WatcherState.RUNNING and self.service.watcher is not None:
            realtime_text = f"On — watching {len(self.service.watcher.watched_paths)} folders"
        elif not self.service.settings.protection.enabled:
            realtime_text = "Off"
        self._detail_values["Real-time protection"].setText(realtime_text)

        self._detail_values["Scanning engine"].setText(
            f"ClamAV {status.engine_version} ({status.engine_origin})"
            if status.engine_version
            else "Not installed"
        )
        self._detail_values["Virus definitions"].setText(
            f"Version {status.database_version:,}" if status.database_version else "Not downloaded"
        )
        database = database_info()
        self._detail_values["Database size"].setText(
            f"{human_size(database.total_bytes)} across {len(database.files)} files"
            if database.present
            else "—"
        )

        self._refresh_activity()

    def _refresh_network(self, status: ProtectionStatus) -> None:
        audit = status.last_network_audit
        if audit is None:
            self.network_badge.setText("Never audited")
            self.network_badge.setProperty("tone", "muted")
            self.network_button.setText("Run network audit")
            self.network_detail.setText(
                "Antivirus catches what arrives as a file. A great deal now arrives over "
                "a port instead — a local model server, a database, a development server "
                "left listening on every interface. The audit checks what this Mac is "
                "offering to the network, and changes nothing."
            )
        else:
            tone = (
                "danger"
                if audit.critical
                else "warn"
                if audit.high or audit.medium
                else "good"
            )
            self.network_badge.setText(f"{audit.grade} — {audit.score}/100")
            self.network_badge.setProperty("tone", tone)
            self.network_button.setText("Run again")
            summary = (
                f"{audit.exposed} of {audit.listening} listening ports were reachable "
                f"from the network when this Mac was audited "
                f"{relative_time(audit.started).lower()}."
            )
            if audit.serious:
                summary += (
                    f" {audit.serious} finding{'s' if audit.serious != 1 else ''} "
                    "need attention — open Network for the detail."
                )
            self.network_detail.setText(summary)
        _repolish(self.network_badge)

    def _configure_hero_action(self, status: ProtectionStatus) -> None:
        """The hero button always does the most useful next thing."""
        if self._hero_connection is not None:
            self.hero_action.clicked.disconnect(self._hero_connection)
            self._hero_connection = None

        if status.health is Health.SETTING_UP:
            text, action = "Set up ClamMac", self.window.run_setup
        elif status.database_version == 0 or status.database_stale:
            text, action = "Update definitions", self.window.update_definitions
        elif not self.service.settings.protection.enabled:
            text, action = "Turn on protection", self.window.enable_protection
        else:
            text, action = "Quick scan", lambda: self._scan(ScanKind.QUICK)

        self.hero_action.setText(text)
        self._hero_connection = self.hero_action.clicked.connect(action)

    def _refresh_activity(self) -> None:
        while self.activity_body.count():
            item = self.activity_body.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Unparent before deleting: deleteLater only schedules the
                # deletion, and until the event loop gets to it the old row
                # goes on painting where it was, over the new one.
                widget.setParent(None)
                widget.deleteLater()

        scans = self.service.history.scans(limit=6)
        if not scans:
            self.activity_body.addWidget(
                caption("Nothing yet. Run your first scan to start building a history.")
            )
            return

        for index, record in enumerate(scans):
            if index:
                self.activity_body.addWidget(Separator())
            self.activity_body.addWidget(_activity_row(record))


def _activity_row(record) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 8, 0, 8)
    layout.setSpacing(Metrics.GAP)

    text = QVBoxLayout()
    text.setSpacing(1)
    text.addWidget(label(f"{record.kind.title()} scan — {record.target_summary}"))
    text.addWidget(caption(f"{record.scanned:,} files in {int(record.duration)}s"))
    layout.addLayout(text, 1)

    if record.infected:
        outcome = label(
            f"{record.infected} threat{'s' if record.infected != 1 else ''}", tone="danger"
        )
    else:
        outcome = label("Clean", tone="good")
    layout.addWidget(outcome, 0, Qt.AlignmentFlag.AlignRight)
    layout.addWidget(caption(relative_time(record.started)), 0, Qt.AlignmentFlag.AlignRight)
    return row


def _repolish(widget: QWidget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()
