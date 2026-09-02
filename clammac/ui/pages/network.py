"""The network audit: what this Mac is exposing, and what to do about it.

The screen is built around one question -- can anything on the network reach
something on this Mac that it should not -- and answers it before anything
else. The grade and the headline come first, then the findings in the order
they deserve attention, then the raw observations for anyone who wants to
check the working.

Nothing here starts by itself. The audit runs when the user asks for it, which
is why the page opens on an explanation rather than on a spinner.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import paths
from ...core.network import AuditProgress, AuditReport, NetworkAudit, Severity
from ...core.network import report as audit_report
from ..theme import Metrics, Palette
from ..widgets.common import (
    Card,
    Separator,
    StatCard,
    badge,
    button,
    caption,
    heading,
    label,
    mono,
    relative_time,
    subtitle,
)
from .base import Page

__all__ = ["NetworkPage"]

_PORT_COLUMNS = ["Bound to", "Service", "Process", "PID", "Protocol", "Reachable from"]
_CONNECTION_COLUMNS = ["Application", "Connected to", "Port", "State", "Where"]
_SHARING_COLUMNS = ["Sharing feature", "Status"]

_GRADE_TONES = {"A": "good", "B": "good", "C": "warn", "D": "danger", "F": "danger"}


class NetworkPage(Page):
    page_title = "Network"
    page_subtitle = "What this Mac exposes to the networks it joins"
    page_icon = "network"

    # -- construction -----------------------------------------------------

    def build(self) -> None:
        self.report: AuditReport | None = None
        self._palette: Palette | None = None

        self.run_button = button(
            "Run audit", variant="primary", on_click=self.window.run_network_audit
        )
        self.header_action(self.run_button)

        self._build_hero()
        self._build_stats()
        self._build_findings()
        self._build_detail()

        self.bridge.auditProgress.connect(self.on_progress)
        self.bridge.auditFinished.connect(self.on_finished)

    def _build_hero(self) -> None:
        self.hero = Card(role="hero", padding=22, spacing=Metrics.GAP)
        row = QHBoxLayout()
        row.setSpacing(20)

        self.grade_label = label("—", role="grade")
        self.grade_label.setFixedWidth(76)
        self.grade_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(self.grade_label, 0, Qt.AlignmentFlag.AlignVCenter)

        text = QVBoxLayout()
        text.setSpacing(4)
        self.hero_headline = heading("No audit has been run yet")
        self.hero_detail = subtitle(
            "The audit looks at everything this Mac offers to the network: which ports "
            "are open and to whom, what the firewall is set to, which sharing services "
            "are answering, how DNS is configured, and which Wi-Fi network you are on. "
            "It reads local settings only — nothing is scanned, contacted or probed."
        )
        text.addWidget(self.hero_headline)
        text.addWidget(self.hero_detail)
        row.addLayout(text, 1)
        self.hero.add_layout(row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()
        self.hero.add(self.progress)

        self.progress_label = caption("")
        self.progress_label.hide()
        self.hero.add(self.progress_label)
        self.add(self.hero)

    def _build_stats(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(Metrics.GAP)
        self.stat_exposed = StatCard("—", "Reachable services")
        self.stat_listening = StatCard("—", "Listening ports")
        self.stat_serious = StatCard("—", "Serious findings")
        self.stat_devices = StatCard("—", "Devices on network")
        for index, card in enumerate(
            (self.stat_exposed, self.stat_listening, self.stat_serious, self.stat_devices)
        ):
            grid.addWidget(card, 0, index)
            grid.setColumnStretch(index, 1)
        self.add_layout(grid)

    def _build_findings(self) -> None:
        self.findings_card = Card()
        header = QHBoxLayout()
        self.findings_heading = heading("Findings")
        header.addWidget(self.findings_heading)
        header.addStretch(1)
        self.export_button = button(
            "Export…", variant="ghost", on_click=self.export, enabled=False
        )
        header.addWidget(self.export_button)
        self.findings_card.add_layout(header)

        self.findings_body = QVBoxLayout()
        self.findings_body.setSpacing(4)
        self.findings_body.setContentsMargins(0, 6, 0, 0)
        self.findings_card.add_layout(self.findings_body)
        self.add(self.findings_card)

    def _build_detail(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setMinimumHeight(340)

        self.ports_table = _table(_PORT_COLUMNS, flexible=(0, 2))
        self.tabs.addTab(_wrap(self.ports_table), "Open ports")

        self.connections_table = _table(_CONNECTION_COLUMNS, flexible=(0, 1))
        self.tabs.addTab(_wrap(self.connections_table), "Connections")

        self.sharing_table = _table(_SHARING_COLUMNS, flexible=(0, 1))
        self.tabs.addTab(_wrap(self.sharing_table), "Sharing")

        self.environment = QWidget()
        environment_layout = QVBoxLayout(self.environment)
        environment_layout.setContentsMargins(14, 14, 14, 14)
        environment_layout.setSpacing(9)
        self.environment_grid = QGridLayout()
        self.environment_grid.setHorizontalSpacing(Metrics.GAP_WIDE)
        self.environment_grid.setVerticalSpacing(8)
        self.environment_grid.setColumnStretch(1, 1)
        self._environment_values: dict[str, QLabel] = {}
        for index, name in enumerate(
            (
                "Firewall",
                "Stealth mode",
                "Wi-Fi",
                "DNS servers",
                "Default gateway",
                "Addresses",
                "Proxy",
                "Audited",
            )
        ):
            self.environment_grid.addWidget(label(name, tone="muted"), index, 0)
            value = label("—", wrap=True)
            self._environment_values[name] = value
            self.environment_grid.addWidget(value, index, 1)
        environment_layout.addLayout(self.environment_grid)
        environment_layout.addWidget(Separator())
        self.limitations_label = caption("")
        environment_layout.addWidget(self.limitations_label)
        environment_layout.addStretch(1)
        self.tabs.addTab(self.environment, "This Mac")

        self.add(self.tabs)

    # -- lifecycle --------------------------------------------------------

    def on_show(self) -> None:
        if self.report is None:
            self._show_history()
        else:
            self._show_report(self.report)

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.on_show()

    # -- running ----------------------------------------------------------

    def audit_started(self) -> None:
        self.run_button.setEnabled(False)
        self.run_button.setText("Auditing…")
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.show()
        self.progress_label.setText("Starting…")
        self.progress_label.show()
        self.hero_headline.setText("Checking this Mac…")

    def on_progress(self, progress: AuditProgress) -> None:
        self.progress.setValue(int(progress.fraction * 100))
        self.progress_label.setText(f"{progress.message}…")

    def on_finished(self, job: NetworkAudit) -> None:
        self.progress.hide()
        self.progress_label.hide()
        self.run_button.setEnabled(True)
        self.run_button.setText("Run audit again")
        if job.report is None:
            self.hero_headline.setText("The audit could not finish")
            self.hero_detail.setText(job.failure or "Nothing was reported.")
            return
        self.report = job.report
        self._show_report(job.report)

    # -- rendering --------------------------------------------------------

    def _show_report(self, report: AuditReport) -> None:
        palette = self._palette or self.window.palette_tokens
        snapshot = report.snapshot
        counts = report.counts

        tone = _GRADE_TONES.get(report.grade, "muted")
        self.grade_label.setText(report.grade)
        self.grade_label.setProperty("tone", tone)
        _repolish(self.grade_label)

        self.hero_headline.setText(f"{report.headline} — {report.score} out of 100")
        self.hero_detail.setText(
            f"{len(snapshot.exposed_listeners)} of {len(snapshot.listeners)} listening "
            f"ports can be reached from the network. "
            f"{_firewall_phrase(snapshot)} "
            f"Audited {relative_time(report.started).lower()} on {snapshot.platform}."
        )

        serious = counts[Severity.CRITICAL] + counts[Severity.HIGH]
        self.stat_exposed.set_value(
            str(len(snapshot.exposed_listeners)),
            "warn" if snapshot.exposed_listeners else "good",
        )
        self.stat_listening.set_value(str(len(snapshot.listeners)))
        self.stat_serious.set_value(str(serious), "danger" if serious else "good")
        self.stat_devices.set_value(str(len(snapshot.neighbours)))

        self._render_findings(report.ordered, palette)
        self._render_ports(snapshot)
        self._render_connections(snapshot)
        self._render_sharing(snapshot)
        self._render_environment(report)
        self.export_button.setEnabled(True)

    def _show_history(self) -> None:
        """Before an audit runs, show what the last one concluded."""
        palette = self._palette or self.window.palette_tokens
        record = self.service.history.last_network_audit()
        if record is None:
            self.grade_label.setText("—")
            self.grade_label.setProperty("tone", "")
            _repolish(self.grade_label)
            self._render_findings([], palette)
            self.export_button.setEnabled(False)
            return

        tone = _GRADE_TONES.get(record.grade, "muted")
        self.grade_label.setText(record.grade or "—")
        self.grade_label.setProperty("tone", tone)
        _repolish(self.grade_label)
        self.hero_headline.setText(f"{record.headline} — {record.score} out of 100")
        self.hero_detail.setText(
            f"From the audit run {relative_time(record.started).lower()}. "
            f"{record.exposed} of {record.listening} listening ports were reachable from "
            "the network. Run the audit again for the current picture."
        )
        self.stat_exposed.set_value(str(record.exposed), "warn" if record.exposed else "good")
        self.stat_listening.set_value(str(record.listening))
        self.stat_serious.set_value(
            str(record.serious), "danger" if record.serious else "good"
        )
        self.stat_devices.set_value("—")

        stored = self.service.history.network_findings(record.id)
        self._render_stored_findings(stored, palette)
        self.export_button.setEnabled(False)

    # -- findings ---------------------------------------------------------

    def _clear_findings(self) -> None:
        """Empty the findings column, spacers and nested layouts included."""
        _empty(self.findings_body)

    def _render_findings(self, findings: list, palette: Palette) -> None:
        self._clear_findings()
        if not findings:
            self.findings_heading.setText("Findings")
            self.findings_body.addWidget(
                caption(
                    "Run the audit to see what this Mac is exposing. It takes a few "
                    "seconds and changes nothing."
                )
            )
            return

        serious = [f for f in findings if f.severity is not Severity.INFO]
        self.findings_heading.setText(
            f"{len(serious)} thing{'s' if len(serious) != 1 else ''} worth fixing"
            if serious
            else "Nothing needs fixing"
        )
        for index, finding in enumerate(findings):
            _add_finding(
                self.findings_body,
                finding.severity.label,
                finding.severity.tone,
                finding.title,
                finding.summary,
                finding.recommendation,
                list(finding.evidence),
                finding.reference,
                first=index == 0,
            )

    def _render_stored_findings(self, stored: list, palette: Palette) -> None:
        self._clear_findings()
        if not stored:
            self.findings_body.addWidget(caption("The last audit found nothing to report."))
            return
        serious = [f for f in stored if f.severity != Severity.INFO.value]
        self.findings_heading.setText(
            f"{len(serious)} thing{'s' if len(serious) != 1 else ''} worth fixing"
            if serious
            else "Nothing needed fixing"
        )
        for index, finding in enumerate(stored):
            severity = _severity(finding.severity)
            _add_finding(
                self.findings_body,
                severity.label,
                severity.tone,
                finding.title,
                finding.summary,
                finding.recommendation,
                list(finding.evidence),
                "",
                first=index == 0,
            )

    # -- tables -----------------------------------------------------------

    def _render_ports(self, snapshot) -> None:
        from ...core.network.catalog import profile_for

        self.ports_table.setRowCount(0)
        for listener in snapshot.listeners:
            row = self.ports_table.rowCount()
            self.ports_table.insertRow(row)
            profile = profile_for(listener.port, listener.process)
            cells = [
                listener.endpoint,
                profile.name if profile else "Unknown",
                listener.process or "—",
                str(listener.pid or "—"),
                listener.protocol.upper(),
                listener.scope.label,
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 5 and listener.exposed:
                    _tint(item, self._colour("warn"))
                elif column == 5:
                    _tint(item, self._colour("good"))
                self.ports_table.setItem(row, column, item)

    def _render_connections(self, snapshot) -> None:
        self.connections_table.setRowCount(0)
        for connection in sorted(
            snapshot.connections, key=lambda item: (not item.remote_is_public, item.remote_port)
        ):
            row = self.connections_table.rowCount()
            self.connections_table.insertRow(row)
            cells = [
                connection.process or "—",
                connection.remote_address,
                str(connection.remote_port),
                connection.state.title(),
                "Internet" if connection.remote_is_public else "This network",
            ]
            for column, text in enumerate(cells):
                self.connections_table.setItem(row, column, QTableWidgetItem(text))

    def _render_sharing(self, snapshot) -> None:
        self.sharing_table.setRowCount(0)
        for service in snapshot.sharing:
            row = self.sharing_table.rowCount()
            self.sharing_table.insertRow(row)
            self.sharing_table.setItem(row, 0, QTableWidgetItem(service.label))
            status = QTableWidgetItem("On — " + service.detail if service.running else "Off")
            _tint(status, self._colour("warn" if service.running else "good"))
            self.sharing_table.setItem(row, 1, status)

    def _render_environment(self, report: AuditReport) -> None:
        snapshot = report.snapshot
        firewall = snapshot.firewall
        values = self._environment_values

        values["Firewall"].setText(_state_text(firewall.enabled, firewall.detail))
        values["Stealth mode"].setText(_state_text(firewall.stealth))
        values["Wi-Fi"].setText(
            f"{snapshot.wireless.ssid} — {snapshot.wireless.security or 'unknown security'}"
            if snapshot.wireless.ssid
            else "Not connected to Wi-Fi"
        )
        values["DNS servers"].setText(
            ", ".join(snapshot.dns.resolvers) if snapshot.dns.resolvers else "—"
        )
        values["Default gateway"].setText(snapshot.route.gateway or "—")
        addresses = [
            f"{interface.name}: {', '.join(interface.ipv4 + interface.ipv6)}"
            for interface in snapshot.interfaces
            if interface.active and interface.kind != "loopback"
        ]
        values["Addresses"].setText("\n".join(addresses) if addresses else "—")
        proxy = snapshot.proxy
        values["Proxy"].setText(
            "; ".join(
                part
                for part in (proxy.http, proxy.https, proxy.socks, proxy.pac_url)
                if part
            )
            or "None configured"
        )
        values["Audited"].setText(
            f"{relative_time(report.started)} — took {report.duration:.1f}s"
        )
        self.limitations_label.setText(
            "\n".join(f"• {note}" for note in snapshot.limitations)
            if snapshot.limitations
            else "Everything this audit checks was readable."
        )

    # -- helpers ----------------------------------------------------------

    def _colour(self, tone: str) -> str:
        palette = self._palette or self.window.palette_tokens
        return {
            "good": palette.good,
            "warn": palette.warn,
            "danger": palette.danger,
            "muted": palette.text_muted,
        }.get(tone, palette.text)

    def export(self) -> None:
        if self.report is None:
            QMessageBox.information(
                self, "Nothing to export", "Run an audit first, then export its report."
            )
            return
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Export network audit",
            str(paths.home() / "Downloads" / "ClamMac network audit.html"),
            "Web page (*.html);;Spreadsheet (*.csv);;JSON (*.json)",
        )
        if not destination:
            return
        suffix = Path(destination).suffix.lstrip(".") or "html"
        try:
            written = audit_report.write_report(
                Path(destination), self.report, fmt=suffix
            )
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not export", str(exc))
            return
        self.window.show_toast(f"Exported to {written.name}")


# --------------------------------------------------------------------------
# small builders
# --------------------------------------------------------------------------


def _table(columns: list[str], *, flexible: tuple[int, ...]) -> QTableWidget:
    from ..widgets.common import configure_table

    table = QTableWidget(0, len(columns))
    configure_table(table, columns, flexible=flexible)
    table.setMinimumHeight(260)
    return table


def _wrap(table: QTableWidget) -> QWidget:
    holder = QWidget()
    layout = QVBoxLayout(holder)
    layout.setContentsMargins(10, 10, 10, 10)
    layout.addWidget(table)
    return holder


def _add_finding(
    layout: QVBoxLayout,
    severity_label: str,
    tone: str,
    title: str,
    summary: str,
    recommendation: str,
    evidence: list[str],
    reference: str,
    *,
    first: bool,
) -> None:
    """Append one finding to the findings column.

    The pieces go straight into the column rather than into a container widget
    of their own. A wrapped QLabel decides its height from its width, and that
    dependency only propagates through nested *layouts* -- put a plain QWidget
    in the middle and the column sizes every finding as a single line, which
    draws them all on top of each other.
    """
    if not first:
        separator = Separator()
        separator.setContentsMargins(0, 10, 0, 10)
        layout.addSpacing(6)
        layout.addWidget(separator)
        layout.addSpacing(10)

    header = QHBoxLayout()
    header.setSpacing(9)
    header.addWidget(badge(severity_label, tone), 0, Qt.AlignmentFlag.AlignTop)
    header.addWidget(label(title, role="heading", wrap=True), 1)
    layout.addLayout(header)
    layout.addSpacing(3)

    layout.addWidget(subtitle(summary))
    if recommendation:
        fix = label(recommendation, wrap=True)
        fix.setProperty("tone", "muted")
        layout.addWidget(fix)
    if evidence:
        layout.addSpacing(2)
        layout.addWidget(mono("\n".join(evidence[:8])))
    if reference:
        layout.addWidget(caption(reference))


def _empty(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
            continue
        child = item.layout()
        if child is not None:
            _empty(child)
            child.deleteLater()


def _severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def _state_text(flag: bool | None, detail: str = "") -> str:
    if flag is None:
        return detail or "Could not be read"
    return "On" if flag else "Off"


def _firewall_phrase(snapshot) -> str:
    firewall = snapshot.firewall
    if firewall.enabled is True and firewall.block_all is True:
        return "The firewall is blocking all incoming connections."
    if firewall.enabled is True:
        return "The firewall is on."
    if firewall.enabled is False:
        return "The firewall is off."
    return "The firewall's state could not be read."


def _tint(item: QTableWidgetItem, colour: str) -> None:
    from PySide6.QtGui import QBrush, QColor

    item.setForeground(QBrush(QColor(colour)))


def _repolish(widget: QWidget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()
