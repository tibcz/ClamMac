"""The interface: does it build, render, and survive being poked at.

These run headless. They cannot judge whether the result looks good, but they
do catch the failures that matter -- a page that raises on construction, a
signal wired to a method that no longer exists, a control whose handler
explodes, or a layout that pushes content outside the window.
"""

from __future__ import annotations

import pytest

from clammac.core import engine as engine_module
from clammac.core.config import Settings, Theme
from clammac.core.service import AppService

pytest.importorskip("PySide6", reason="the interface tests need PySide6")

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QSpinBox,
)


@pytest.fixture(scope="session")
def qt_app():
    """One QApplication for the whole session; Qt allows only one."""
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture
def window(qt_app, engine_tools, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from clammac.ui.main_window import MainWindow

    settings = Settings()
    settings.interface.completed_first_run = True
    settings.interface.show_menu_bar_item = False

    service = AppService(settings=settings)
    service.engine = engine_module.EngineInfo(
        tools=engine_tools, engine_version="1.5.4", database_version=27700
    )
    main = MainWindow(service)
    main.resize(1120, 780)
    yield main
    main.close()


class TestConstruction:
    def test_every_page_is_present(self, window):
        assert len(window.pages) == 9
        assert window.sidebar.count() == len(window.pages)
        assert [page.page_title for page in window.pages] == [
            "Overview",
            "Scan",
            "Protection",
            "Network",
            "Quarantine",
            "Definitions",
            "Schedule",
            "History",
            "Settings",
        ]

    def test_each_page_has_a_title_and_an_icon(self, window):
        for index, page in enumerate(window.pages):
            assert page.page_title
            assert not window.sidebar.item(index).icon().isNull()

    def test_the_menu_bar_is_populated(self, window):
        titles = [a.text() for a in window.menuBar().actions()]
        assert "&Scan" in titles
        assert "&Tools" in titles

    def test_the_tools_menu_offers_the_network_audit(self, window):
        tools = next(a for a in window.menuBar().actions() if a.text() == "&Tools")
        assert "Run &Network Audit" in [a.text() for a in tools.menu().actions()]


class TestNavigation:
    def test_visiting_every_page_twice_does_not_raise(self, window, qt_app):
        for _round in range(2):
            for index in range(len(window.pages)):
                window.sidebar.setCurrentRow(index)
                qt_app.processEvents()
        assert window.stack.currentIndex() == len(window.pages) - 1

    def test_pages_render_to_a_pixmap(self, window, qt_app):
        for index in range(len(window.pages)):
            window.sidebar.setCurrentRow(index)
            qt_app.processEvents()
            image = window.grab()
            assert not image.isNull()
            assert image.width() > 0


class TestLayout:
    @pytest.mark.parametrize("width", [940, 1120, 1400])
    def test_content_stays_inside_the_window(self, window, qt_app, width):
        """A page wider than the window silently clips its right-hand edge.

        Long non-wrapping labels and content-sized tables both cause this, and
        neither is visible in a screenshot taken at the wrong width, so it is
        checked at the narrowest supported size and above.
        """
        window.show()
        window.resize(width, 780)
        qt_app.processEvents()
        too_wide = []
        for index, page in enumerate(window.pages):
            window.sidebar.setCurrentRow(index)
            for _ in range(4):
                qt_app.processEvents()
            required = page.content_width_required()
            available = page.content_width_available()
            if available and required > available:
                too_wide.append(
                    f"{page.page_title} needs {required}px but has {available}px"
                )
        assert not too_wide, (
            f"at {width}px these pages overflow and their right edge is clipped: "
            + "; ".join(too_wide)
        )


class TestTheming:
    @pytest.mark.parametrize("theme", list(Theme))
    def test_every_theme_applies(self, window, qt_app, theme):
        window.service.settings.interface.theme = theme
        window.apply_theme()
        qt_app.processEvents()
        assert window.palette_tokens.name in {"light", "dark"}

    def test_switching_back_and_forth_is_stable(self, window, qt_app):
        for theme in (Theme.DARK, Theme.LIGHT, Theme.DARK, Theme.SYSTEM):
            window.service.settings.interface.theme = theme
            window.apply_theme()
            qt_app.processEvents()
        assert not window.grab().isNull()


class TestControls:
    def test_every_checkbox_can_be_toggled(self, window, qt_app):
        for page in window.pages:
            window.sidebar.setCurrentRow(window.pages.index(page))
            qt_app.processEvents()
            for checkbox in page.findChildren(QCheckBox):
                original = checkbox.isChecked()
                checkbox.setChecked(not original)
                qt_app.processEvents()
                checkbox.setChecked(original)
                qt_app.processEvents()

    def test_every_combo_box_can_be_cycled(self, window, qt_app):
        for page in window.pages:
            window.sidebar.setCurrentRow(window.pages.index(page))
            qt_app.processEvents()
            for combo in page.findChildren(QComboBox):
                for index in range(combo.count()):
                    combo.setCurrentIndex(index)
                    qt_app.processEvents()

    def test_spin_boxes_accept_their_extremes(self, window, qt_app):
        for page in window.pages:
            window.sidebar.setCurrentRow(window.pages.index(page))
            qt_app.processEvents()
            for spin in page.findChildren(QSpinBox):
                spin.setValue(spin.minimum())
                spin.setValue(spin.maximum())
                qt_app.processEvents()


class TestDialogs:
    def test_the_about_box_builds_and_carries_the_notices(self, window, qt_app):
        from PySide6.QtWidgets import QPlainTextEdit

        from clammac.ui.about import AboutDialog

        dialog = AboutDialog(window)
        text = " ".join(v.toPlainText() for v in dialog.findChildren(QPlainTextEdit))
        assert "registered trademark of Cisco Systems" in text
        assert "GNU General Public License" in text
        assert "not affiliated" in text
        assert "LGPL" in text
        dialog.close()

    def test_the_setup_wizard_builds(self, window, qt_app):
        from clammac.ui.setup_wizard import SetupWizard

        wizard = SetupWizard(window.service, window)
        assert wizard.primary_button.text()
        wizard.close()


class TestScanFlow:
    def test_a_scan_runs_through_the_window(self, window, qt_app, sample_tree):
        import time

        from clammac.core.scanner import ScanKind
        from clammac.ui.pages.scan import ScanPage

        window.start_scan(ScanKind.CUSTOM, [sample_tree])
        job = window.service.active_scan
        assert job is not None
        job.wait(60)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            qt_app.processEvents()
            if window._page(ScanPage).table.rowCount():
                break
            time.sleep(0.02)

        page = window._page(ScanPage)
        assert page.table.rowCount() == 1
        assert page.table.item(0, 0).text() == "Test.Fake.Signature-1"
        assert window.service.quarantine.count() == 1


class TestNetworkAudit:
    """The audit page, driven the way the window drives it."""

    def test_it_opens_before_any_audit_has_run(self, window, qt_app):
        from clammac.ui.pages.network import NetworkPage

        page = window._page(NetworkPage)
        window.show_page(NetworkPage)
        qt_app.processEvents()
        assert page.report is None
        assert "No audit" in page.hero_headline.text()
        assert not page.export_button.isEnabled()

    def test_a_full_audit_runs_through_the_window(self, window, qt_app):
        import time

        from clammac.ui.pages.network import NetworkPage

        window.run_network_audit()
        audit = window.service.active_audit
        assert audit is not None
        audit.wait(60)

        deadline = time.monotonic() + 10
        page = window._page(NetworkPage)
        while time.monotonic() < deadline:
            qt_app.processEvents()
            if page.report is not None:
                break
            time.sleep(0.02)

        assert page.report is not None
        assert page.grade_label.text() in {"A", "B", "C", "D", "F"}
        assert page.export_button.isEnabled()
        assert page.ports_table.rowCount() == len(page.report.snapshot.listeners)
        assert page.sharing_table.rowCount() == len(page.report.snapshot.sharing)

    def test_the_result_is_recorded_and_shown_on_the_dashboard(self, window, qt_app):
        from clammac.ui.pages.dashboard import DashboardPage

        window.run_network_audit()
        audit = window.service.active_audit
        assert audit is not None
        audit.wait(60)
        for _ in range(20):
            qt_app.processEvents()

        record = window.service.history.last_network_audit()
        assert record is not None
        assert 0 <= record.score <= 100

        dashboard = window._page(DashboardPage)
        dashboard.refresh(window.service.status())
        qt_app.processEvents()
        assert "/100" in dashboard.network_badge.text()

    def test_findings_do_not_draw_on_top_of_each_other(self, window, qt_app):
        """Wrapped text sized as one line stacks findings on top of each other.

        Two ways in: a height-for-width label put inside a plain container
        widget rather than a nested layout, and a row removed from the layout
        but left parented, which keeps painting where it was. Both are
        invisible to every other test here and both make the page unreadable,
        so the rectangles the labels actually occupy are compared directly.
        """
        from PySide6.QtWidgets import QLabel

        from clammac.core.network import checks
        from clammac.core.network.model import (
            AuditReport,
            FirewallState,
            Listener,
            Snapshot,
        )
        from clammac.ui.pages.network import NetworkPage

        window.show()
        window.resize(1120, 900)
        page = window._page(NetworkPage)
        window.show_page(NetworkPage)

        snapshot = Snapshot(
            hostname="test",
            platform="macOS",
            listeners=[
                Listener(protocol="tcp", address="0.0.0.0", port=port, process="thing")
                for port in (11434, 7860, 6379, 22, 5900)
            ],
            firewall=FirewallState(available=True, enabled=False),
        )
        snapshot.sharing = checks.derive_sharing(snapshot)
        report = AuditReport(
            audit_id="x",
            started_at="2026-09-01T10:00:00+00:00",
            snapshot=snapshot,
            findings=checks.evaluate(snapshot),
        )
        assert len(report.findings) >= 5

        page.report = report
        # Twice: re-rendering is what a second audit, or a theme change, does,
        # and a row that is only removed from the layout goes on painting where
        # it was until the event loop gets round to deleting it.
        for _ in range(2):
            page._show_report(report)
            for _ in range(10):
                qt_app.processEvents()

        boxes = []
        for widget in page.findings_card.findChildren(QLabel):
            if not widget.isVisible() or not widget.text().strip():
                continue
            rect = widget.rect().adjusted(1, 1, -1, -1)
            if rect.width() <= 0 or rect.height() <= 0:
                continue
            boxes.append((rect.translated(widget.mapTo(page, rect.topLeft())), widget))
        assert len(boxes) >= 15, "the findings did not render"

        overlaps = [
            f"{first.text()[:36]!r} over {second.text()[:36]!r}"
            for index, (rect, first) in enumerate(boxes)
            for other, second in boxes[index + 1 :]
            if rect.intersects(other)
        ]
        assert not overlaps, "findings are drawn on top of each other: " + "; ".join(
            overlaps[:5]
        )

    def test_exporting_without_a_report_does_not_crash(self, window, qt_app, monkeypatch):
        from PySide6.QtWidgets import QMessageBox

        from clammac.ui.pages.network import NetworkPage

        monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
        window._page(NetworkPage).export()


class TestIcons:
    def test_every_named_glyph_renders(self, qt_app):
        from clammac.ui.icons import NAMES, glyph

        for name in NAMES:
            assert not glyph(name, "#2D6BE4", 20).pixmap(20, 20).isNull()

    def test_the_application_icon_renders_at_every_size(self, qt_app):
        from clammac.ui.icons import app_icon_pixmap

        for size in (16, 32, 128, 512, 1024):
            pixmap = app_icon_pixmap(size)
            assert pixmap.width() == size
            assert pixmap.hasAlphaChannel()
