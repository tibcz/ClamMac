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
        assert len(window.pages) == 8
        assert window.sidebar.count() == len(window.pages)

    def test_each_page_has_a_title_and_an_icon(self, window):
        for index, page in enumerate(window.pages):
            assert page.page_title
            assert not window.sidebar.item(index).icon().isNull()

    def test_the_menu_bar_is_populated(self, window):
        titles = [a.text() for a in window.menuBar().actions()]
        assert "&Scan" in titles
        assert "&Tools" in titles


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
