"""The shape every page shares.

A page is a scrollable column with a title, a subtitle, and content. Pages are
told when they become visible so they can refresh from the service rather than
polling in the background, and told when the palette changes so anything drawn
with QPainter can follow the theme.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QScrollArea, QVBoxLayout, QWidget

from ..theme import Metrics, Palette
from ..widgets.common import subtitle, title

if TYPE_CHECKING:  # pragma: no cover
    from ..main_window import MainWindow

__all__ = ["Page"]


class Page(QWidget):
    """Base class for everything in the main window's stack."""

    #: Shown in the sidebar and as the page heading.
    page_title = "Page"
    #: One line under the heading explaining what this screen is for.
    page_subtitle = ""
    #: Which drawn glyph the sidebar uses.
    page_icon = "shield"

    def __init__(self, window: MainWindow) -> None:
        super().__init__()
        self.window = window
        self.service = window.service
        self.bridge = window.bridge

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)

        self.column = QVBoxLayout(container)
        self.column.setContentsMargins(
            Metrics.PAGE_MARGIN, Metrics.PAGE_MARGIN, Metrics.PAGE_MARGIN, Metrics.PAGE_MARGIN
        )
        self.column.setSpacing(Metrics.GAP_WIDE)

        self.header_row = QHBoxLayout()
        self.header_row.setSpacing(Metrics.GAP)
        header_text = QVBoxLayout()
        header_text.setSpacing(3)
        self.title_label = title(self.page_title)
        header_text.addWidget(self.title_label)
        if self.page_subtitle:
            self.subtitle_label = subtitle(self.page_subtitle)
            header_text.addWidget(self.subtitle_label)
        self.header_row.addLayout(header_text, 1)
        self.column.addLayout(self.header_row)

        self.build()
        self.column.addStretch(1)

    # -- for subclasses ---------------------------------------------------

    def build(self) -> None:
        """Construct the page's content. Called once, during __init__."""

    def on_show(self) -> None:
        """The page just became visible; refresh anything stale."""

    def on_hide(self) -> None:
        """The page is no longer visible."""

    def apply_palette(self, palette: Palette) -> None:
        """The theme changed. Update anything not driven by the stylesheet."""

    # -- helpers ----------------------------------------------------------

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.column.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self.column.addLayout(layout)

    def header_action(self, widget: QWidget) -> QWidget:
        """Put a control on the right-hand side of the page heading."""
        self.header_row.addWidget(widget, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return widget
