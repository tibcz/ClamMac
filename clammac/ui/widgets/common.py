"""Small building blocks the pages are assembled from.

Factories rather than subclasses wherever a subclass would add nothing: the
styling lives in the stylesheet, keyed off Qt dynamic properties, so these
mostly exist to set those properties consistently and keep page code readable.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..theme import Metrics, Palette

__all__ = [
    "Card",
    "ProgressRing",
    "Separator",
    "SettingRow",
    "Spinner",
    "StatCard",
    "button",
    "caption",
    "configure_table",
    "elide",
    "heading",
    "human_duration",
    "human_size",
    "label",
    "metric",
    "relative_time",
    "subtitle",
    "title",
]


# --------------------------------------------------------------------------
# labels
# --------------------------------------------------------------------------


def label(text: str = "", *, role: str = "", tone: str = "", wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setProperty("role", role)
    if tone:
        widget.setProperty("tone", tone)
    widget.setWordWrap(wrap)
    widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def title(text: str = "") -> QLabel:
    return label(text, role="title")


def heading(text: str = "") -> QLabel:
    return label(text, role="heading")


def subtitle(text: str = "", *, wrap: bool = True) -> QLabel:
    return label(text, role="subtitle", wrap=wrap)


def caption(text: str = "", *, wrap: bool = True) -> QLabel:
    """Small explanatory text. Wraps by default.

    A long non-wrapping label reports a very wide minimum size, which
    propagates up through the layout and pushes the page wider than the
    window -- and since pages do not scroll sideways, the right-hand edge of
    everything gets clipped. Descriptive text must wrap.
    """
    return label(text, role="caption", wrap=wrap)


def metric(text: str = "", tone: str = "") -> QLabel:
    return label(text, role="metric", tone=tone)


# --------------------------------------------------------------------------
# buttons
# --------------------------------------------------------------------------


def button(
    text: str,
    *,
    variant: str = "",
    size: str = "",
    on_click: Callable[[], None] | None = None,
    tooltip: str = "",
    enabled: bool = True,
) -> QPushButton:
    widget = QPushButton(text)
    if variant:
        widget.setProperty("variant", variant)
    if size:
        widget.setProperty("size", size)
    if tooltip:
        widget.setToolTip(tooltip)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    widget.setEnabled(enabled)
    if on_click is not None:
        widget.clicked.connect(lambda: on_click())
    return widget


# --------------------------------------------------------------------------
# containers
# --------------------------------------------------------------------------


class Card(QFrame):
    """A padded panel. The visual unit every page is built from."""

    def __init__(
        self,
        *,
        role: str = "card",
        padding: int = 18,
        spacing: int = Metrics.GAP,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("role", role)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)

    def add_stretch(self, amount: int = 1) -> None:
        self.body.addStretch(amount)

    def add_row(self, *widgets: QWidget, spacing: int = Metrics.GAP) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(spacing)
        for widget in widgets:
            row.addWidget(widget)
        self.body.addLayout(row)
        return row

    def shadow(self, palette: Palette) -> None:
        """A soft drop shadow. Used sparingly -- only the dashboard hero."""
        effect = QGraphicsDropShadowEffect(self)
        effect.setBlurRadius(24)
        effect.setOffset(0, 3)
        effect.setColor(QColor(0, 0, 0, 55 if palette.is_dark else 26))
        self.setGraphicsEffect(effect)


class StatCard(Card):
    """A number with a label under it."""

    def __init__(self, value: str, description: str, *, tone: str = "", parent=None) -> None:
        super().__init__(padding=14, spacing=2, parent=parent)
        self.value_label = metric(value, tone)
        self.description_label = caption(description.upper())
        self.add(self.value_label)
        self.add(self.description_label)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def set_value(self, value: str, tone: str = "") -> None:
        self.value_label.setText(value)
        self.value_label.setProperty("tone", tone)
        _restyle(self.value_label)


class SettingRow(QWidget):
    """A control on the right, its explanation on the left."""

    def __init__(self, text: str, control: QWidget, *, hint: str = "", parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(Metrics.GAP_WIDE)

        text_column = QVBoxLayout()
        text_column.setSpacing(1)
        text_column.addWidget(label(text))
        if hint:
            text_column.addWidget(caption(hint))
        layout.addLayout(text_column, 1)
        layout.addWidget(control, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.control = control


class Separator(QFrame):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setProperty("role", "separator")
        self.setFixedHeight(1)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


# --------------------------------------------------------------------------
# tables
# --------------------------------------------------------------------------


def configure_table(table, columns: list[str], *, flexible: tuple[int, ...] = (0,)) -> None:
    """Apply ClamMac's table conventions, and stop tables widening the page.

    A table whose columns size to their contents reports a large minimum width,
    which propagates up and pushes the whole page wider than the window. Since
    pages do not scroll sideways, that clips content off the right edge. Giving
    the table an Ignored horizontal size policy lets it take the width it is
    offered and scroll internally instead, which is what a table inside a fixed
    column should do anyway.
    """
    table.setHorizontalHeaderLabels(columns)
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.setTextElideMode(Qt.TextElideMode.ElideMiddle)

    header = table.horizontalHeader()
    header.setMinimumSectionSize(56)
    header.setStretchLastSection(False)
    for index in range(len(columns)):
        header.setSectionResizeMode(
            index,
            QHeaderView.ResizeMode.Stretch
            if index in flexible
            else QHeaderView.ResizeMode.ResizeToContents,
        )

    table.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)


# --------------------------------------------------------------------------
# progress indicators
# --------------------------------------------------------------------------


class Spinner(QWidget):
    """An indeterminate activity ring, for work with no measurable end."""

    def __init__(self, colour: str = "#2D6BE4", diameter: int = 18, parent=None) -> None:
        super().__init__(parent)
        self._angle = 0
        self._colour = QColor(colour)
        self.setFixedSize(diameter, diameter)
        from PySide6.QtCore import QTimer

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)

    def start(self) -> None:
        if not self._timer.isActive():
            self._timer.start(28)
        self.show()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def set_colour(self, colour: str) -> None:
        self._colour = QColor(colour)
        self.update()

    def _advance(self) -> None:
        self._angle = (self._angle + 12) % 360
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(self._colour)
        pen.setWidthF(max(2.0, self.width() / 9))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        inset = pen.widthF()
        rect = self.rect().adjusted(int(inset), int(inset), -int(inset), -int(inset))
        painter.drawArc(rect, -self._angle * 16, 100 * 16)


class ProgressRing(QWidget):
    """A circular progress indicator with a value in the middle.

    Used for the scan page, where a ring reads more clearly at a glance than a
    bar and leaves room for the count in the centre.
    """

    def __init__(self, diameter: int = 132, parent=None) -> None:
        super().__init__(parent)
        self._fraction = -1.0
        self._caption = ""
        self._value = ""
        self._track = QColor("#E1E4E9")
        self._colour = QColor("#2D6BE4")
        self._sweep = 0
        self.setFixedSize(diameter, diameter)
        from PySide6.QtCore import QTimer

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)

    def set_palette_colours(self, track: str, colour: str) -> None:
        self._track = QColor(track)
        self._colour = QColor(colour)
        self.update()

    def set_colour(self, colour: str) -> None:
        self._colour = QColor(colour)
        self.update()

    def set_progress(self, fraction: float, value: str = "", caption_text: str = "") -> None:
        self._fraction = fraction
        self._value = value
        self._caption = caption_text
        if fraction < 0:
            if not self._timer.isActive():
                self._timer.start(28)
        else:
            self._timer.stop()
        self.update()

    def stop(self) -> None:
        self._timer.stop()
        self.update()

    def _advance(self) -> None:
        self._sweep = (self._sweep + 10) % 360
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = max(7.0, self.width() / 14)
        inset = width / 2 + 1
        rect = self.rect().adjusted(int(inset), int(inset), -int(inset), -int(inset))

        track_pen = QPen(self._track)
        track_pen.setWidthF(width)
        painter.setPen(track_pen)
        painter.drawEllipse(rect)

        value_pen = QPen(self._colour)
        value_pen.setWidthF(width)
        value_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(value_pen)
        if self._fraction < 0:
            painter.drawArc(rect, -self._sweep * 16, 90 * 16)
        else:
            painter.drawArc(rect, 90 * 16, -int(self._fraction * 360) * 16)

        if self._value:
            painter.setPen(QPen(self.palette().windowText().color()))
            font = QFont(self.font())
            font.setPointSize(max(15, self.width() // 6))
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            value_rect = rect.adjusted(0, -8 if self._caption else 0, 0, -8 if self._caption else 0)
            painter.drawText(value_rect, Qt.AlignmentFlag.AlignCenter, self._value)

        if self._caption:
            small = QFont(self.font())
            small.setPointSize(max(9, self.width() // 15))
            painter.setFont(small)
            painter.setPen(QPen(QColor(self._track).darker(160)))
            painter.drawText(
                rect.adjusted(0, self.width() // 5, 0, 0),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
                self._caption,
            )


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------


def elide(text: str, limit: int = 60) -> str:
    if len(text) <= limit:
        return text
    keep = limit - 1
    return text[: keep // 2] + "…" + text[-(keep - keep // 2) :]


def human_size(num_bytes: float) -> str:
    value = float(num_bytes)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0 or unit == "TB":
            if unit == "bytes":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def relative_time(when) -> str:
    """A friendly 'when did this happen', for timestamps in lists."""
    from datetime import datetime

    if when is None:
        return "Never"
    if isinstance(when, str):
        try:
            when = datetime.fromisoformat(when)
        except ValueError:
            return when
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    delta = (datetime.now(UTC) - when).total_seconds()

    if delta < 45:
        return "Just now"
    if delta < 3600:
        minutes = int(delta // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if delta < 86400:
        hours = int(delta // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    if delta < 7 * 86400:
        days = int(delta // 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    return when.astimezone().strftime("%d %b %Y")


def _restyle(widget: QWidget) -> None:
    """Force a re-evaluation of the stylesheet after a property change."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()
