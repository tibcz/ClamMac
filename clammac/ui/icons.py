"""Icons, drawn rather than shipped.

Every glyph here is built from primitives -- lines, arcs, rounded rectangles --
written for this project. Nothing is traced from an existing icon set and no
font outlines are embedded, which keeps ClamMac free of third-party artwork
licensing and keeps the application bundle small.

Icons are drawn at request time in the current accent colour, so they follow
the theme without needing a second set of assets for dark mode.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

__all__ = ["NAMES", "app_icon_pixmap", "glyph"]

NAMES = (
    "shield",
    "search",
    "box",
    "download",
    "pulse",
    "clock",
    "list",
    "gear",
    "info",
    "check",
    "warning",
    "cross",
    "network",
    "lock",
)


def _pen(painter: QPainter, colour: QColor, width: float) -> None:
    pen = QPen(colour)
    pen.setWidthF(width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)


def _shield_path(inset: float = 3.0, size: float = 24.0) -> QPainterPath:
    """A shield outline: the one shape the whole icon set is built around."""
    left, right = inset, size - inset
    top, bottom = inset, size - inset
    middle = size / 2
    shoulder = top + (bottom - top) * 0.34

    path = QPainterPath()
    path.moveTo(middle, top)
    path.lineTo(right, top + (bottom - top) * 0.16)
    path.lineTo(right, shoulder)
    path.cubicTo(
        QPointF(right, bottom - (bottom - top) * 0.22),
        QPointF(middle + (right - middle) * 0.55, bottom),
        QPointF(middle, bottom),
    )
    path.cubicTo(
        QPointF(middle - (right - middle) * 0.55, bottom),
        QPointF(left, bottom - (bottom - top) * 0.22),
        QPointF(left, shoulder),
    )
    path.lineTo(left, top + (bottom - top) * 0.16)
    path.closeSubpath()
    return path


def _draw(name: str, painter: QPainter, colour: QColor, size: float) -> None:
    s = size
    stroke = max(1.6, s / 13.0)
    _pen(painter, colour, stroke)

    if name == "shield":
        painter.drawPath(_shield_path(s * 0.13, s))
    elif name == "check":
        painter.drawPolyline(
            [QPointF(s * 0.22, s * 0.52), QPointF(s * 0.42, s * 0.72), QPointF(s * 0.78, s * 0.30)]
        )
    elif name == "cross":
        painter.drawLine(QPointF(s * 0.26, s * 0.26), QPointF(s * 0.74, s * 0.74))
        painter.drawLine(QPointF(s * 0.74, s * 0.26), QPointF(s * 0.26, s * 0.74))
    elif name == "search":
        radius = s * 0.24
        painter.drawEllipse(QPointF(s * 0.44, s * 0.44), radius, radius)
        painter.drawLine(QPointF(s * 0.62, s * 0.62), QPointF(s * 0.80, s * 0.80))
    elif name == "box":
        rect = QRectF(s * 0.18, s * 0.28, s * 0.64, s * 0.50)
        painter.drawRoundedRect(rect, s * 0.06, s * 0.06)
        painter.drawLine(QPointF(s * 0.18, s * 0.44), QPointF(s * 0.82, s * 0.44))
        painter.drawLine(QPointF(s * 0.42, s * 0.60), QPointF(s * 0.58, s * 0.60))
    elif name == "download":
        painter.drawLine(QPointF(s * 0.50, s * 0.20), QPointF(s * 0.50, s * 0.60))
        painter.drawPolyline(
            [QPointF(s * 0.34, s * 0.46), QPointF(s * 0.50, s * 0.62), QPointF(s * 0.66, s * 0.46)]
        )
        painter.drawPolyline(
            [QPointF(s * 0.22, s * 0.74), QPointF(s * 0.22, s * 0.80), QPointF(s * 0.78, s * 0.80),
             QPointF(s * 0.78, s * 0.74)]
        )
    elif name == "pulse":
        painter.drawPolyline(
            [
                QPointF(s * 0.14, s * 0.52), QPointF(s * 0.34, s * 0.52),
                QPointF(s * 0.43, s * 0.28), QPointF(s * 0.56, s * 0.74),
                QPointF(s * 0.65, s * 0.52), QPointF(s * 0.86, s * 0.52),
            ]
        )
    elif name == "clock":
        painter.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.31, s * 0.31)
        painter.drawPolyline(
            [QPointF(s * 0.50, s * 0.30), QPointF(s * 0.50, s * 0.52), QPointF(s * 0.66, s * 0.60)]
        )
    elif name == "list":
        for y in (0.30, 0.50, 0.70):
            painter.drawLine(QPointF(s * 0.20, s * y), QPointF(s * 0.22, s * y))
            painter.drawLine(QPointF(s * 0.34, s * y), QPointF(s * 0.80, s * y))
    elif name == "gear":
        painter.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.15, s * 0.15)
        painter.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.31, s * 0.31)
        for step in range(8):
            from math import cos, radians, sin

            angle = radians(step * 45)
            painter.drawLine(
                QPointF(s * 0.5 + cos(angle) * s * 0.31, s * 0.5 + sin(angle) * s * 0.31),
                QPointF(s * 0.5 + cos(angle) * s * 0.40, s * 0.5 + sin(angle) * s * 0.40),
            )
    elif name == "info":
        painter.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.32, s * 0.32)
        painter.drawLine(QPointF(s * 0.5, s * 0.46), QPointF(s * 0.5, s * 0.68))
        painter.drawPoint(QPointF(s * 0.5, s * 0.33))
    elif name == "network":
        # A globe: an outline with one meridian and two parallels. Reads as
        # "the network" at 18px, which the more obvious node-and-edge diagram
        # does not.
        radius = s * 0.32
        painter.drawEllipse(QPointF(s * 0.5, s * 0.5), radius, radius)
        painter.drawEllipse(QPointF(s * 0.5, s * 0.5), radius * 0.45, radius)
        painter.drawLine(QPointF(s * 0.18, s * 0.5), QPointF(s * 0.82, s * 0.5))
        painter.drawArc(
            QRectF(s * 0.18, s * 0.24, s * 0.64, s * 0.34), 200 * 16, 140 * 16
        )
        painter.drawArc(
            QRectF(s * 0.18, s * 0.42, s * 0.64, s * 0.34), 20 * 16, 140 * 16
        )
    elif name == "lock":
        painter.drawRoundedRect(
            QRectF(s * 0.24, s * 0.46, s * 0.52, s * 0.34), s * 0.06, s * 0.06
        )
        painter.drawArc(QRectF(s * 0.34, s * 0.20, s * 0.32, s * 0.36), 0, 180 * 16)
    elif name == "warning":
        painter.drawPolyline(
            [QPointF(s * 0.5, s * 0.18), QPointF(s * 0.86, s * 0.80),
             QPointF(s * 0.14, s * 0.80), QPointF(s * 0.5, s * 0.18)]
        )
        painter.drawLine(QPointF(s * 0.5, s * 0.42), QPointF(s * 0.5, s * 0.60))
        painter.drawPoint(QPointF(s * 0.5, s * 0.70))


def glyph(name: str, colour: str | QColor, size: int = 20) -> QIcon:
    """A themed icon, drawn at ``size`` points (and again at 2x for Retina)."""
    icon = QIcon()
    for scale in (1, 2):
        pixels = size * scale
        pixmap = QPixmap(pixels, pixels)
        pixmap.setDevicePixelRatio(scale)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        _draw(name, painter, QColor(colour), float(pixels))
        painter.end()
        icon.addPixmap(pixmap)
    return icon


def app_icon_pixmap(size: int = 512, *, accent: str = "#2D6BE4", tint: str = "#5FD3A6") -> QPixmap:
    """The application icon: a shield with a scan sweep across it.

    Drawn from the same primitives as the interface glyphs so the icon and the
    app look like they come from the same place. Deliberately unlike the
    branding of ClamAV or any other antivirus product.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    from PySide6.QtGui import QLinearGradient

    s = float(size)
    shield = _shield_path(s * 0.14, s)

    gradient = QLinearGradient(0, 0, 0, s)
    gradient.setColorAt(0.0, QColor(accent).lighter(118))
    gradient.setColorAt(1.0, QColor(accent).darker(122))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(gradient)
    painter.drawPath(shield)

    # A lighter sweep across the upper half, clipped to the shield.
    painter.setClipPath(shield)
    sweep = QPainterPath()
    sweep.moveTo(0, s * 0.46)
    sweep.cubicTo(QPointF(s * 0.35, s * 0.32), QPointF(s * 0.65, s * 0.58), QPointF(s, s * 0.40))
    sweep.lineTo(s, 0)
    sweep.lineTo(0, 0)
    sweep.closeSubpath()
    painter.setBrush(QColor(255, 255, 255, 34))
    painter.drawPath(sweep)
    painter.setClipping(False)

    # The check mark, in the accent tint.
    pen = QPen(QColor(tint))
    pen.setWidthF(s * 0.075)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPolyline(
        [QPointF(s * 0.33, s * 0.50), QPointF(s * 0.45, s * 0.62), QPointF(s * 0.69, s * 0.38)]
    )

    painter.end()
    return pixmap
