"""Icons: the interface glyphs are drawn, the application icon is artwork.

Every glyph here is built from primitives -- lines, arcs, rounded rectangles --
written for this project. Nothing is traced from an existing icon set and no
font outlines are embedded, which keeps ClamMac free of third-party artwork
licensing and keeps the application bundle small. The one exception is the
application icon itself, whose artwork is a single image set into the macOS
tile by ``app_icon_pixmap``.

Icons are drawn at request time in the current accent colour, so they follow
the theme without needing a second set of assets for dark mode.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap

from ..core import paths

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


#: The artwork is the one thing here that is shipped rather than drawn: a
#: full-bleed square, which ``app_icon_pixmap`` sets into the macOS icon tile.
_ART_NAME = "app-icon.png"

#: macOS app icons occupy 824 of a 1024-point canvas; the rest is room for the
#: shadow. The corner is a superellipse, the usual stand-in for Apple's
#: continuous curve.
_CANVAS = 1024
_TILE = 824
_SUPERELLIPSE = 5.0


def _art_candidates() -> Iterator[Path]:
    yield Path(__file__).resolve().parent.parent / "resources" / _ART_NAME
    yield paths.bundle_dir() / "clammac" / "resources" / _ART_NAME
    yield paths.bundle_dir() / "resources" / _ART_NAME


def _tile_path(size: float = _TILE) -> QPainterPath:
    centre = _CANVAS / 2
    radius = size / 2
    path = QPainterPath()
    for degrees in range(361):
        angle = math.radians(degrees)
        cosine, sine = math.cos(angle), math.sin(angle)
        point = QPointF(
            centre + radius * math.copysign(abs(cosine) ** (2 / _SUPERELLIPSE), cosine),
            centre + radius * math.copysign(abs(sine) ** (2 / _SUPERELLIPSE), sine),
        )
        if degrees == 0:
            path.moveTo(point)
        else:
            path.lineTo(point)
    path.closeSubpath()
    return path


@lru_cache(maxsize=1)
def _app_icon_master() -> QImage:
    """The icon at full size: artwork, tile mask, shadow and edge light."""
    image = QImage(_CANVAS, _CANVAS, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)

    art = QImage()
    for candidate in _art_candidates():
        if candidate.exists() and art.load(str(candidate)):
            break
    if art.isNull():
        return image

    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    painter.setPen(Qt.PenStyle.NoPen)

    tile = _tile_path()

    # A soft shadow: many faint copies, nudged down, read as one blurred edge.
    for step in range(24, 0, -1):
        painter.setBrush(QColor(0, 0, 0, 3))
        painter.save()
        painter.translate(0, 10 + step * 0.6)
        painter.drawPath(tile)
        painter.restore()

    painter.save()
    painter.setClipPath(tile)
    origin = (_CANVAS - _TILE) / 2
    painter.drawImage(QRectF(origin, origin, _TILE, _TILE), art)
    painter.restore()

    edge = QPen(QColor(255, 255, 255, 40))
    edge.setWidthF(3)
    painter.setPen(edge)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(tile)
    painter.end()
    return image


def app_icon_pixmap(size: int = 512) -> QPixmap:
    """The application icon at ``size`` pixels square.

    Used for the Dock, the window, the About box and the generated ``.icns``,
    so they can never drift apart. Large masters are scaled down in one smooth
    step, which is what keeps the 16 and 32 pixel renditions clean.
    """
    master = _app_icon_master()
    if size != _CANVAS:
        master = master.scaled(
            size,
            size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
    return QPixmap.fromImage(master)
