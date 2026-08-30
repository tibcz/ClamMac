"""Colours, spacing and the stylesheet that gives ClamMac its look.

Everything visual comes from one set of tokens with a light and a dark value,
so appearance changes in one place and the whole application follows. The
stylesheet is generated from those tokens rather than written out twice.

ClamMac follows the system appearance by default. Qt 6.5 and later report it
through ``QStyleHints.colorScheme()``; on anything older the window
background's luminance is a reliable enough proxy.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QPalette

from ..core.config import Theme

__all__ = ["DARK", "LIGHT", "Metrics", "Palette", "palette_for", "stylesheet", "system_is_dark"]


@dataclass(frozen=True)
class Palette:
    """Every colour the interface uses."""

    name: str
    window: str
    surface: str
    surface_alt: str
    surface_hover: str
    border: str
    border_strong: str
    text: str
    text_muted: str
    text_faint: str
    accent: str
    accent_hover: str
    accent_text: str
    good: str
    good_soft: str
    warn: str
    warn_soft: str
    danger: str
    danger_soft: str
    sidebar: str
    sidebar_selected: str
    shadow: str

    @property
    def is_dark(self) -> bool:
        return self.name == "dark"


LIGHT = Palette(
    name="light",
    window="#F4F5F7",
    surface="#FFFFFF",
    surface_alt="#FAFBFC",
    surface_hover="#F0F2F5",
    border="#E1E4E9",
    border_strong="#CBD1D9",
    text="#14171C",
    text_muted="#5F6874",
    text_faint="#8A929E",
    accent="#2D6BE4",
    accent_hover="#255CC8",
    accent_text="#FFFFFF",
    good="#158A4C",
    good_soft="#E3F5EA",
    warn="#B8710F",
    warn_soft="#FDF1DF",
    danger="#C93A36",
    danger_soft="#FCE9E8",
    sidebar="#ECEEF1",
    sidebar_selected="#DCE3F5",
    shadow="rgba(15, 20, 30, 0.10)",
)

DARK = Palette(
    name="dark",
    window="#151719",
    surface="#1D2025",
    surface_alt="#23272D",
    surface_hover="#2A2F36",
    border="#2E333B",
    border_strong="#3D444E",
    text="#E9EBEF",
    text_muted="#9AA3B0",
    text_faint="#727B88",
    accent="#5B93F5",
    accent_hover="#6FA2FF",
    accent_text="#0E1116",
    good="#3ECF7E",
    good_soft="#14301F",
    warn="#E5A73C",
    warn_soft="#33270F",
    danger="#F0706B",
    danger_soft="#361B1A",
    sidebar="#1A1D21",
    sidebar_selected="#2B3648",
    shadow="rgba(0, 0, 0, 0.40)",
)


class Metrics:
    """Spacing and sizing constants, so layouts stay consistent."""

    GAP_TIGHT = 6
    GAP = 12
    GAP_WIDE = 20
    PAGE_MARGIN = 28
    RADIUS = 10
    RADIUS_SMALL = 6
    SIDEBAR_WIDTH = 208
    ROW_HEIGHT = 34
    CONTROL_HEIGHT = 30


def system_is_dark() -> bool:
    """Is the system currently in dark mode?"""
    application = QGuiApplication.instance()
    if application is None:
        return False

    hints = application.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is not None:
        try:
            return scheme() == Qt.ColorScheme.Dark
        except (AttributeError, TypeError):
            pass

    # Fall back to asking whether the window background is darker than its text.
    palette = application.palette()
    background = palette.color(QPalette.ColorRole.Window)
    return background.lightness() < 128


def palette_for(theme: Theme) -> Palette:
    if theme is Theme.LIGHT:
        return LIGHT
    if theme is Theme.DARK:
        return DARK
    return DARK if system_is_dark() else LIGHT


def default_font() -> QFont:
    """The system UI font, at a size that suits dense information."""
    font = QFont()
    font.setFamilies(["SF Pro Text", "-apple-system", "Helvetica Neue", "Segoe UI", "Inter"])
    font.setPointSize(13)
    return font


def mix(first: str, second: str, amount: float) -> str:
    """Blend two hex colours. Used for subtle derived shades."""
    a, b = QColor(first), QColor(second)
    return QColor(
        round(a.red() + (b.red() - a.red()) * amount),
        round(a.green() + (b.green() - a.green()) * amount),
        round(a.blue() + (b.blue() - a.blue()) * amount),
    ).name()


def stylesheet(p: Palette) -> str:
    """The application-wide Qt stylesheet, generated from a palette."""
    m = Metrics
    return f"""
/* ---------- base ---------- */
QWidget {{
    background: transparent;
    color: {p.text};
    font-size: 13px;
}}
QMainWindow, QDialog {{ background: {p.window}; }}

QToolTip {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: {m.RADIUS_SMALL}px;
    padding: 5px 8px;
}}

/* ---------- typography helpers ---------- */
QLabel[role="title"]    {{ font-size: 22px; font-weight: 650; color: {p.text}; }}
QLabel[role="heading"]  {{ font-size: 15px; font-weight: 600; color: {p.text}; }}
QLabel[role="subtitle"] {{ font-size: 13px; color: {p.text_muted}; }}
QLabel[role="caption"]  {{ font-size: 11px; color: {p.text_faint}; }}
QLabel[role="metric"]   {{ font-size: 26px; font-weight: 650; color: {p.text}; }}
QLabel[role="mono"]     {{ font-family: "SF Mono", ui-monospace, Menlo, monospace; font-size: 11px;
                           color: {p.text_muted}; }}
QLabel[tone="good"]     {{ color: {p.good}; }}
QLabel[tone="warn"]     {{ color: {p.warn}; }}
QLabel[tone="danger"]   {{ color: {p.danger}; }}
QLabel[tone="muted"]    {{ color: {p.text_muted}; }}

/* ---------- cards ---------- */
QFrame[role="card"] {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: {m.RADIUS}px;
}}
QFrame[role="hero"] {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 14px;
}}
QFrame[role="separator"] {{ background: {p.border}; border: none; max-height: 1px; }}

/* ---------- sidebar ---------- */
QListWidget#sidebar {{
    background: {p.sidebar};
    border: none;
    border-right: 1px solid {p.border};
    outline: none;
    padding: 10px 8px;
}}
QListWidget#sidebar::item {{
    color: {p.text_muted};
    border-radius: {m.RADIUS_SMALL}px;
    padding: 7px 10px;
    margin: 1px 0;
}}
QListWidget#sidebar::item:hover {{ background: {p.surface_hover}; color: {p.text}; }}
QListWidget#sidebar::item:selected {{
    background: {p.sidebar_selected};
    color: {p.text};
    font-weight: 600;
}}

/* ---------- buttons ---------- */
QPushButton {{
    background: {p.surface};
    color: {p.text};
    border: 1px solid {p.border_strong};
    border-radius: {m.RADIUS_SMALL}px;
    padding: 6px 14px;
    min-height: {m.CONTROL_HEIGHT - 12}px;
}}
QPushButton:hover  {{ background: {p.surface_hover}; }}
QPushButton:pressed {{ background: {p.border}; }}
QPushButton:disabled {{ color: {p.text_faint}; border-color: {p.border}; background: {p.surface_alt}; }}

QPushButton[variant="primary"] {{
    background: {p.accent};
    color: {p.accent_text};
    border: 1px solid {p.accent};
    font-weight: 600;
}}
QPushButton[variant="primary"]:hover  {{ background: {p.accent_hover}; border-color: {p.accent_hover}; }}
QPushButton[variant="primary"]:disabled {{
    background: {mix(p.accent, p.surface, 0.6)};
    border-color: transparent;
    color: {p.text_faint};
}}
QPushButton[variant="danger"] {{
    background: {p.danger}; color: #FFFFFF; border: 1px solid {p.danger}; font-weight: 600;
}}
QPushButton[variant="danger"]:hover {{ background: {mix(p.danger, "#000000", 0.12)}; }}
QPushButton[variant="ghost"] {{ background: transparent; border-color: transparent; color: {p.accent}; }}
QPushButton[variant="ghost"]:hover {{ background: {p.surface_hover}; }}
QPushButton[size="large"] {{ font-size: 14px; padding: 10px 22px; }}

/* ---------- inputs ---------- */
QLineEdit, QSpinBox, QComboBox, QTimeEdit, QPlainTextEdit, QTextEdit {{
    background: {p.surface};
    border: 1px solid {p.border_strong};
    border-radius: {m.RADIUS_SMALL}px;
    padding: 5px 9px;
    selection-background-color: {p.accent};
    selection-color: {p.accent_text};
    min-height: {m.CONTROL_HEIGHT - 12}px;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTimeEdit:focus, QPlainTextEdit:focus {{
    border-color: {p.accent};
}}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{
    background: {p.surface_alt}; color: {p.text_faint};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: {m.RADIUS_SMALL}px;
    selection-background-color: {p.accent};
    selection-color: {p.accent_text};
    padding: 4px;
}}
QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; border: none; background: transparent; }}

/* ---------- checkboxes and radios ----------
   Deliberately left to the platform style. Restyling the indicator means
   supplying the tick mark as an image too, and a hand-drawn tick is never
   going to look as right on macOS as the one the system draws -- which also
   follows the user's chosen accent colour and their accessibility settings. */
QCheckBox, QRadioButton {{ spacing: 8px; color: {p.text}; padding: 2px 0; }}
QCheckBox:disabled, QRadioButton:disabled {{ color: {p.text_faint}; }}

/* ---------- tables ---------- */
QTableWidget, QTableView, QTreeWidget {{
    background: {p.surface};
    alternate-background-color: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: {m.RADIUS}px;
    gridline-color: transparent;
    outline: none;
    selection-background-color: {p.sidebar_selected};
    selection-color: {p.text};
}}
QTableWidget::item, QTreeWidget::item {{ padding: 6px 8px; border: none; }}
QTableWidget::item:selected, QTreeWidget::item:selected {{
    background: {p.sidebar_selected}; color: {p.text};
}}
QHeaderView::section {{
    background: {p.surface_alt};
    color: {p.text_muted};
    border: none;
    border-bottom: 1px solid {p.border};
    padding: 7px 8px;
    font-size: 11px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {p.surface_alt}; border: none; }}

/* ---------- progress ---------- */
QProgressBar {{
    background: {p.surface_hover};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 4px; }}
QProgressBar[tone="good"]::chunk   {{ background: {p.good}; }}
QProgressBar[tone="danger"]::chunk {{ background: {p.danger}; }}

/* ---------- scrollbars ---------- */
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {p.border_strong}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.text_faint}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: {p.border_strong}; border-radius: 5px; min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; border: none; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ---------- tabs, groups, menus ---------- */
QTabWidget::pane {{ border: 1px solid {p.border}; border-radius: {m.RADIUS}px; background: {p.surface}; }}
QTabBar::tab {{
    background: transparent; color: {p.text_muted};
    padding: 7px 15px; border: none; border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {p.text}; border-bottom: 2px solid {p.accent}; font-weight: 600; }}
QTabBar::tab:hover {{ color: {p.text}; }}

QGroupBox {{
    border: 1px solid {p.border}; border-radius: {m.RADIUS}px;
    margin-top: 18px; padding: 14px; background: {p.surface};
}}
QGroupBox::title {{
    subcontrol-origin: margin; left: 12px; padding: 0 5px;
    color: {p.text}; font-weight: 600;
}}

QMenu {{
    background: {p.surface}; border: 1px solid {p.border};
    border-radius: {m.RADIUS_SMALL}px; padding: 5px;
}}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 4px; }}
QMenu::item:selected {{ background: {p.accent}; color: {p.accent_text}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 4px 8px; }}

QSplitter::handle {{ background: {p.border}; }}
"""
