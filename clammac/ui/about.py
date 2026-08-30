"""The About box, including the licence statements ClamMac is obliged to show."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..version import APP_NAME, COPYRIGHT, HOMEPAGE, VERSION
from .icons import app_icon_pixmap
from .theme import Metrics
from .widgets.common import button, caption, label, subtitle

__all__ = ["AboutDialog"]

_CLAMMAC_LICENCE = f"""{APP_NAME} {VERSION}
{COPYRIGHT}

{APP_NAME} is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

The full licence text is included in the application bundle as LICENSE.
"""

_INDEPENDENCE = f"""{APP_NAME} is an independent project.

It is not affiliated with, sponsored by, endorsed by, or derived from Cisco
Systems, Inc., the ClamAV project, or any other antivirus product or graphical
front end. No source code, artwork, interface layout, or asset from any other
application was copied or adapted into it. Every line of {APP_NAME}'s source and
every graphical asset it ships was written for this project.

The application icon is generated from geometric primitives at build time. It
contains no third-party artwork and no font outlines.

TRADEMARKS

ClamAV is a registered trademark of Cisco Systems, Inc.
macOS, Mac and Apple are trademarks of Apple Inc.

{APP_NAME} uses these names only to identify the software it works with and the
platform it runs on. All trademarks are the property of their respective owners.
"""

_CLAMAV = f"""THE CLAMAV ENGINE

{APP_NAME} does not include ClamAV. No ClamAV binary, library, or signature
database ships in the {APP_NAME} disk image or application bundle.

{APP_NAME} is a separate program that runs the ClamAV command-line tools as
independent child processes and talks to clamd over its documented local socket.
It does not link against libclamav and does not embed ClamAV source code, so it
is not a derivative work of ClamAV.

On first run, and only after you confirm it, {APP_NAME} downloads the official
macOS installer package published by the ClamAV project over HTTPS, verifies it
against a SHA-256 digest pinned in {APP_NAME}'s source, and unpacks it into its
own folder in your home directory.

ClamAV is distributed by its authors under the GNU General Public License,
version 2. Its complete source code is published by the ClamAV project at
<https://github.com/Cisco-Talos/clamav>. The script
scripts/fetch-clamav-source.sh in {APP_NAME}'s repository downloads the exact
upstream source corresponding to any engine version {APP_NAME} can install.

Virus signature databases are downloaded by freshclam -- a ClamAV program --
directly from the ClamAV project's own mirrors, under whatever terms that
project applies to them. {APP_NAME} only schedules and reports on the process.
"""

_THIRD_PARTY = """COMPONENTS SHIPPED INSIDE THE APPLICATION BUNDLE

Python
    Python Software Foundation License 2.0
    <https://docs.python.org/3/license.html>

PySide6 (Qt for Python)
    GNU Lesser General Public License, version 3
    <https://doc.qt.io/qtforpython/licenses.html>

Qt
    GNU Lesser General Public License, version 3
    <https://www.qt.io/licensing/>

PySide6 and Qt are used under the LGPL-3.0. They are dynamically linked and
shipped as unmodified shared libraries, so you may replace them with your own
build. The procedure required by LGPL-3.0 section 4(d) is documented in
docs/RELINKING.md in the project repository.

Everything else in the bundle -- all Python source, the application icon, and
every other asset -- is original work under ClamMac's own GPL-3.0 licence.
"""

_WARRANTY = """NO WARRANTY

This program is provided without any warranty. See sections 15 and 16 of the
GNU General Public License for the full disclaimer.

Beyond the legal position, it is worth being straight about what this software
can and cannot do.

ClamAV's signature database is good at known malware, including the Windows
malware that Macs pass around without being affected by it, and at the macOS
families that have been catalogued. What neither ClamMac nor ClamAV does is
behavioural detection, exploit mitigation, or reputation scoring. A brand-new
threat with no signature will not be caught until a signature exists for it.

Keep macOS updated, keep FileVault on, and treat ClamMac as one useful layer
rather than the whole defence.
"""


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setModal(True)
        self.resize(660, 560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 20)
        layout.setSpacing(Metrics.GAP)

        header = QHBoxLayout()
        header.setSpacing(18)
        icon = QLabel()
        icon.setPixmap(
            app_icon_pixmap(88).scaled(
                88, 88, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )
        header.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(3)
        text.addWidget(label(APP_NAME, role="title"))
        text.addWidget(subtitle(f"Version {VERSION}"))
        text.addWidget(
            subtitle(
                "A native macOS antivirus application built around the ClamAV "
                "scanning engine."
            )
        )
        text.addWidget(caption(HOMEPAGE))
        text.addStretch(1)
        header.addLayout(text, 1)
        layout.addLayout(header)

        tabs = QTabWidget()
        for name, body in (
            ("Independence", _INDEPENDENCE),
            ("ClamMac licence", _CLAMMAC_LICENCE),
            ("ClamAV", _CLAMAV),
            ("Third-party", _THIRD_PARTY),
            ("Warranty", _WARRANTY),
        ):
            view = QPlainTextEdit(body.strip())
            view.setReadOnly(True)
            tabs.addTab(view, name)
        layout.addWidget(tabs, 1)

        footer = QHBoxLayout()
        footer.addStretch(1)
        footer.addWidget(button("Close", variant="primary", on_click=self.accept))
        layout.addLayout(footer)
