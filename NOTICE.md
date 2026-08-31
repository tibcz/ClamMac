# ClamMac — Notices and Attributions

## Independence

ClamMac is an **independent, original work**. It is not affiliated with,
sponsored by, endorsed by, or derived from Cisco Systems, Inc., the ClamAV
project, or any other antivirus product, graphical front end, or vendor.

No source code, artwork, user-interface layout, icon, string, or asset from any
other antivirus application or ClamAV front end was copied, adapted, decompiled,
or otherwise incorporated into this project. Every line of ClamMac's source and
every graphical asset it ships was authored for this project.

The name "ClamMac" was chosen to describe what the program is — a macOS front
end for the ClamAV scanning engine. It is not intended to suggest any
relationship with, or origin from, another product, and is not presented as
being produced or approved by any third party.

## Trademarks

**ClamAV** is a registered trademark of **Cisco Systems, Inc.**

**macOS**, **Mac**, and **Apple** are trademarks of **Apple Inc.**

ClamMac uses these names only nominatively — that is, only to identify and
describe the software ClamMac interoperates with and the platform it runs on, as
is necessary to describe the program accurately. ClamMac makes no claim of
ownership over these marks, does not use them in its logo or icon, and does not
imply sponsorship or affiliation. All trademarks are the property of their
respective owners.

## The ClamAV engine

ClamMac is a *separate program* that drives the ClamAV command-line tools
(`clamscan`, `clamdscan`, `clamd`, `freshclam`, `sigtool`, `clamconf`) as
independent child processes, and speaks to `clamd` over its documented local
socket protocol. It does not link against `libclamav`, does not embed ClamAV
source code, and is not a derivative work of ClamAV. The two programs
communicate only at arm's length, through command-line arguments, exit codes,
standard output, and a documented socket protocol.

**ClamMac does not redistribute ClamAV.** No ClamAV binary, library, or virus
signature database is included in the ClamMac disk image or application bundle.

Instead, when you first run ClamMac, it offers to fetch the official
`clamav-<version>.macos.universal.pkg` package published by the ClamAV project
on its own release channel, over HTTPS, and verifies the download against a
SHA-256 digest pinned in this repository before using it. The download happens
only after you explicitly confirm it, and you may instead point ClamMac at a
copy of ClamAV you installed yourself (via Homebrew, MacPorts, the official
installer package, or a build from source).

ClamAV is distributed by its authors under the **GNU General Public License,
version 2**. Its source code is published by the ClamAV project. ClamMac
displays the ClamAV licence and a link to its source from **ClamMac ▸ About ▸
Open Source Licences**, and `scripts/fetch-clamav-source.sh` in this repository
will download the exact upstream source tarball corresponding to any pinned
engine version.

Because ClamMac neither includes nor conveys ClamAV, ClamMac's own licence does
not extend to it, and ClamAV's licence does not extend to ClamMac. They are
separate works that happen to cooperate on your machine — the same relationship
a terminal emulator has with the commands you type into it.

## Virus signature databases

ClamMac does not distribute virus signature databases. Signatures are downloaded
by `freshclam` — a ClamAV program — directly from the ClamAV project's own
mirrors, under whatever terms the ClamAV project applies to them. ClamMac only
schedules and reports on that process.

## ClamMac's own licence

ClamMac is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License, version 3 or (at your option) any
later version**. See [`LICENSE`](LICENSE) for the full text.

    ClamMac — a macOS graphical front end for the ClamAV scanning engine
    Copyright (C) 2026 ClamMac contributors

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along
    with this program. If not, see <https://www.gnu.org/licenses/>.

## Third-party components ClamMac does ship

| Component | Licence | How it is used |
|---|---|---|
| [Python](https://www.python.org/) | PSF License 2.0 | Interpreter embedded in the application bundle |
| [PySide6 / Qt for Python](https://doc.qt.io/qtforpython/) | LGPL-3.0 | Graphical toolkit, dynamically linked and replaceable |
| [Qt](https://www.qt.io/) | LGPL-3.0 | Underlying widget toolkit, dynamically linked and replaceable |

PySide6 and Qt are used under the LGPL-3.0. They are dynamically linked and
shipped as unmodified shared libraries inside the application bundle, so you may
replace them with your own build: see [`docs/RELINKING.md`](docs/RELINKING.md)
for the procedure required by LGPL-3.0 §4(d).

The full text of the LGPL-3.0 — which incorporates the GNU GPL v3 it is built
on — is in [`LICENSES/LGPL-3.0.txt`](LICENSES/LGPL-3.0.txt). Both that file and
`docs/RELINKING.md` are copied into the application bundle, so everything
LGPL-3.0 §4(b) and §4(d) ask to be supplied with the combined work travels with
it rather than only living in this repository.

Everything else in the application bundle — all Python source, the application
icon, and every other asset — is original work covered by ClamMac's own GPL-3.0
licence.

## Icon and artwork

The ClamMac application icon is generated procedurally by
[`packaging/make_icon.py`](packaging/make_icon.py) from geometric primitives
written for this project. It contains no traced, copied, or derived artwork, no
third-party icon set, and no font glyph outlines. It deliberately does not
resemble the branding of ClamAV or of any other antivirus product.

## No warranty

ClamMac is provided without any warranty. It is a convenience front end for a
third-party scanning engine, and neither ClamMac nor ClamAV can be relied upon
as a complete defence against malicious software. See sections 15 and 16 of the
GNU General Public License for the full disclaimer.
