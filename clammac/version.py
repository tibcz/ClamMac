"""Single source of truth for the ClamMac version."""

from __future__ import annotations

__all__ = ["APP_ID", "APP_NAME", "COPYRIGHT", "HOMEPAGE", "VERSION", "VERSION_INFO"]

APP_NAME = "ClamMac"
APP_ID = "com.clammac.ClamMac"

VERSION_INFO = (1, 0, 1)
VERSION = ".".join(str(part) for part in VERSION_INFO)

COPYRIGHT = "Copyright (C) 2026 ClamMac contributors"
HOMEPAGE = "https://github.com/tibcz/ClamMac"
