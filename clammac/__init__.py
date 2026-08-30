"""ClamMac -- a macOS graphical front end for the ClamAV scanning engine.

ClamMac is an independent program. It drives the ClamAV command-line tools as
child processes and speaks to ``clamd`` over its documented local socket; it
does not link against libclamav and is not a derivative work of ClamAV. See
NOTICE.md for the full attribution and trademark statement.
"""

from __future__ import annotations

from .version import APP_ID, APP_NAME, VERSION, VERSION_INFO

__all__ = ["APP_ID", "APP_NAME", "VERSION", "VERSION_INFO"]
