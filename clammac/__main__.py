"""Entry point for ``python -m clammac`` and for the built application.

The import below is deliberately absolute. PyInstaller runs this file as a
top-level script with no parent package, so a relative ``from .app import``
fails twice over: at runtime with "attempted relative import with no known
parent package", and -- more insidiously -- during analysis, where the
unresolved import means the whole dependency tree behind it is never
discovered and Qt is silently left out of the bundle.

An absolute import works in both contexts.
"""

from __future__ import annotations

import sys

from clammac.app import main

if __name__ == "__main__":
    sys.exit(main())
