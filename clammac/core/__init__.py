"""Platform and engine services that carry no GUI dependency.

Everything in this package is import-safe without Qt so that it can be unit
tested on any platform, even though most of it only *does* anything on macOS.
"""
