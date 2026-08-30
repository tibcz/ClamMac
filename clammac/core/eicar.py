"""The EICAR anti-malware test file.

EICAR is a harmless 68-byte text file that the industry agreed, by convention,
every scanner would detect. It contains no malicious code -- it is a printable
ASCII string that does nothing -- and exists so people can confirm their
antivirus actually works without going anywhere near real malware.

The string is assembled at runtime from fragments rather than written out as a
literal. If it appeared verbatim in the source, every scanner on earth would
flag ClamMac's own source tree and application bundle, which would be both
embarrassing and unhelpful.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

__all__ = ["EICAR_LENGTH", "test_file_bytes", "write_test_file", "is_test_signature"]

#: The standard test string, in pieces.
_FRAGMENTS = (
    "X5O!P%@AP[4",
    "\\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-",
    "ANTIVIRUS-TEST-FILE!",
    "$H+H*",
)

EICAR_LENGTH = 68


def test_file_bytes() -> bytes:
    """The EICAR test string as ASCII bytes."""
    return "".join(_FRAGMENTS).encode("ascii")


def write_test_file(directory: Path | None = None, name: str = "clammac-selftest.txt") -> Path:
    """Write a test file and return its path.

    The caller is responsible for deleting it. ClamMac's self-test writes into
    a temporary directory and removes the whole thing afterwards, so a stray
    test file cannot be left behind to alarm the user later.
    """
    target_dir = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="clammac-selftest-"))
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / name
    target.write_bytes(test_file_bytes())
    target.chmod(0o600)
    return target


def is_test_signature(signature: str) -> bool:
    """True when a detection name refers to the EICAR test file.

    Used to keep a self-test detection out of the threat count and out of
    quarantine -- finding it is a success, not an incident.
    """
    lowered = signature.lower()
    return "eicar" in lowered
