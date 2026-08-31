#!/usr/bin/env python3
"""A stand-in for clamscan, used by the integration tests.

Walks the targets it is given and prints output in exactly the shape the real
scanner produces, so the streaming parser, the progress accounting, and the
detection handling can all be exercised without a 250 MB signature database.

Every format string here was read out of the ClamAV 1.5 binaries rather than
remembered, because the previous version of this file had quietly drifted from
them -- it printed "Data scanned: 12.34 MB", a form ClamAV no longer emits, and
that single stale line was enough to hide a real unit-handling bug in the
summary parser. A test double that has drifted from the thing it doubles is
worse than no double at all: it makes the suite confidently green about
behaviour that does not exist.

Real ClamAV 1.5 prints:

    <path>: OK
    <path>: Empty file
    <path>: Excluded
    <path>: Symbolic link
    <path>: Access denied
    <path>: <Signature> FOUND

and sizes with whichever unit suits the number -- "170 B", "800 KiB",
"6.64 MiB", "3.20 GiB" -- never a bare "MB".

File names drive the behaviour: "infected" is reported as a detection,
"unreadable" as access denied, "empty" as an empty file.
"""
import os
import sys
import time


def format_size(num_bytes: float) -> str:
    """Render a byte count the way ClamAV 1.5 does.

    Matches its own format strings: "%lu B", "%.02f KiB", "%.02f MiB",
    "%.02f GiB" -- binary units, chosen by magnitude.
    """
    if num_bytes < 1024:
        return f"{int(num_bytes)} B"
    for unit, scale in (("KiB", 1024), ("MiB", 1024**2), ("GiB", 1024**3)):
        if num_bytes < scale * 1024 or unit == "GiB":
            return f"{num_bytes / scale:.02f} {unit}"
    return f"{num_bytes} B"


def main() -> int:
    targets = [a for a in sys.argv[1:] if not a.startswith("-")]
    delay = float(os.environ.get("FAKE_CLAMSCAN_DELAY", "0"))
    # Lets a test ask for a specific reported volume, to pin unit handling.
    scanned_bytes = float(os.environ.get("FAKE_CLAMSCAN_BYTES", 12.34 * 1024**2))

    scanned = infected = directories = 0
    started = time.strftime("%Y:%m:%d %H:%M:%S")

    for target in targets:
        if os.path.isfile(target):
            files = [target]
        else:
            files = []
            for root, _dirs, names in os.walk(target):
                directories += 1
                files.extend(os.path.join(root, n) for n in sorted(names))
        for path in files:
            if delay:
                time.sleep(delay)
            name = os.path.basename(path)
            scanned += 1
            if "infected" in name:
                infected += 1
                print(f"{path}: Test.Fake.Signature-1 FOUND", flush=True)
            elif "unreadable" in name:
                print(f"{path}: Access denied", flush=True)
            elif "empty" in name:
                print(f"{path}: Empty file", flush=True)
            else:
                print(f"{path}: OK", flush=True)

    print("", flush=True)
    print("----------- SCAN SUMMARY -----------", flush=True)
    print("Known viruses: 8690123", flush=True)
    print("Engine version: 1.5.4", flush=True)
    print(f"Scanned directories: {directories}", flush=True)
    print(f"Scanned files: {scanned}", flush=True)
    print(f"Infected files: {infected}", flush=True)
    print(f"Data scanned: {format_size(scanned_bytes)}", flush=True)
    print(
        f"Data read: {format_size(scanned_bytes * 0.81)} (ratio 1.23:1)",
        flush=True,
    )
    print("Time: 1.234 sec (0 m 1 s)", flush=True)
    print(f"Start Date: {started}", flush=True)
    print(f"End Date:   {time.strftime('%Y:%m:%d %H:%M:%S')}", flush=True)
    return 1 if infected else 0


if __name__ == "__main__":
    sys.exit(main())
