#!/usr/bin/env python3
"""A stand-in for clamscan, used by the integration tests.

Walks the targets it is given and prints output in exactly the shape the real
scanner produces, so the streaming parser, the progress accounting, and the
detection handling can all be exercised without a 250 MB signature database.

Any file whose name contains "infected" is reported as a detection.
"""
import os
import sys
import time

def main() -> int:
    targets = [a for a in sys.argv[1:] if not a.startswith("-")]
    delay = float(os.environ.get("FAKE_CLAMSCAN_DELAY", "0"))
    scanned = infected = directories = 0

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
            scanned += 1
            if "infected" in os.path.basename(path):
                infected += 1
                print(f"{path}: Test.Fake.Signature-1 FOUND", flush=True)
            elif "unreadable" in os.path.basename(path):
                print(f"{path}: Access denied.", flush=True)
            else:
                print(f"{path}: OK", flush=True)

    print("", flush=True)
    print("----------- SCAN SUMMARY -----------", flush=True)
    print("Known viruses: 8690123", flush=True)
    print("Engine version: 1.5.4", flush=True)
    print(f"Scanned directories: {directories}", flush=True)
    print(f"Scanned files: {scanned}", flush=True)
    print(f"Infected files: {infected}", flush=True)
    print("Data scanned: 12.34 MB", flush=True)
    print("Data read: 10.00 MB (ratio 1.23:1)", flush=True)
    print("Time: 1.234 sec (0 m 1 s)", flush=True)
    return 1 if infected else 0

if __name__ == "__main__":
    sys.exit(main())
