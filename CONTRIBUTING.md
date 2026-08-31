# Contributing to ClamMac

Bug reports, fixes and improvements are all welcome.

## Before you start

Read [NOTICE.md](NOTICE.md). ClamMac deliberately keeps its distance from other
projects: it is original work, it does not redistribute ClamAV, and it does not
claim any relationship with Cisco Systems, Inc. Contributions must keep it that
way.

**Do not contribute code, artwork, strings, or interface layouts copied or
adapted from another antivirus product or ClamAV front end**, whatever its
licence. Even where a licence would permit it, ClamMac's independence is the
point. Write it, or don't send it.

By contributing you agree your work is licensed under the GPL-3.0-or-later, the
same as the rest of the project, and that it is yours to license.

## Getting set up

```sh
git clone https://github.com/tibcz/ClamMac.git
cd ClamMac
make venv
make check      # lint and test
make run
```

You do not need macOS to work on most of this. The core package has no Qt
dependency and the interface tests run headless with `QT_QPA_PLATFORM=offscreen`.
Only building the `.app` needs a Mac.

## How the code is arranged

```
clammac/core/     everything that works without Qt
clammac/ui/       PySide6: the window, its pages, and the theme
packaging/        icon, PyInstaller spec, DMG builder
scripts/          engine manifest verification, ClamAV source fetch
tests/            pytest; fixtures build synthetic Mach-O and .pkg files
```

Two rules hold this together:

1. **`core/` never imports Qt.** A scheduled scan fired by launchd has no GUI,
   and it runs the same code as the window does. Keeping the boundary also
   means the interesting logic is testable without starting Qt.

2. **Worker threads never touch widgets.** Scans, updates and the folder watcher
   all run on background threads and report through plain callbacks. The
   interface converts those to Qt signals in `ui/bridge.py`, which delivers them
   on the interface thread. If you find yourself calling a widget method from a
   thread, add a signal instead.

## Changes worth extra care

**Anything that deletes or moves a user's files.** Quarantine and delete are the
two places ClamMac can destroy something irreplaceable. A false positive on the
only copy of somebody's work is the worst thing this program can do. Default to
reversible, confirm before destructive, and record what happened.

**The engine provisioner.** It downloads and executes third-party code. The
SHA-256 check against the pinned manifest is not optional and must happen before
anything is unpacked. If you add an engine version, run
`python3 scripts/verify-manifest.py --version <v>`.

**Layouts.** ClamMac's pages do not scroll sideways, so content wider than the
window is silently clipped rather than reachable. Long labels must wrap, and
tables must not size themselves to their contents. `tests/test_interface.py`
checks this at the minimum supported window width — if it fails, that is a real
bug and not a fussy test.

## Sending a change

1. Branch from `main`.
2. Make the change, with a test that fails without it.
3. `make check` — lint and the full suite must pass.
4. Write a commit message that explains *why*. The diff already says what.
5. Open a pull request describing the problem, the approach, and how you
   checked it works.

## Reporting a bug

Include the ClamMac version (**ClamMac ▸ Settings ▸ About**), your macOS
version and whether the Mac is Apple silicon or Intel, what you did and what
happened, and anything relevant from **Settings ▸ Open log folder**.

Please redact anything private from log excerpts — paths can be revealing.

For a security problem in ClamMac itself, see [SECURITY.md](SECURITY.md)
instead; don't open a public issue.
