# Changelog

All notable changes to ClamMac are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-08-31

An audit of the 1.0.0 release turned up two faults that were invisible from
inside the application: it never noticed that definitions had been updated, and
it silently skipped anything you pointed it at through a symlink. Both are
fixed, along with the reason the tests failed to catch either.

### Fixed
- **Definition updates are recognised again, and `clamd` is told to reload.**
  ClamMac's own `freshclam.conf` sets `LogTime yes`, which makes freshclam
  prefix every line with a timestamp. The patterns that read those lines were
  anchored at the start of the message, so none of them ever matched: an update
  that downloaded a fresh database reported itself as "already up to date", no
  update was recorded in history, the notification never fired, and — worst of
  it — `clamd` was never told to reload, so real-time protection kept matching
  against the database it had loaded at startup.
- **Symlinked scan targets are scanned instead of skipped.** The two symlink
  settings mapped "off" to `--follow-*-symlinks=0`, which tells `clamscan` to
  refuse even the path it was given on the command line. Since `/tmp` is a
  symlink on macOS, every quick scan silently omitted it, and any folder or
  file reached through a symlink — chosen, dragged onto the window, or dropped
  on the Dock icon — reported zero files and a clean result. "Off" now maps to
  `1`, which is `clamscan`'s own default: don't wander into symlinks while
  walking, but do scan what you were pointed at.
- **Scan volumes are recorded with their units.** ClamAV prints `170 B`,
  `800 KiB`, `6.64 MiB` or `3.20 GiB` depending on the number; ClamMac read the
  figure and called it megabytes regardless, so the volume stored in history and
  shown in exported reports could be out by a factor of a thousand either way.

### Changed
- **The engine manifest is refreshed when an engine is installed.** The code to
  do this existed but was never called, so a build was pinned for life to the
  ClamAV releases known on the day it shipped. It is best-effort — an
  unreachable manifest is not an error — and it cannot weaken anything: a
  downloaded manifest may only add releases, never redefine a digest that
  shipped with the application. See SECURITY.md for what this means for
  outbound requests.
- **"Play a sound when a threat is found" now plays a sound.** The setting was
  stored and consulted by nothing.
- Three settings that nothing ever read — `only_when_idle`, `start_minimised`
  and `skip_larger_than_mb` — have been removed. Settings files written by
  1.0.0 still load.

### Licensing
- The full text of the LGPL-3.0 and `docs/RELINKING.md` are now copied into the
  application bundle. Qt and PySide6 travel inside it under that licence, which
  asks for both to be supplied with the combined work; previously they existed
  only in the repository, and the About box pointed bundle-only users at a file
  that was not there. The build now fails if either is missing.

### Internal
- A manifest-supplied filename is reduced to a bare name before it is used as a
  path, so a hostile or corrupted manifest cannot steer a download outside
  ClamMac's cache directory.
- `tests/fixtures/fake_clamscan.py` now emits what ClamAV 1.5 actually prints.
  It had drifted to an older format, and that drift is the single reason two of
  the faults above survived a suite that was otherwise green — a test double
  that no longer matches the thing it doubles makes the suite confident about
  behaviour that does not exist.

## [1.0.0] — 2026-08-31

First release.

### Scanning
- Quick scan covering where infections actually arrive: Downloads, Desktop,
  mail attachments, user launch agents and `/tmp`
- Full scan, or any file or folder you choose
- Drag and drop onto the window or the Dock icon
- Live progress driven by the scanner's own per-file output, so the file named
  on screen is the one being worked on
- Pause, resume and stop, holding position rather than starting over
- Runs at low priority by default so a full scan does not make the Mac unusable

### Real-time protection
- Watches Downloads, Desktop, removable volumes and any folder you add
- Waits for files to stop changing before scanning, so downloads in progress are
  not scanned half-written
- Backed by a private `clamd` running as the logged-in user

### Quarantine
- Detections are moved, not deleted, and stay recoverable
- Stored with no permissions in a private folder, and enough metadata to be put
  back exactly where they came from
- Restore never overwrites a file that has since taken the name

### Definitions
- Automatic updates on a schedule, plus update-on-launch
- Live progress and a plain statement of what changed
- Clear warning when the databases get stale

### Scheduling
- Unattended scans hourly, daily, weekly or monthly
- Registered with launchd, so a scan runs whether or not ClamMac is open

### History and reporting
- Every scan and detection recorded in SQLite
- Export as self-contained HTML, CSV or JSON

### Interface
- Eight screens behind a sidebar, with an overview whose primary button always
  does the most useful next thing
- Light, dark, or follow-the-system appearance
- Menu bar item with status and one-click quick scan
- Native macOS notifications
- Built-in EICAR self-test

### Setup
- Downloads the official ClamAV package, verifies it against a pinned SHA-256,
  and unpacks it into ClamMac's own folder — **without asking for a password**
- Uses an existing Homebrew, MacPorts or system ClamAV when it finds one
- Falls back to an administrator-authorised system install only if the private
  install fails its own verification

[1.0.1]: https://github.com/tibcz/ClamMac/releases/tag/v1.0.1
[1.0.0]: https://github.com/tibcz/ClamMac/releases/tag/v1.0.0
