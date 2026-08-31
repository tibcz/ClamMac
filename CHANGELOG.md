# Changelog

All notable changes to ClamMac are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/tibcz/ClamMac/releases/tag/v1.0.0
