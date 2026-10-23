# Changelog

All notable changes to ClamMac are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Crash when opening the menu bar menu on macOS 27.** On macOS 27 the system
  can open a menu bar item's menu without a mouse event being current, and Qt's
  tray-icon code (Qt 6.11 and earlier) read the click count of that event
  unconditionally. AppKit raises an exception for that, the exception had
  nowhere to go, and ClamMac aborted with `SIGABRT` in
  `-[NSEvent clickCount]`. Qt 6.12 checks the event first, so ClamMac now
  requires PySide6 6.12 or later. Builds made with older versions are affected;
  rebuild the app to pick up the fix.

## [1.1.0] — 2026-09-02

A second layer. ClamMac's scanner answers "is there something bad on this
disk"; this release adds a screen that answers a different question, and one
that a signature scanner cannot reach: **what is this Mac offering to the
network, and who can get to it.**

The prompt for it is the local AI tooling. Ollama, LM Studio's server mode,
ComfyUI, Gradio web UIs, Jupyter and Ray's dashboard all ship with no
authentication at all, several of them bind every interface by default, and
none of that is a file, so nothing the scanner does will ever notice. The audit
covers those alongside everything else a Mac can leave open.

### Added
- **A network audit, on the new Network screen.** A read-only, point-in-time
  examination of the machine it runs on. It takes a couple of seconds, needs no
  administrator rights, and changes nothing.
  - Every listening TCP and UDP socket, the address it is bound to, the process
    that opened it and the user who owns it — with each one classified as
    reachable from this Mac only, the local network, or every interface.
  - A catalogue of around ninety services, matched by port and by process, so a
    finding reads "Ollama's model API, which has no authentication of any kind"
    rather than "port 11434". Local AI servers, vector and ordinary databases,
    container and orchestration control planes, development servers, the
    classic network services, and the sharing features macOS itself offers.
  - The application firewall: on or off, stealth mode, block-all, logging, and
    whether signed software is admitted without asking. The packet filter too,
    where it can be read.
  - Sharing: Remote Login, Screen Sharing, Remote Management, File Sharing over
    SMB and AFP, Printer Sharing, Media Sharing, AirPlay Receiver, Remote Apple
    Events, Content Caching and Internet Sharing.
  - Tunnelling and remote-control agents — ngrok, Cloudflare Tunnel,
    localtunnel, Tailscale, ZeroTier, TeamViewer, AnyDesk, RustDesk — which
    publish a local service to the internet without opening a single port on an
    external interface, and which a port-based check alone would miss entirely.
  - Addressing: a publicly routable IPv4 address on an interface means no
    router is translating in front of this Mac; globally routable IPv6 means the
    same for every service bound to it.
  - Wi-Fi encryption, with open networks and WEP/TKIP called out.
  - DNS: which resolvers answer, whether they are your gateway or a recognised
    public service, and whether queries are encrypted. `/etc/hosts` overrides
    too — a redirected antivirus or software-update domain is treated as
    serious, because that trick disables protection while every screen still
    says it is on.
  - Proxies, including automatic proxy discovery.
  - The ARP table, flagging one hardware address claiming several IP addresses:
    sometimes a router with several addresses, sometimes ARP spoofing.
  - Established outbound connections, which application owns each, and any
    using a protocol that sends credentials in clear text.
- **A posture score out of 100 and a letter grade**, with severities adjusted
  for the machine's actual situation rather than fixed: the firewall being on
  lowers a finding, blocking all incoming lowers it further, holding a public
  address raises it, and a tunnelling agent gets no firewall discount at all,
  because bypassing the firewall is what it does.
- **Audit reports export as HTML, CSV or JSON.** The HTML is self-contained, on
  the same terms as the scan reports. The JSON carries the raw snapshot as well
  as the findings, so anyone who disagrees with a rule can re-derive their own
  answer from the same observations.
- **Audits are recorded in history**, so the last result and its findings are
  still there after a restart, and the Overview screen carries a network
  exposure tile with the grade and what it means.
- **Settings ▸ Network audit**: run at launch, include established connections,
  check Wi-Fi, and a list of ports to leave out.
- **Tools ▸ Run Network Audit**, on ⌘3.

### What the audit deliberately does not do
- It sends no packet to any other device. The ARP table is read, not built.
  This is an audit of the machine you are sitting at, not a network scanner.
- It looks nothing up on the internet: no reverse DNS, no reputation service,
  no "what is my IP" request.
- It changes no setting. Every command it runs is a query.
- It runs when you ask it to, not continuously.
- Without administrator rights it cannot see sockets opened by other users or
  read the packet filter's rules, and the report says so rather than quietly
  leaving them out.

### Fixed
- **Rows removed from a layout no longer paint over the rows that replace
  them.** `deleteLater()` only schedules a deletion; until the event loop gets
  to it, the old widget goes on drawing where it was. Both places that rebuild
  a list of rows — the new findings list and the Overview screen's recent
  activity — now unparent before deleting. There is a test that reproduces the
  ghosting and fails without the fix.

### Internal
- The audit lives in `clammac/core/network/`, laid out like the rest of the
  core: `probe` talks to the system, `model` describes what came back,
  `catalog` and `checks` decide what it means, `audit` runs it on a thread, and
  `report` writes it out. None of it imports Qt, and the parsers are separated
  from the commands so the entire rule set can be exercised against recorded
  output on any platform.
- `docs/NETWORK-AUDIT.md` documents every check, every command the audit runs,
  and how severity is decided.

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
