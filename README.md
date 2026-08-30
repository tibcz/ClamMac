# ClamMac

A native macOS antivirus application built around the ClamAV scanning engine.

ClamMac gives ClamAV the things a command-line scanner does not have on its
own: a real interface, always-on folder monitoring, a safe quarantine, unattended
scheduled scans, automatic signature updates, and a readable history of what was
scanned and what was found.

> **ClamMac is an independent project.** It is not affiliated with, endorsed by,
> or derived from Cisco Systems, Inc., the ClamAV project, or any other
> antivirus product. ClamAV® is a registered trademark of Cisco Systems, Inc.
> See [NOTICE.md](NOTICE.md).

---

## Install

1. Download `ClamMac-<version>.dmg` from the
   [Releases page](https://github.com/tibcz/ClamMac/releases).
2. Open the disk image and drag **ClamMac** into **Applications**.
3. Launch it. A setup assistant fetches the ClamAV engine and the current virus
   definitions for you.

### First launch: "ClamMac cannot be opened"

ClamMac's releases are **not signed with an Apple Developer ID**, because the
project has no paid Apple developer account. macOS therefore refuses to open it
on the first attempt. This is Gatekeeper's default treatment of *every*
unsigned app, not a statement about this one.

To open it the first time:

- **Right-click** (or Control-click) the ClamMac icon in Applications, choose
  **Open**, then click **Open** in the dialog; **or**
- open it once normally, then go to **System Settings ▸ Privacy & Security**,
  scroll to the Security section, and click **Open Anyway**.

You only have to do this once. Afterwards ClamMac opens by double-clicking like
anything else.

If you would rather not take that on trust, build it yourself — `make dmg`
produces the same application from the source in this repository.

## The engine, and why there is a setup step

ClamMac does not bundle ClamAV. On first run it offers to download the official
`clamav-<version>.macos.universal.pkg` published by the ClamAV project, checks
it against a SHA-256 digest pinned in
[`clammac/resources/engine_manifest.json`](clammac/resources/engine_manifest.json),
and unpacks it into `~/Library/Application Support/ClamMac/Engine`.

**This does not ask for your password.** ClamMac reads the installer package
itself rather than running it, and adapts the unpacked binaries to their new
location, so the engine lives entirely inside your home folder. Nothing is
written to `/usr/local`, `/Library`, or anywhere else outside it.

If you already have ClamAV — from Homebrew, MacPorts, the official installer, or
a build of your own — ClamMac finds and uses it instead, and downloads nothing.

Signature databases are downloaded separately by `freshclam`, straight from the
ClamAV project's mirrors.

## What it does

**Scanning**
- Quick scan of the places infections actually arrive: Downloads, Desktop, mail
  attachments, user launch agents, `/tmp`
- Full scan, or any folder or file you choose
- Drag anything onto the window, or onto the Dock icon, to scan it
- Live progress with the current file, counts, and rate
- Pause, resume, and stop
- Runs at low priority by default, so a full scan does not make the machine
  unusable

**Real-time protection**
- Watches Downloads, Desktop, removable volumes, and anything else you add
- Scans files as they land, after they stop changing
- Optional per-file size ceiling so large downloads do not stall the queue

**Quarantine**
- Infected files are moved into a private store, stripped of execute
  permission, and recorded with where they came from
- Restore or delete, one at a time or in bulk
- Nothing is ever deleted without asking, unless you turn that on yourself

**Definitions**
- Automatic updates on your schedule, plus update-on-launch
- Clear staleness warning when the databases get old
- Manual update whenever you want one

**Scheduling**
- Unattended scans hourly, daily, weekly, or monthly, at a time you pick
- Runs through a LaunchAgent, so it fires whether or not ClamMac is open

**History and reporting**
- Every scan recorded with its duration, coverage, and findings
- Full detection history, searchable
- Export any scan, or the whole history, as HTML, CSV, or JSON

**Elsewhere**
- Menu bar item with protection status and one-click quick scan
- Native macOS notifications
- Light, dark, or follow-the-system appearance
- Built-in EICAR self-test, so you can confirm detection actually works
- Exclusions by path, by extension, or by size

## Requirements

- macOS 11 Big Sur or later
- Apple silicon or Intel (the application and the engine are both universal)
- About 400 MB of disk: ~90 MB engine, ~250 MB signature databases
- An internet connection for the initial setup and for updates

## Building from source

```sh
git clone https://github.com/tibcz/ClamMac.git
cd ClamMac
make venv          # create a virtualenv and install dependencies
make run           # run from source
make test          # run the test suite
make dmg           # build ClamMac.dmg into dist/
```

`make dmg` needs macOS. Everything else, including the tests, runs anywhere.

To sign the build with your own Apple Developer ID, set `CODESIGN_IDENTITY`
before building; to notarise it as well, also set `NOTARY_PROFILE`. Both are
optional and neither is stored in the repository. See
[`docs/BUILDING.md`](docs/BUILDING.md).

## Is this a replacement for a commercial antivirus?

Partly, and it is worth being straight about where the line is.

ClamAV's signature database is genuinely good at known malware, including the
Windows malware that Macs pass around without being affected by it, and at the
macOS families that have been catalogued. ClamMac makes that easy to run
continuously instead of by hand.

What neither ClamMac nor ClamAV does is behavioural detection, exploit
mitigation, or reputation scoring. A brand-new threat with no signature will not
be caught until a signature exists for it. Keep macOS updated, keep FileVault
on, and treat ClamMac as one useful layer rather than the whole defence.

## Contributing

Bug reports and pull requests are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue in ClamMac
itself, see [SECURITY.md](SECURITY.md).

## Licence

ClamMac is free software under the **GNU General Public License, version 3 or
later**. See [LICENSE](LICENSE) for the terms and [NOTICE.md](NOTICE.md) for
attributions and trademark information.
