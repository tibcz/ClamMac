# Security

## Reporting a vulnerability in ClamMac

Please report privately rather than opening a public issue: use GitHub's
[private vulnerability reporting](https://github.com/tibcz/ClamMac/security/advisories/new)
on this repository.

Useful things to include: what the issue is, how to reproduce it, what an
attacker gains, and the ClamMac and macOS versions you saw it on.

You will get an acknowledgement within a few days. Fixes are released as soon as
they are ready, and you will be credited unless you prefer otherwise.

## Reporting a vulnerability in ClamAV

ClamMac is a front end. Problems in the scanning engine itself — a crash while
parsing a file, a signature bypass, a bug in `clamd` — belong to the ClamAV
project: <https://github.com/Cisco-Talos/clamav/security/policy>.

If you are not sure which side a problem is on, report it here and it will be
passed along.

## What ClamMac is not

**ClamMac is not a security boundary.** It is a convenience front end for a
signature-matching scanner. It does not sandbox the files it scans, and a bug in
ClamAV's parsers is exploitable through ClamMac exactly as it is through
`clamscan` on the command line. Keep the engine updated.

**A scan is not a guarantee.** ClamAV matches known signatures. It does no
behavioural analysis, no exploit mitigation and no reputation scoring. Something
new enough to have no signature will not be caught.

## How ClamMac tries to be careful

**Engine downloads are verified before they are opened.** The installer package
is checked against a SHA-256 digest pinned in this repository before a single
byte is unpacked, and only HTTPS sources are accepted. A downloaded manifest may
add engine versions but can never redefine the digest of one that shipped with
the application.

**The package is parsed, not executed.** ClamMac reads the installer format
itself rather than running Apple's installer, so the default path needs no
administrator rights and writes nothing outside your home folder. Members that
try to escape the destination directory are refused.

**Quarantine is private and inert.** It lives in a `0700` directory and stored
files are given mode `0000`, so nothing can execute, index or preview them by
accident. On macOS the owner can still change that back — this stops accidents,
not a determined user.

**Detections are handled by ClamMac, not the scanner.** `--remove`, `--move` and
`--copy` are never passed to `clamscan`. A file is only touched after the scan
has reported it, the configured action has been applied, and the result recorded.

**The daemon runs as you.** `clamd` is started as the logged-in user with a
`0600` socket inside ClamMac's support directory. There is no system daemon, no
root, and nothing shared with other accounts.

**Settings and history are not world-readable**, and nothing ClamMac writes is
group- or world-writable.

## What ClamMac sends

Nothing, to us. ClamMac has no telemetry, no analytics, and no update ping of
its own.

It makes exactly two kinds of outbound request, both to the ClamAV project:

- the engine installer package, once, during setup;
- signature database updates, via `freshclam`.

Scan results, file names, file contents and detections stay on your machine.
Nothing is uploaded when a threat is found.

## Supported versions

The latest release gets security fixes. Given the size of the project, older
releases do not — please update.
