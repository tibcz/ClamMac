"""Exporting what ClamMac found, in formats other tools can read.

HTML for a person to read or print, CSV for a spreadsheet, JSON for anything
that needs to consume it programmatically. The HTML report is self-contained --
no external stylesheet, no fonts, no scripts -- so it survives being emailed,
archived, or opened years later on a machine with no network.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .history import DetectionRecord, ScanRecord
from ..version import APP_NAME, HOMEPAGE, VERSION

__all__ = ["to_json", "to_csv", "to_html", "write_report", "FORMATS"]

FORMATS = {"html": "Web page (.html)", "csv": "Spreadsheet (.csv)", "json": "JSON (.json)"}


def _stamp(value: str) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    return parsed.astimezone().strftime("%d %b %Y, %H:%M:%S")


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def to_json(scans: list[ScanRecord], detections: list[DetectionRecord]) -> str:
    payload = {
        "generator": {"name": APP_NAME, "version": VERSION, "homepage": HOMEPAGE},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scans": [asdict(s) for s in scans],
        "detections": [asdict(d) for d in detections],
    }
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------


def to_csv(scans: list[ScanRecord], detections: list[DetectionRecord]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(["Scans"])
    writer.writerow(
        ["Scan ID", "Type", "Targets", "Started", "Finished", "Result",
         "Files scanned", "Threats", "Errors", "Duration (s)", "Engine", "Definitions"]
    )
    for scan in scans:
        writer.writerow(
            [scan.id, scan.kind, " | ".join(scan.targets), scan.started_at, scan.finished_at,
             scan.state, scan.scanned, scan.infected, scan.errors, round(scan.duration, 2),
             scan.engine_version, scan.database_version]
        )

    writer.writerow([])
    writer.writerow(["Detections"])
    writer.writerow(["Detected", "Threat", "File", "Action taken", "Scan ID"])
    for item in detections:
        writer.writerow([item.detected_at, item.signature, item.path, item.action, item.scan_id])

    return buffer.getvalue()


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0; padding: 40px 28px 72px; background: #f6f7f9; color: #16181d;
}
main { max-width: 980px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 17px; margin: 36px 0 12px; letter-spacing: -0.01em; }
.sub { color: #6a7280; margin: 0 0 28px; font-size: 13px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 600; letter-spacing: -0.02em; }
.card .l { font-size: 12px; color: #6a7280; text-transform: uppercase; letter-spacing: .05em; }
.card.bad .n { color: #c0392b; }
.card.good .n { color: #1e8449; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #e3e6ea; border-radius: 10px; overflow: hidden; font-size: 13px; }
th { text-align: left; background: #f0f2f5; font-weight: 600; font-size: 11px;
     text-transform: uppercase; letter-spacing: .05em; color: #55606e; }
th, td { padding: 9px 12px; border-bottom: 1px solid #edeff2; }
tr:last-child td { border-bottom: 0; }
td.path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
          word-break: break-all; }
.sig { color: #c0392b; font-weight: 600; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px;
        font-weight: 600; background: #e8eaed; color: #444; }
.pill.clean { background: #e4f4ea; color: #1e8449; }
.pill.threat { background: #fbe6e3; color: #c0392b; }
.empty { background: #fff; border: 1px dashed #d5d9df; border-radius: 10px;
         padding: 28px; text-align: center; color: #6a7280; }
footer { margin-top: 44px; padding-top: 16px; border-top: 1px solid #e3e6ea;
         color: #8a929c; font-size: 12px; }
a { color: #2f6fd0; }
@media (prefers-color-scheme: dark) {
  body { background: #16181d; color: #e6e8ec; }
  .card, table, .empty { background: #1e2128; border-color: #2c313a; }
  th { background: #23272f; color: #98a2b0; }
  th, td { border-color: #2a2e37; }
  .sub, .card .l, footer { color: #8b95a3; }
  .pill { background: #2c313a; color: #c3c9d3; }
  .pill.clean { background: #16351f; color: #6ede9a; }
  .pill.threat { background: #3a1c19; color: #ff9b8f; }
  .sig { color: #ff9b8f; }
  .empty { border-color: #333944; }
  a { color: #6fa8ff; }
}
@media print { body { background: #fff; padding: 0; } .card, table { border-color: #ccc; } }
"""


def to_html(scans: list[ScanRecord], detections: list[DetectionRecord], *, title: str = "") -> str:
    """A self-contained HTML report."""
    e = html.escape
    heading = e(title or f"{APP_NAME} scan report")
    generated = datetime.now().strftime("%d %B %Y at %H:%M")

    files = sum(s.scanned for s in scans)
    threats = len(detections)
    seconds = sum(s.duration for s in scans)

    cards = f"""
    <div class="cards">
      <div class="card"><div class="n">{len(scans):,}</div><div class="l">Scans</div></div>
      <div class="card"><div class="n">{files:,}</div><div class="l">Files scanned</div></div>
      <div class="card {'bad' if threats else 'good'}">
        <div class="n">{threats:,}</div><div class="l">Threats found</div></div>
      <div class="card"><div class="n">{_duration(seconds)}</div><div class="l">Total time</div></div>
    </div>"""

    if detections:
        rows = "\n".join(
            f"<tr><td>{e(_stamp(d.detected_at))}</td>"
            f"<td class='sig'>{e(d.signature)}</td>"
            f"<td class='path'>{e(d.path)}</td>"
            f"<td><span class='pill'>{e(d.action)}</span></td></tr>"
            for d in detections
        )
        threat_section = (
            "<table><thead><tr><th>Detected</th><th>Threat</th><th>File</th>"
            f"<th>Action</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        threat_section = "<div class='empty'>No threats were found.</div>"

    if scans:
        scan_rows = "\n".join(
            f"<tr><td>{e(_stamp(s.started_at))}</td>"
            f"<td>{e(s.kind.title())}</td>"
            f"<td class='path'>{e(s.target_summary)}</td>"
            f"<td>{s.scanned:,}</td>"
            f"<td><span class='pill {'clean' if s.clean else 'threat'}'>"
            f"{'Clean' if s.clean else f'{s.infected} found'}</span></td>"
            f"<td>{_duration(s.duration)}</td></tr>"
            for s in scans
        )
        scan_section = (
            "<table><thead><tr><th>Started</th><th>Type</th><th>Target</th>"
            f"<th>Files</th><th>Result</th><th>Duration</th></tr></thead>"
            f"<tbody>{scan_rows}</tbody></table>"
        )
    else:
        scan_section = "<div class='empty'>No scans recorded.</div>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{heading}</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
  <h1>{heading}</h1>
  <p class="sub">Generated {e(generated)} by {e(APP_NAME)} {e(VERSION)}</p>
  {cards}
  <h2>Threats</h2>
  {threat_section}
  <h2>Scans</h2>
  {scan_section}
  <footer>
    Produced by <a href="{e(HOMEPAGE)}">{e(APP_NAME)}</a>, an independent graphical
    front end for the ClamAV scanning engine. ClamAV is a registered trademark of
    Cisco Systems, Inc. ClamMac is not affiliated with or endorsed by Cisco Systems, Inc.
  </footer>
</main>
</body>
</html>
"""


def write_report(
    destination: Path,
    scans: list[ScanRecord],
    detections: list[DetectionRecord],
    *,
    fmt: str = "html",
    title: str = "",
) -> Path:
    """Render a report and write it to ``destination``."""
    fmt = fmt.lower().lstrip(".")
    if fmt == "json":
        body = to_json(scans, detections)
    elif fmt == "csv":
        body = to_csv(scans, detections)
    elif fmt == "html":
        body = to_html(scans, detections, title=title)
    else:
        raise ValueError(f"unsupported report format: {fmt}")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body, encoding="utf-8")
    return destination
