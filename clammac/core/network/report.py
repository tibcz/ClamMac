"""Exporting an audit: a page to read, a spreadsheet to sort, JSON to consume.

Same rules as the scan reports. The HTML is entirely self-contained -- no
stylesheet, no font, no script, nothing fetched -- so it can be attached to a
ticket, archived, or opened in five years on a machine with no network.

The JSON export deliberately includes the raw snapshot as well as the
findings, so anyone who disagrees with a rule can re-derive their own answer
from the same observations.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ...version import APP_NAME, HOMEPAGE, VERSION
from .model import AuditReport, Severity

__all__ = ["FORMATS", "to_csv", "to_html", "to_json", "write_report"]

FORMATS = {"html": "Web page (.html)", "csv": "Spreadsheet (.csv)", "json": "JSON (.json)"}


def _stamp(value: str) -> str:
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    return parsed.astimezone().strftime("%d %b %Y, %H:%M:%S")


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def to_json(report: AuditReport) -> str:
    snapshot = asdict(report.snapshot)
    snapshot["listeners"] = [
        {**asdict(listener), "scope": listener.scope.value, "exposed": listener.exposed}
        for listener in report.snapshot.listeners
    ]
    payload = {
        "generator": {"name": APP_NAME, "version": VERSION, "homepage": HOMEPAGE},
        "audit": {
            "id": report.audit_id,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "duration_seconds": round(report.duration, 3),
            "score": report.score,
            "grade": report.grade,
            "headline": report.headline,
            "counts": {severity.value: count for severity, count in report.counts.items()},
        },
        "findings": [
            {
                "id": finding.check_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "category": finding.category.value,
                "summary": finding.summary,
                "recommendation": finding.recommendation,
                "evidence": list(finding.evidence),
                "reference": finding.reference,
            }
            for finding in report.ordered
        ],
        "snapshot": snapshot,
    }
    return json.dumps(payload, indent=2, default=str)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------


def to_csv(report: AuditReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(["Audit"])
    writer.writerow(["ID", "Started", "Finished", "Score", "Grade", "Host", "Platform"])
    writer.writerow(
        [
            report.audit_id,
            report.started_at,
            report.finished_at,
            report.score,
            report.grade,
            report.snapshot.hostname,
            report.snapshot.platform,
        ]
    )

    writer.writerow([])
    writer.writerow(["Findings"])
    writer.writerow(
        ["Check", "Severity", "Category", "Title", "Summary", "Recommendation", "Evidence"]
    )
    for finding in report.ordered:
        writer.writerow(
            [
                finding.check_id,
                finding.severity.value,
                finding.category.value,
                finding.title,
                finding.summary,
                finding.recommendation,
                " | ".join(finding.evidence),
            ]
        )

    writer.writerow([])
    writer.writerow(["Listening ports"])
    writer.writerow(["Protocol", "Address", "Port", "Reachable from", "Process", "PID", "User"])
    for listener in report.snapshot.listeners:
        writer.writerow(
            [
                listener.protocol,
                listener.address,
                listener.port,
                listener.scope.label,
                listener.process,
                listener.pid,
                listener.user,
            ]
        )

    writer.writerow([])
    writer.writerow(["Established connections"])
    writer.writerow(["Protocol", "Process", "PID", "Local", "Remote", "State", "Scope"])
    for connection in report.snapshot.connections:
        writer.writerow(
            [
                connection.protocol,
                connection.process,
                connection.pid,
                f"{connection.local_address}:{connection.local_port}",
                connection.remote_endpoint,
                connection.state,
                "external" if connection.remote_is_public else "local",
            ]
        )

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
main { max-width: 1000px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 17px; margin: 36px 0 12px; letter-spacing: -0.01em; }
.sub { color: #6a7280; margin: 0 0 28px; font-size: 13px; }
.score { display: flex; align-items: center; gap: 20px; background: #fff;
         border: 1px solid #e3e6ea; border-radius: 12px; padding: 20px 24px; }
.score .g { font-size: 46px; font-weight: 650; letter-spacing: -0.03em; line-height: 1; }
.score .t { font-size: 19px; font-weight: 600; margin-bottom: 2px; }
.score .d { color: #6a7280; font-size: 13px; }
.g.a, .g.b { color: #1e8449; }
.g.c { color: #b8710f; }
.g.d, .g.f { color: #c0392b; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
         gap: 12px; margin-top: 12px; }
.card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 24px; font-weight: 600; letter-spacing: -0.02em; }
.card .l { font-size: 11px; color: #6a7280; text-transform: uppercase; letter-spacing: .05em; }
.finding { background: #fff; border: 1px solid #e3e6ea; border-left-width: 4px;
           border-radius: 10px; padding: 16px 18px; margin-bottom: 12px; }
.finding h3 { margin: 0 0 6px; font-size: 15px; }
.finding p { margin: 0 0 8px; font-size: 13.5px; }
.finding .rec { color: #2f6fd0; font-size: 13.5px; }
.finding .ref { color: #8a929c; font-size: 11.5px; margin-top: 8px; }
.finding.critical { border-left-color: #c0392b; }
.finding.high { border-left-color: #d9534f; }
.finding.medium { border-left-color: #b8710f; }
.finding.low { border-left-color: #7a8494; }
.finding.info { border-left-color: #2f6fd0; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px;
        font-weight: 600; background: #e8eaed; color: #444; vertical-align: 2px; }
.pill.critical, .pill.high { background: #fbe6e3; color: #c0392b; }
.pill.medium { background: #fdf1df; color: #8a5a08; }
.pill.info, .pill.low { background: #e8eaed; color: #55606e; }
.pill.open { background: #fbe6e3; color: #c0392b; }
.pill.localonly { background: #e4f4ea; color: #1e8449; }
ul.ev { margin: 6px 0 0; padding-left: 18px; }
ul.ev li { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
           color: #55606e; word-break: break-all; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #e3e6ea; border-radius: 10px; overflow: hidden; font-size: 13px; }
th { text-align: left; background: #f0f2f5; font-weight: 600; font-size: 11px;
     text-transform: uppercase; letter-spacing: .05em; color: #55606e; }
th, td { padding: 9px 12px; border-bottom: 1px solid #edeff2; }
tr:last-child td { border-bottom: 0; }
td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
          word-break: break-all; }
.empty { background: #fff; border: 1px dashed #d5d9df; border-radius: 10px;
         padding: 28px; text-align: center; color: #6a7280; }
footer { margin-top: 44px; padding-top: 16px; border-top: 1px solid #e3e6ea;
         color: #8a929c; font-size: 12px; }
a { color: #2f6fd0; }
@media (prefers-color-scheme: dark) {
  body { background: #16181d; color: #e6e8ec; }
  .card, table, .empty, .finding, .score { background: #1e2128; border-color: #2c313a; }
  th { background: #23272f; color: #98a2b0; }
  th, td { border-color: #2a2e37; }
  .sub, .card .l, footer, .score .d, ul.ev li { color: #8b95a3; }
  .pill { background: #2c313a; color: #c3c9d3; }
  .pill.critical, .pill.high, .pill.open { background: #3a1c19; color: #ff9b8f; }
  .pill.medium { background: #33270f; color: #e5a73c; }
  .pill.localonly { background: #16351f; color: #6ede9a; }
  .g.a, .g.b { color: #3ecf7e; }
  .g.c { color: #e5a73c; }
  .g.d, .g.f { color: #ff9b8f; }
  a, .finding .rec { color: #6fa8ff; }
}
@media print { body { background: #fff; padding: 0; } .card, table, .finding { border-color: #ccc; } }
"""


def to_html(report: AuditReport, *, title: str = "") -> str:
    """A self-contained HTML network audit report."""
    e = html.escape
    heading = e(title or f"{APP_NAME} network audit")
    generated = datetime.now().strftime("%d %B %Y at %H:%M")
    snapshot = report.snapshot
    counts = report.counts

    exposed = snapshot.exposed_listeners
    score_block = f"""
    <div class="score">
      <div class="g {report.grade.lower()}">{report.grade}</div>
      <div>
        <div class="t">{e(report.headline)}</div>
        <div class="d">Posture score {report.score} of 100 &middot;
          {e(snapshot.hostname)} &middot; {e(snapshot.platform)} &middot;
          audited {e(_stamp(report.started_at))}</div>
      </div>
    </div>
    <div class="cards">
      <div class="card"><div class="n">{len(exposed)}</div>
        <div class="l">Reachable services</div></div>
      <div class="card"><div class="n">{len(snapshot.listeners)}</div>
        <div class="l">Listening ports</div></div>
      <div class="card"><div class="n">{counts[Severity.CRITICAL] + counts[Severity.HIGH]}</div>
        <div class="l">Serious findings</div></div>
      <div class="card"><div class="n">{len(snapshot.public_connections)}</div>
        <div class="l">External connections</div></div>
    </div>"""

    actionable = report.actionable
    if actionable:
        findings_block = "\n".join(_finding_html(finding) for finding in actionable)
    else:
        findings_block = (
            "<div class='empty'>Nothing needs your attention. No service on this Mac is "
            "reachable from the network in a way that looks unsafe.</div>"
        )

    notes = [finding for finding in report.ordered if finding.severity is Severity.INFO]
    notes_block = (
        "\n".join(_finding_html(finding) for finding in notes)
        if notes
        else "<div class='empty'>Nothing else to report.</div>"
    )

    if snapshot.listeners:
        rows = "\n".join(
            f"<tr><td>{e(listener.protocol.upper())}</td>"
            f"<td class='mono'>{e(listener.endpoint)}</td>"
            f"<td>{e(listener.process or '—')}</td>"
            f"<td>{listener.pid or '—'}</td>"
            f"<td><span class='pill {'open' if listener.exposed else 'localonly'}'>"
            f"{e(listener.scope.label)}</span></td></tr>"
            for listener in snapshot.listeners
        )
        ports_block = (
            "<table><thead><tr><th>Protocol</th><th>Bound to</th><th>Process</th>"
            f"<th>PID</th><th>Reachable from</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        ports_block = "<div class='empty'>No listening sockets were found.</div>"

    limitations = ""
    if snapshot.limitations:
        items = "\n".join(f"<li>{e(note)}</li>" for note in snapshot.limitations)
        limitations = f"<h2>What this audit could not see</h2><ul class='ev'>{items}</ul>"

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
  {score_block}
  <h2>Needs attention</h2>
  {findings_block}
  <h2>Also worth knowing</h2>
  {notes_block}
  <h2>Every listening port</h2>
  {ports_block}
  {limitations}
  <footer>
    Produced by <a href="{e(HOMEPAGE)}">{e(APP_NAME)}</a>. This audit describes only the
    Mac it ran on: it reads local configuration and does not scan, contact, or probe any
    other device. ClamAV is a registered trademark of Cisco Systems, Inc. ClamMac is not
    affiliated with or endorsed by Cisco Systems, Inc.
  </footer>
</main>
</body>
</html>
"""


def _finding_html(finding) -> str:
    e = html.escape
    evidence = ""
    if finding.evidence:
        items = "\n".join(f"<li>{e(line)}</li>" for line in finding.evidence)
        evidence = f"<ul class='ev'>{items}</ul>"
    recommendation = (
        f"<p class='rec'>{e(finding.recommendation)}</p>" if finding.recommendation else ""
    )
    reference = f"<div class='ref'>{e(finding.reference)}</div>" if finding.reference else ""
    severity = finding.severity.value
    return (
        f"<div class='finding {severity}'>"
        f"<h3>{e(finding.title)} <span class='pill {severity}'>"
        f"{e(finding.severity.label)}</span></h3>"
        f"<p>{e(finding.summary)}</p>{recommendation}{evidence}{reference}</div>"
    )


def write_report(destination: Path, report: AuditReport, *, fmt: str = "html", title: str = "") -> Path:
    """Render an audit report and write it to ``destination``."""
    fmt = fmt.lower().lstrip(".")
    if fmt == "json":
        body = to_json(report)
    elif fmt == "csv":
        body = to_csv(report)
    elif fmt == "html":
        body = to_html(report, title=title)
    else:
        raise ValueError(f"unsupported report format: {fmt}")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body, encoding="utf-8")
    return destination
