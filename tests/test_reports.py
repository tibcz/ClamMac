"""Exporting scans and detections."""

from __future__ import annotations

import csv
import io
import json

import pytest

from clammac.core import reports
from clammac.core.history import DetectionRecord, ScanRecord


@pytest.fixture
def scans():
    return [
        ScanRecord(
            id="s1", kind="quick", targets=["/Users/someone/Downloads"],
            started_at="2026-08-30T10:00:00+00:00", finished_at="2026-08-30T10:02:00+00:00",
            state="completed", scanned=12043, infected=1, duration=142.0,
            engine_version="1.5.4", database_version=27700,
        ),
        ScanRecord(
            id="s2", kind="full", targets=["/Users/someone"],
            started_at="2026-08-29T03:00:00+00:00", state="completed",
            scanned=418223, infected=0, duration=4021.0,
        ),
    ]


@pytest.fixture
def detections():
    return [
        DetectionRecord(
            id=1, scan_id="s1", path='/Users/someone/Downloads/<invoice> & "x".exe',
            signature="Win.Trojan.Agent-1", detected_at="2026-08-30T10:01:12+00:00",
            action="quarantine",
        )
    ]


class TestHtml:
    def test_escapes_markup_in_paths(self, scans, detections):
        body = reports.to_html(scans, detections)
        assert "&lt;invoice&gt;" in body
        assert "<invoice>" not in body

    def test_is_self_contained(self, scans, detections):
        """A report should still open years later on a machine with no network."""
        body = reports.to_html(scans, detections)
        assert "<script" not in body.lower()
        assert 'src="http' not in body
        assert "<link" not in body.lower()

    def test_adapts_to_dark_mode(self, scans, detections):
        assert "prefers-color-scheme: dark" in reports.to_html(scans, detections)

    def test_carries_the_trademark_notice(self, scans, detections):
        # Collapse whitespace: the footer wraps across source lines.
        body = " ".join(reports.to_html(scans, detections).split())
        assert "ClamAV is a registered trademark of Cisco Systems, Inc." in body
        assert "not affiliated with or endorsed by Cisco Systems" in body

    def test_says_so_when_nothing_was_found(self, scans):
        assert "No threats were found" in reports.to_html(scans, [])

    def test_copes_with_no_data_at_all(self):
        assert "No scans recorded" in reports.to_html([], [])


class TestCsv:
    def test_has_both_sections(self, scans, detections):
        rows = list(csv.reader(io.StringIO(reports.to_csv(scans, detections))))
        assert ["Scans"] in rows
        assert ["Detections"] in rows

    def test_every_scan_and_detection_appears(self, scans, detections):
        body = reports.to_csv(scans, detections)
        assert "s1" in body and "s2" in body
        assert "Win.Trojan.Agent-1" in body

    def test_quoting_survives_a_round_trip(self, scans, detections):
        rows = list(csv.reader(io.StringIO(reports.to_csv(scans, detections))))
        paths = [cell for row in rows for cell in row if "invoice" in cell]
        assert paths == ['/Users/someone/Downloads/<invoice> & "x".exe']


class TestJson:
    def test_is_valid_and_complete(self, scans, detections):
        payload = json.loads(reports.to_json(scans, detections))
        assert payload["generator"]["name"] == "ClamMac"
        assert len(payload["scans"]) == 2
        assert len(payload["detections"]) == 1
        assert payload["generated_at"]


class TestWriting:
    @pytest.mark.parametrize("fmt", ["html", "csv", "json"])
    def test_writes_each_format(self, tmp_path, scans, detections, fmt):
        written = reports.write_report(tmp_path / f"report.{fmt}", scans, detections, fmt=fmt)
        assert written.exists() and written.stat().st_size > 0

    def test_creates_missing_directories(self, tmp_path, scans, detections):
        target = tmp_path / "deep" / "nested" / "report.html"
        assert reports.write_report(target, scans, detections).exists()

    def test_rejects_an_unknown_format(self, tmp_path, scans, detections):
        with pytest.raises(ValueError, match="unsupported report format"):
            reports.write_report(tmp_path / "r.pdf", scans, detections, fmt="pdf")
