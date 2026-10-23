"""The record of what was scanned and what was found."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from clammac.core.history import History, ScanRecord


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "history.sqlite3")


def _scan(scan_id="s1", **overrides):
    payload = {
        "id": scan_id,
        "kind": "quick",
        "targets": ["/Users/someone/Downloads"],
        "started_at": "2026-08-30T10:00:00+00:00",
        "finished_at": "2026-08-30T10:02:00+00:00",
        "state": "completed",
        "scanned": 1200,
        "infected": 0,
        "duration": 120.0,
    }
    payload.update(overrides)
    return ScanRecord(**payload)


class TestScans:
    def test_records_and_reads_back(self, history):
        history.record_scan(_scan())
        stored = history.last_scan()
        assert stored.id == "s1"
        assert stored.scanned == 1200
        assert stored.clean

    def test_recording_the_same_id_updates_it(self, history):
        history.record_scan(_scan())
        history.record_scan(_scan(scanned=9999, duration=300.0))
        assert len(history.scans()) == 1
        assert history.last_scan().scanned == 9999

    def test_returned_newest_first(self, history):
        history.record_scan(_scan("old", started_at="2026-08-01T00:00:00+00:00"))
        history.record_scan(_scan("new", started_at="2026-08-30T00:00:00+00:00"))
        assert [s.id for s in history.scans()] == ["new", "old"]

    def test_targets_survive_the_round_trip(self, history):
        history.record_scan(_scan(targets=["/a", "/b", "/c"]))
        assert history.last_scan().targets == ["/a", "/b", "/c"]
        assert "+2" in history.last_scan().target_summary

    def test_no_scans_yet(self, history):
        assert history.last_scan() is None
        assert history.scans() == []


class TestDetections:
    def test_records_and_reads_back(self, history):
        history.record_scan(_scan(infected=2))
        history.record_detections(
            "s1",
            [
                ("/a/evil.exe", "Win.Trojan.A", "quarantine", "q1"),
                ("/b/bad.doc", "Doc.Dropper.B", "report", ""),
            ],
        )
        found = history.detections()
        assert len(found) == 2
        assert {d.signature for d in found} == {"Win.Trojan.A", "Doc.Dropper.B"}

    def test_search_matches_paths_and_signatures(self, history):
        history.record_scan(_scan())
        history.record_detections(
            "s1", [("/a/evil.exe", "Win.Trojan.A", "quarantine", ""),
                   ("/b/fine.doc", "Doc.Dropper.B", "report", "")]
        )
        assert [d.name for d in history.detections(search="evil")] == ["evil.exe"]
        assert [d.name for d in history.detections(search="Dropper")] == ["fine.doc"]

    def test_filtering_by_scan(self, history):
        history.record_scan(_scan("s1"))
        history.record_scan(_scan("s2"))
        history.record_detections("s1", [("/a", "A", "report", "")])
        history.record_detections("s2", [("/b", "B", "report", "")])
        assert [d.signature for d in history.detections(scan_id="s2")] == ["B"]

    def test_recording_nothing_is_a_no_op(self, history):
        history.record_scan(_scan())
        history.record_detections("s1", [])
        assert history.detections() == []

    def test_deleting_a_scan_removes_its_detections(self, history):
        """The foreign key cascade keeps orphaned detections from piling up."""
        history.record_scan(_scan(started_at="2000-01-01T00:00:00+00:00"))
        history.record_detections("s1", [("/a", "A", "report", "")])
        history.prune(keep_days=1)
        assert history.detections() == []


class TestStatistics:
    def test_aggregates(self, history):
        history.record_scan(_scan("s1", scanned=100, duration=10.0))
        history.record_scan(_scan("s2", scanned=200, duration=20.0))
        history.record_detections("s1", [("/a", "A", "report", "")])

        stats = history.statistics()
        assert stats["scan_count"] == 2
        assert stats["files_scanned"] == 300
        assert stats["total_seconds"] == 30.0
        assert stats["threats_total"] == 1

    def test_empty_database_gives_zeroes(self, history):
        stats = history.statistics()
        assert stats["scan_count"] == 0
        assert stats["threats_total"] == 0

    def test_recent_threats_window(self, history):
        history.record_scan(_scan())
        history.record_detections("s1", [("/a", "A", "report", "")])
        assert history.statistics()["threats_last_30_days"] == 1


class TestMaintenance:
    def test_pruning_keeps_recent_records(self, history):
        recent = (datetime.now(UTC) - timedelta(days=1)).isoformat(timespec="seconds")
        history.record_scan(_scan("old", started_at="2000-01-01T00:00:00+00:00"))
        history.record_scan(_scan("new", started_at=recent))
        assert history.prune(keep_days=30) == 1
        assert [s.id for s in history.scans()] == ["new"]

    def test_clearing_removes_everything(self, history):
        history.record_scan(_scan())
        history.record_detections("s1", [("/a", "A", "report", "")])
        history.record_event("test", "something happened")
        history.clear()
        assert history.scans() == []
        assert history.detections() == []

    def test_the_database_is_not_world_readable(self, history):
        assert history.path.stat().st_mode & 0o077 == 0


class TestEvents:
    def test_records_and_filters(self, history):
        history.record_event("update", "definitions updated")
        history.record_event("quarantine", "file isolated", "warning")
        assert len(history.events()) == 2
        assert [e.message for e in history.events(kind="update")] == ["definitions updated"]


class TestCrashJournal:
    """A scan is written down as it happens, so a crash cannot take it with it."""

    def test_a_begun_scan_is_visible_and_active(self, history):
        history.begin_scan(_scan("s1", state="running", finished_at="", scanned=0))
        stored = history.scan("s1")
        assert stored.in_progress
        assert stored.owner_pid > 0

    def test_an_unfinished_scan_is_not_the_last_scan(self, history):
        history.record_scan(_scan("done", started_at="2026-08-01T00:00:00+00:00"))
        history.begin_scan(_scan("live", state="running", started_at="2026-08-30T00:00:00+00:00"))
        assert history.last_scan().id == "done"

    def test_checkpoints_update_counters(self, history):
        history.begin_scan(_scan("s1", state="running", scanned=0))
        history.checkpoint_scan(
            "s1", state="running", scanned=500, infected=2, errors=1, duration=12.0
        )
        stored = history.scan("s1")
        assert (stored.scanned, stored.infected, stored.errors) == (500, 2, 1)

    def test_a_checkpoint_never_reopens_a_closed_scan(self, history):
        history.record_scan(_scan("s1", state="completed", scanned=1200))
        history.checkpoint_scan(
            "s1", state="running", scanned=5, infected=0, errors=0, duration=1.0
        )
        assert history.scan("s1").state == "completed"
        assert history.scan("s1").scanned == 1200

    def test_a_scan_owned_by_a_dead_process_is_orphaned(self, history):
        record = _scan("s1", state="running", owner_pid=2**22 + 12345)
        history.record_scan(record)
        assert [s.id for s in history.orphaned_scans()] == ["s1"]

    def test_a_scan_owned_by_this_process_is_not_orphaned(self, history):
        history.begin_scan(_scan("s1", state="running"))
        assert history.orphaned_scans() == []

    def test_a_scan_owned_by_a_live_process_is_not_orphaned(self, history):
        import os

        history.record_scan(_scan("s1", state="running", owner_pid=os.getppid()))
        assert history.orphaned_scans() == []

    def test_marking_interrupted_keeps_what_was_counted(self, history):
        history.begin_scan(_scan("s1", state="running", scanned=0))
        history.checkpoint_scan("s1", state="running", scanned=900, infected=0, errors=0, duration=30)
        history.mark_interrupted("s1", infected=3)
        stored = history.scan("s1")
        assert stored.interrupted
        assert stored.scanned == 900
        assert stored.infected == 3
        assert stored.finished_at
        assert history.last_scan().id == "s1"

    def test_a_detection_is_saved_before_anything_is_done_about_it(self, history):
        history.begin_scan(_scan("s1", state="running"))
        history.record_detection("s1", "/tmp/bad.exe", "Win.Trojan.X")
        assert [d.action for d in history.pending_detections("s1")] == ["found"]

    def test_settling_updates_rather_than_duplicates(self, history):
        history.begin_scan(_scan("s1", state="running"))
        history.record_detection("s1", "/tmp/bad.exe", "Win.Trojan.X")
        history.settle_detection("s1", "/tmp/bad.exe", "Win.Trojan.X", "quarantine", "q1")
        found = history.detections(scan_id="s1")
        assert len(found) == 1
        assert (found[0].action, found[0].quarantine_id) == ("quarantine", "q1")
        assert history.pending_detections("s1") == []

    def test_settling_a_detection_that_was_never_journaled_adds_it(self, history):
        history.begin_scan(_scan("s1", state="running"))
        history.settle_detection("s1", "/tmp/bad.exe", "Win.Trojan.X", "report")
        assert len(history.detections(scan_id="s1")) == 1

    def test_a_database_from_before_the_journal_is_upgraded(self, tmp_path):
        import sqlite3

        path = tmp_path / "old.sqlite3"
        connection = sqlite3.connect(path)
        connection.executescript(
            """CREATE TABLE scans (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, targets TEXT NOT NULL DEFAULT '[]',
                started_at TEXT NOT NULL, finished_at TEXT, state TEXT NOT NULL,
                scanned INTEGER NOT NULL DEFAULT 0, infected INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0, duration REAL NOT NULL DEFAULT 0,
                engine_version TEXT NOT NULL DEFAULT '',
                database_version INTEGER NOT NULL DEFAULT 0,
                data_scanned_mb REAL NOT NULL DEFAULT 0);
            INSERT INTO scans (id, kind, started_at, state) VALUES
                ('old', 'quick', '2026-08-01T00:00:00+00:00', 'completed');"""
        )
        connection.commit()
        connection.close()

        upgraded = History(path)
        assert upgraded.last_scan().id == "old"
        upgraded.begin_scan(_scan("new", state="running"))
        assert upgraded.scan("new").owner_pid > 0
