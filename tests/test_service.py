"""The coordinator: what happens end to end when a scan finds something."""

from __future__ import annotations

import time
from datetime import UTC

import pytest

from clammac.core import engine as engine_module
from clammac.core.config import ThreatAction
from clammac.core.scanner import ScanKind
from clammac.core.service import AppService, Health


@pytest.fixture
def service(engine_tools, settings):
    instance = AppService(settings=settings)
    instance.engine = engine_module.EngineInfo(
        tools=engine_tools, engine_version="1.5.4", database_version=27700
    )
    return instance


def _run(service, targets, **kwargs):
    job = service.start_scan(ScanKind.CUSTOM, targets, **kwargs)
    assert job.wait(60)
    # The finished callback runs on the scan thread just after wait returns.
    deadline = time.monotonic() + 10
    while service.active_scan is not None and time.monotonic() < deadline:
        time.sleep(0.02)
    return job


class TestThreatResponse:
    def test_quarantine_moves_the_file_and_records_it(self, service, sample_tree):
        service.settings.scan.on_threat = ThreatAction.QUARANTINE
        job = _run(service, [sample_tree])

        assert len(job.detections) == 1
        assert service.quarantine.count() == 1
        assert not (sample_tree / "nested" / "totally-infected.exe").exists()

        entry = service.quarantine.entries()[0]
        assert entry.signature == "Test.Fake.Signature-1"
        assert entry.scan_id == job.job_id

        recorded = service.history.detections()
        assert [d.action for d in recorded] == ["quarantine"]
        assert recorded[0].quarantine_id == entry.entry_id

    def test_delete_removes_the_file(self, service, sample_tree):
        service.settings.scan.on_threat = ThreatAction.DELETE
        _run(service, [sample_tree])
        assert not (sample_tree / "nested" / "totally-infected.exe").exists()
        assert service.quarantine.count() == 0
        assert [d.action for d in service.history.detections()] == ["deleted"]

    def test_report_only_leaves_the_file_alone(self, service, sample_tree):
        service.settings.scan.on_threat = ThreatAction.REPORT
        _run(service, [sample_tree])
        assert (sample_tree / "nested" / "totally-infected.exe").exists()
        assert service.quarantine.count() == 0
        assert [d.action for d in service.history.detections()] == ["report"]

    def test_a_self_test_detection_is_never_quarantined(self, service, tmp_path, monkeypatch):
        """Finding the EICAR file is the point of the test, not an incident."""
        from clammac.core.scanner import FileResult, FileStatus

        target = tmp_path / "clammac-selftest.txt"
        target.write_text("harmless")
        detection = FileResult(str(target), FileStatus.INFECTED, signature="Win.Test.EICAR_HDB-1")

        action, quarantine_id = service._act_on(detection, ThreatAction.QUARANTINE, "selftest")
        assert action == "report"
        assert quarantine_id == ""
        assert target.exists()

    def test_a_failed_quarantine_is_recorded_rather_than_raised(self, service, tmp_path):
        from clammac.core.scanner import FileResult, FileStatus

        detection = FileResult(str(tmp_path / "gone.exe"), FileStatus.INFECTED, signature="X")
        action, _ = service._act_on(detection, ThreatAction.QUARANTINE, "s1")
        assert action == "failed"
        assert any(e.level == "error" for e in service.history.events())


class TestHistoryRecording:
    def test_a_completed_scan_is_recorded(self, service, sample_tree):
        job = _run(service, [sample_tree])
        record = service.history.last_scan()
        assert record.id == job.job_id
        assert record.state == "completed"
        assert record.scanned == 8
        assert record.infected == 1
        assert record.engine_version == "1.5.4"
        assert record.database_version == 27700

    def test_callbacks_still_fire(self, service, sample_tree):
        finished, detections = [], []
        _run(service, [sample_tree], on_finished=finished.append, on_detection=detections.append)
        assert len(finished) == 1
        assert len(detections) == 1


class TestConcurrency:
    def test_only_one_scan_at_a_time(self, service, sample_tree, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.05")
        service.start_scan(ScanKind.CUSTOM, [sample_tree])
        with pytest.raises(RuntimeError, match="already running"):
            service.start_scan(ScanKind.CUSTOM, [sample_tree])
        service.stop_scan()

    def test_the_slot_is_released_afterwards(self, service, sample_tree):
        _run(service, [sample_tree])
        assert service.active_scan is None
        _run(service, [sample_tree])  # would raise if the slot were still held


class TestTargets:
    def test_an_empty_target_list_is_refused(self, service):
        with pytest.raises(ValueError, match="nothing to scan"):
            service.start_scan(ScanKind.CUSTOM, [])

    def test_quick_and_full_resolve_themselves(self, service):
        assert service.resolve_targets(ScanKind.FULL)
        assert isinstance(service.resolve_targets(ScanKind.QUICK), list)

    def test_scanning_without_an_engine_raises(self, settings, sample_tree):
        bare = AppService(settings=settings)
        bare.engine = None
        with pytest.raises(RuntimeError, match="No ClamAV engine"):
            bare.start_scan(ScanKind.CUSTOM, [sample_tree])


class TestStatus:
    def test_no_engine_means_setting_up(self, settings):
        bare = AppService(settings=settings)
        bare.engine = None
        status = bare.status()
        assert status.health is Health.SETTING_UP
        assert any("engine" in reason for reason in status.reasons)

    def test_no_definitions_means_at_risk(self, service):
        status = service.status()
        assert status.health is Health.AT_RISK
        assert any("definitions" in reason for reason in status.reasons)

    def test_stale_definitions_ask_for_attention(self, service, monkeypatch):
        from datetime import datetime, timedelta
        from pathlib import Path

        from clammac.core.engine import DatabaseInfo

        stale = DatabaseInfo(
            directory=Path("/db"),
            files=(Path("/db/daily.cvd"),),
            total_bytes=1000,
            newest=datetime.now(UTC) - timedelta(days=30),
        )
        monkeypatch.setattr("clammac.core.service.engine_module.database_info", lambda *a: stale)
        status = service.status()
        assert status.health is Health.ATTENTION
        assert status.database_stale

    def test_listeners_are_told(self, service):
        seen = []
        service.add_status_listener(seen.append)
        service.notify_status()
        assert len(seen) == 1

    def test_a_broken_listener_does_not_break_the_others(self, service):
        seen = []

        def explode(_status):
            raise RuntimeError("this listener is broken")

        service.add_status_listener(explode)
        service.add_status_listener(seen.append)
        service.notify_status()
        assert len(seen) == 1


class TestCrashRecovery:
    """What the next launch does about a scan the last one never finished."""

    def _orphan(self, service, sample_tree, *, found=("bad.exe",), scanned=700):
        from clammac.core.history import ScanRecord

        service.history.record_scan(
            ScanRecord(
                id="crashed",
                kind="quick",
                targets=[str(sample_tree)],
                started_at="2026-08-30T10:00:00+00:00",
                state="running",
                scanned=scanned,
                owner_pid=2**22 + 4321,
            )
        )
        paths = []
        for name in found:
            victim = sample_tree / name
            victim.write_text("not really malware")
            service.history.record_detection("crashed", str(victim), "Win.Trojan.Test")
            paths.append(victim)
        return paths

    def test_findings_and_progress_survive_a_crash(self, service, sample_tree):
        self._orphan(service, sample_tree)
        assert service.recover_interrupted_scans() == 1
        record = service.history.scan("crashed")
        assert record.interrupted
        assert record.scanned == 700
        assert record.infected == 1
        assert len(service.history.detections(scan_id="crashed")) == 1

    def test_the_configured_response_is_applied_to_what_was_found(self, service, sample_tree):
        service.settings.scan.on_threat = ThreatAction.QUARANTINE
        (victim,) = self._orphan(service, sample_tree)
        service.recover_interrupted_scans()
        assert not victim.exists()
        assert service.quarantine.count() == 1
        (detection,) = service.history.detections(scan_id="crashed")
        assert detection.action == "quarantine"

    def test_report_only_leaves_files_alone(self, service, sample_tree):
        service.settings.scan.on_threat = ThreatAction.REPORT
        (victim,) = self._orphan(service, sample_tree)
        service.recover_interrupted_scans()
        assert victim.exists()
        assert service.history.detections(scan_id="crashed")[0].action == "report"

    def test_a_file_that_has_gone_is_noted_not_failed(self, service, sample_tree):
        (victim,) = self._orphan(service, sample_tree)
        victim.unlink()
        service.recover_interrupted_scans()
        assert service.history.detections(scan_id="crashed")[0].action == "missing"

    def test_the_user_is_told(self, service, sample_tree):
        from clammac.core.notifications import notifier

        sent = []
        notifier.set_backend(lambda n: sent.append(n) or True)
        try:
            self._orphan(service, sample_tree)
            service.recover_interrupted_scans()
        finally:
            notifier.set_backend(None)
        assert any("interrupted" in n.title for n in sent)

    def test_threat_listeners_hear_about_recovered_detections(self, service, sample_tree):
        heard = []
        service.add_threat_listener(lambda detection, action: heard.append(action))
        self._orphan(service, sample_tree)
        service.recover_interrupted_scans()
        assert len(heard) == 1

    def test_recovery_is_idempotent(self, service, sample_tree):
        self._orphan(service, sample_tree)
        assert service.recover_interrupted_scans() == 1
        assert service.recover_interrupted_scans() == 0

    def test_a_running_scan_is_not_mistaken_for_a_crash(self, service, sample_tree, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.05")
        job = service.start_scan(ScanKind.CUSTOM, [sample_tree])
        try:
            assert service.recover_interrupted_scans() == 0
            assert service.history.scan(job.job_id).in_progress
        finally:
            service.stop_scan()
            job.wait(30)

    def test_a_scan_is_on_record_while_it_is_still_running(self, service, sample_tree, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.05")
        job = service.start_scan(ScanKind.CUSTOM, [sample_tree])
        try:
            assert service.history.scan(job.job_id) is not None
        finally:
            service.stop_scan()
            job.wait(30)

    def test_detections_are_saved_the_moment_they_are_found(self, service, sample_tree, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.02")
        seen = {}

        def on_detection(result):
            seen["saved"] = [d.action for d in service.history.detections()]

        job = service.start_scan(ScanKind.CUSTOM, [sample_tree], on_detection=on_detection)
        assert job.wait(60)
        assert seen["saved"] == ["found"]

    def test_a_failing_journal_never_stops_the_scan(self, service, sample_tree, monkeypatch):
        def broken(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(service.history, "checkpoint_scan", broken)
        monkeypatch.setattr(service.history, "record_detection", broken)
        job = _run(service, [sample_tree])
        assert job.state.value == "completed"
        assert [d.action for d in service.history.detections()] == ["quarantine"]
