"""Multi-core full scans: the walk, the daemon, and the job driving both."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from clammac.core import engine, parallel, paths
from clammac.core.clamd import _parse_single_verdict
from clammac.core.engine import EngineTools
from clammac.core.scanner import FileStatus, JobState, ScanJob, ScanKind
from clammac.core.service import AppService

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_CLAMD = FIXTURES / "fake_clamd.py"
FAKE_CLAMSCAN = FIXTURES / "fake_clamscan.py"


@pytest.fixture
def short_home(monkeypatch):
    """A support folder with a short path.

    A Unix socket path may be at most 104 bytes on macOS, and pytest's own
    temporary folders are already longer than that once ClamMac's runtime
    directory and socket name are added.
    """
    base = tempfile.mkdtemp(prefix="cm-", dir="/tmp")
    monkeypatch.setenv("CLAMMAC_HOME", base)
    paths.ensure_tree()
    yield Path(base)
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def daemon_tools():
    return EngineTools(
        root=FIXTURES,
        clamscan=FAKE_CLAMSCAN,
        freshclam=FAKE_CLAMSCAN,
        clamd=FAKE_CLAMD,
        clamdscan=FAKE_CLAMSCAN,
    )


@pytest.fixture
def wide_tree(tmp_path):
    """Enough files that a parallel scan has something to spread out."""
    root = tmp_path / "wide"
    for group in range(4):
        folder = root / f"group{group}" / "deeper"
        folder.mkdir(parents=True)
        for index in range(10):
            (folder / f"clean{index}.txt").write_text("harmless\n")
    (root / "group2" / "totally-infected.exe").write_text("payload\n")
    (root / "group3" / "unreadable.bin").write_text("locked\n")
    return root


def run(job: ScanJob, timeout: float = 30) -> ScanJob:
    job.start()
    assert job.wait(timeout), "the scan did not finish"
    return job


# --------------------------------------------------------------------------
# the walk
# --------------------------------------------------------------------------


class TestWalk:
    def test_finds_every_regular_file(self, wide_tree, settings):
        found = set(parallel.iter_scan_files([wide_tree], settings))
        assert len(found) == 42
        assert str(wide_tree / "group2" / "totally-infected.exe") in found

    def test_a_file_target_is_yielded_as_is(self, wide_tree, settings):
        target = wide_tree / "group2" / "totally-infected.exe"
        assert list(parallel.iter_scan_files([target], settings)) == [str(target)]

    def test_honours_path_and_extension_exclusions(self, wide_tree, settings):
        settings.exclusions.paths = [str(wide_tree / "group0")]
        settings.exclusions.extensions = ["exe"]
        found = list(parallel.iter_scan_files([wide_tree], settings))
        assert len(found) == 31  # 42, less ten in group0 and the one .exe
        assert not any("group0" in p or p.endswith(".exe") for p in found)

    def test_never_enters_the_quarantine(self, settings, isolated_home):
        quarantined = paths.quarantine_dir() / "held.bin"
        quarantined.parent.mkdir(parents=True, exist_ok=True)
        quarantined.write_text("flagged earlier\n")
        found = list(parallel.iter_scan_files([paths.support_dir()], settings))
        assert str(quarantined) not in found

    def test_does_not_follow_directory_links_by_default(self, wide_tree, tmp_path, settings):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "elsewhere.txt").write_text("x\n")
        (wide_tree / "link").symlink_to(outside)
        assert not any("elsewhere" in p for p in parallel.iter_scan_files([wide_tree], settings))

    def test_follows_directory_links_when_asked_without_looping(self, wide_tree, settings):
        settings.scan.follow_directory_symlinks = True
        (wide_tree / "group0" / "loop").symlink_to(wide_tree)
        found = list(parallel.iter_scan_files([wide_tree], settings))
        assert len(found) == 42  # the loop back to the root adds nothing

    def test_file_links_only_when_asked(self, wide_tree, settings):
        (wide_tree / "alias.txt").symlink_to(wide_tree / "group0" / "deeper" / "clean0.txt")
        assert str(wide_tree / "alias.txt") not in parallel.iter_scan_files([wide_tree], settings)
        settings.scan.follow_file_symlinks = True
        assert str(wide_tree / "alias.txt") in parallel.iter_scan_files([wide_tree], settings)

    def test_skips_fifos_which_would_hang_a_scanner(self, wide_tree, settings):
        os.mkfifo(wide_tree / "pipe")
        assert str(wide_tree / "pipe") not in parallel.iter_scan_files([wide_tree], settings)

    def test_reports_directories_it_cannot_open(self, wide_tree, settings):
        locked = wide_tree / "locked"
        locked.mkdir()
        locked.chmod(0)
        errors: list[tuple[str, str]] = []
        try:
            list(parallel.iter_scan_files([wide_tree], settings, on_error=lambda *e: errors.append(e)))
        finally:
            locked.chmod(0o755)
        assert [path for path, _ in errors] == [str(locked)]

    def test_a_missing_target_is_an_error_not_a_crash(self, tmp_path, settings):
        errors: list[tuple[str, str]] = []
        found = list(
            parallel.iter_scan_files(
                [tmp_path / "absent"], settings, on_error=lambda *e: errors.append(e)
            )
        )
        assert found == [] and len(errors) == 1

    def test_stops_when_told(self, wide_tree, settings):
        assert list(parallel.iter_scan_files([wide_tree], settings, should_stop=lambda: True)) == []


class TestWorkerCount:
    def test_uses_the_performance_cores(self, monkeypatch):
        monkeypatch.setattr(parallel, "_sysctl_int", lambda name: 8)
        assert parallel.worker_count() == 8

    def test_is_capped(self, monkeypatch):
        monkeypatch.setattr(parallel, "_sysctl_int", lambda name: 64)
        assert parallel.worker_count() == parallel.MAX_WORKERS

    def test_falls_back_to_all_cores_but_one(self, monkeypatch):
        monkeypatch.setattr(parallel, "_sysctl_int", lambda name: 0)
        monkeypatch.setattr(os, "cpu_count", lambda: 6)
        assert parallel.worker_count() == 5

    def test_never_drops_below_one(self, monkeypatch):
        monkeypatch.setattr(parallel, "_sysctl_int", lambda name: 0)
        monkeypatch.setattr(os, "cpu_count", lambda: None)
        assert parallel.worker_count() == 1


# --------------------------------------------------------------------------
# the daemon's config and replies
# --------------------------------------------------------------------------


class TestDaemonConfig:
    def test_a_named_daemon_gets_its_own_files(self, settings):
        config = engine.write_clamd_conf(settings=settings, name="clamd-scan", max_threads=8)
        body = config.read_text()
        assert config.name == "clamd-scan.conf"
        assert "clamd-scan.sock" in body and "clamd-scan.pid" in body
        assert "MaxThreads 8\n" in body

    def test_the_queue_is_deep_enough_for_every_connection(self, settings):
        """The job opens two connections per clamd thread; none may be refused."""
        for threads in (4, 16, 40):
            body = engine.write_clamd_conf(settings=settings, max_threads=threads).read_text()
            queue = int(body.split("MaxQueue ", 1)[1].split("\n", 1)[0])
            assert queue >= threads * 2

    def test_real_time_protection_keeps_its_old_config(self, settings):
        body = engine.write_clamd_conf(settings=settings).read_text()
        assert "clamd.sock" in body and "MaxThreads 4\n" in body


class TestSingleVerdict:
    def test_clean(self):
        verdict = _parse_single_verdict("/x/a.txt: OK", "/x/a.txt")
        assert verdict.ok

    def test_detection_strips_the_multiple_marker(self):
        verdict = _parse_single_verdict("/x/a: Foo.Bar (Multiple) FOUND", "/x/a")
        assert verdict.infected and verdict.signature == "Foo.Bar"

    def test_error(self):
        verdict = _parse_single_verdict("/x/a: Access denied. ERROR", "/x/a")
        assert verdict.error == "Access denied." and not verdict.infected

    def test_a_name_with_a_newline_and_colon_still_matches(self):
        path = "/x/odd: name\nhere.txt"
        assert _parse_single_verdict(f"{path}: OK", path).ok


# --------------------------------------------------------------------------
# the job
# --------------------------------------------------------------------------


class TestParallelJob:
    def test_finds_everything_a_single_core_scan_finds(
        self, short_home, daemon_tools, wide_tree, settings
    ):
        job = run(ScanJob(daemon_tools, [wide_tree], settings, kind=ScanKind.FULL, parallel=True))
        assert job.state is JobState.COMPLETED
        assert job.scanned == 42
        assert [d.path for d in job.detections] == [str(wide_tree / "group2" / "totally-infected.exe")]
        assert job.detections[0].signature == "Test.Fake.Signature-1"
        assert [e.status for e in job.errors] == [FileStatus.ERROR]
        assert job.summary.scanned_files == 42 and job.summary.infected_files == 1

    def test_really_scans_files_at_the_same_time(
        self, short_home, daemon_tools, wide_tree, settings, monkeypatch
    ):
        report = short_home / "report.json"
        monkeypatch.setenv("FAKE_CLAMD_DELAY", "0.05")
        monkeypatch.setenv("FAKE_CLAMD_REPORT", str(report))
        monkeypatch.setattr(parallel, "worker_count", lambda: 4)
        job = run(ScanJob(daemon_tools, [wide_tree], settings, parallel=True))
        assert job.state is JobState.COMPLETED
        seen = json.loads(report.read_text())
        assert seen["max_concurrent"] >= 4
        assert len(seen["scanned"]) == len(set(seen["scanned"])) == 42  # nothing twice

    def test_the_daemon_is_gone_afterwards(self, short_home, daemon_tools, wide_tree, settings):
        run(ScanJob(daemon_tools, [wide_tree], settings, parallel=True))
        assert not (paths.runtime_dir() / "clamd-scan.sock").exists()

    def test_reports_progress_and_detections_as_it_goes(
        self, short_home, daemon_tools, wide_tree, settings
    ):
        updates, found = [], []
        job = ScanJob(daemon_tools, [wide_tree], settings, parallel=True)
        job.on_progress = updates.append
        job.on_detection = found.append
        run(job)
        assert updates[-1].state is JobState.COMPLETED
        assert any(u.state is JobState.RUNNING for u in updates)
        assert len(found) == 1

    def test_pause_holds_and_resume_finishes(
        self, short_home, daemon_tools, wide_tree, settings, monkeypatch
    ):
        monkeypatch.setenv("FAKE_CLAMD_DELAY", "0.05")
        monkeypatch.setattr(parallel, "worker_count", lambda: 2)
        job = ScanJob(daemon_tools, [wide_tree], settings, parallel=True)
        job.start()
        deadline = time.monotonic() + 15
        while job.scanned == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert job.pause()
        assert job.state is JobState.PAUSED
        time.sleep(0.3)  # let the files already with clamd come back
        held = job.scanned
        time.sleep(0.4)
        assert job.scanned == held, "files kept being scanned while paused"
        assert job.resume()
        assert job.wait(30)
        assert job.state is JobState.COMPLETED and job.scanned == 42

    def test_cancel_stops_the_daemon_promptly(
        self, short_home, daemon_tools, wide_tree, settings, monkeypatch
    ):
        monkeypatch.setenv("FAKE_CLAMD_DELAY", "0.5")
        monkeypatch.setattr(parallel, "worker_count", lambda: 1)
        job = ScanJob(daemon_tools, [wide_tree], settings, parallel=True)
        job.start()
        deadline = time.monotonic() + 15
        while job.state is not JobState.RUNNING and time.monotonic() < deadline:
            time.sleep(0.01)
        started = time.monotonic()
        job.cancel()
        assert job.wait(10)
        assert time.monotonic() - started < 8
        assert job.state is JobState.CANCELLED
        assert job.scanned < 42
        assert not (paths.runtime_dir() / "clamd-scan.sock").exists()

    def test_cancel_while_the_database_loads_does_not_block(
        self, short_home, daemon_tools, wide_tree, settings, monkeypatch
    ):
        """Cancel is called from the interface; it must not wait out the load."""
        monkeypatch.setenv("FAKE_CLAMD_LOAD", "20")
        job = ScanJob(daemon_tools, [wide_tree], settings, parallel=True)
        job.start()
        deadline = time.monotonic() + 10
        while (job._daemon is None or job._daemon._process is None) and time.monotonic() < deadline:
            time.sleep(0.01)
        started = time.monotonic()
        job.cancel()
        assert time.monotonic() - started < 3
        assert job.wait(10)
        assert job.state is JobState.CANCELLED
        assert job.scanned == 0

    def test_cancel_while_paused(self, short_home, daemon_tools, wide_tree, settings, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMD_DELAY", "0.05")
        job = ScanJob(daemon_tools, [wide_tree], settings, parallel=True)
        job.start()
        deadline = time.monotonic() + 15
        while job.state is not JobState.RUNNING and time.monotonic() < deadline:
            time.sleep(0.01)
        assert job.pause()
        job.cancel()
        assert job.wait(10)
        assert job.state is JobState.CANCELLED

    def test_falls_back_to_clamscan_when_clamd_will_not_start(
        self, short_home, daemon_tools, wide_tree, settings, monkeypatch
    ):
        monkeypatch.setenv("FAKE_CLAMD_FAIL", "1")
        job = run(ScanJob(daemon_tools, [wide_tree], settings, parallel=True))
        assert job.state is JobState.COMPLETED
        assert job.scanned == 42 and len(job.detections) == 1

    def test_falls_back_when_there_is_no_clamd_at_all(self, short_home, wide_tree, settings):
        tools = EngineTools(root=FIXTURES, clamscan=FAKE_CLAMSCAN, freshclam=FAKE_CLAMSCAN)
        job = run(ScanJob(tools, [wide_tree], settings, parallel=True))
        assert job.state is JobState.COMPLETED and job.scanned == 42


class TestWhichScansGoParallel:
    def test_full_scans_do(self):
        assert AppService.scans_in_parallel(ScanKind.FULL, paths.default_scan_targets())

    def test_scheduled_full_scans_do(self):
        assert AppService.scans_in_parallel(ScanKind.SCHEDULED, paths.default_scan_targets())

    @pytest.mark.parametrize("kind", [ScanKind.QUICK, ScanKind.CUSTOM, ScanKind.REALTIME])
    def test_others_do_not(self, kind, tmp_path):
        assert not AppService.scans_in_parallel(kind, [tmp_path])

    def test_a_scheduled_folder_scan_does_not(self, tmp_path):
        assert not AppService.scans_in_parallel(ScanKind.SCHEDULED, [tmp_path])
