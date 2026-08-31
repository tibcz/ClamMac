"""Interpreting scanner output, and driving a scan to completion."""

from __future__ import annotations

import time

import pytest

from clammac.core.scanner import (
    FileStatus,
    JobState,
    ScanJob,
    ScanKind,
    ScanProgress,
    count_files,
    parse_result_line,
    parse_summary,
)


class TestParsing:
    def test_detection(self):
        result = parse_result_line("/x/evil.com: Win.Test.EICAR_HDB-1 FOUND")
        assert result.status is FileStatus.INFECTED
        assert result.path == "/x/evil.com"
        assert result.signature == "Win.Test.EICAR_HDB-1"
        assert result.is_threat

    def test_clean(self):
        assert parse_result_line("/x/ok.txt: OK").status is FileStatus.CLEAN

    def test_a_path_containing_a_colon_and_space(self):
        """The status is at the end of the line, so this must not split early."""
        result = parse_result_line("/x/my: notes: draft.txt: OK")
        assert result.path == "/x/my: notes: draft.txt"
        assert result.status is FileStatus.CLEAN

    def test_a_detection_in_a_path_containing_a_colon(self):
        result = parse_result_line("/x/a: b/c.exe: Trojan.Foo-1 FOUND")
        assert result.path == "/x/a: b/c.exe"
        assert result.signature == "Trojan.Foo-1"

    def test_strips_the_multiple_marker_clamd_adds(self):
        assert parse_result_line("/x: Foo.Bar (Multiple) FOUND").signature == "Foo.Bar"

    @pytest.mark.parametrize(
        "line,status",
        [
            ("/x/empty.zip: Empty file", FileStatus.EMPTY),
            ("/x/locked: Access denied.", FileStatus.ERROR),
            ("/x/y.bin: Can't open file or directory ERROR", FileStatus.ERROR),
            ("/x/z: Excluded", FileStatus.EXCLUDED),
        ],
    )
    def test_other_statuses(self, line, status):
        assert parse_result_line(line).status is status

    def test_engine_level_errors_have_no_path(self):
        result = parse_result_line("LibClamAV Error: cli_scanxz: too big")
        assert result.status is FileStatus.ERROR
        assert result.path == ""

    @pytest.mark.parametrize("line", ["", "   ", "----------- SCAN SUMMARY -----------"])
    def test_uninteresting_lines_are_ignored(self, line):
        assert parse_result_line(line) is None

    def test_summary(self):
        """The shape ClamAV 1.5 actually prints, binary units and all."""
        summary = parse_summary(
            [
                "----------- SCAN SUMMARY -----------",
                "Known viruses: 8690123",
                "Engine version: 1.5.4",
                "Scanned directories: 412",
                "Scanned files: 9871",
                "Infected files: 2",
                "Data scanned: 1204.55 MiB",
                "Data read: 980.12 MiB (ratio 1.23:1)",
                "Time: 133.482 sec (2 m 13 s)",
                "Start Date: 2026:08:31 08:16:46",
                "End Date:   2026:08:31 08:18:59",
            ]
        )
        assert summary.known_viruses == 8690123
        assert summary.engine_version == "1.5.4"
        assert summary.scanned_files == 9871
        assert summary.infected_files == 2
        assert summary.data_scanned_mb == pytest.approx(1204.55 * 1024**2 / 1e6)
        assert summary.seconds == pytest.approx(133.482)

    def test_a_partial_summary_does_not_raise(self):
        assert parse_summary(["Scanned files: not a number", "nonsense"]).scanned_files == 0


class TestSummarySizeUnits:
    """clamscan picks the unit to suit the number; the reader must follow.

    Taking the leading figure and calling it megabytes -- which is what the
    field is named for and what the parser used to do -- is wrong by a factor
    of a thousand in either direction, and the wrong number is what lands in
    the history database and in every exported report.
    """

    @pytest.mark.parametrize(
        ("printed", "expected_mb"),
        [
            ("170 B", 170 / 1e6),
            ("512 B", 512 / 1e6),
            ("800.00 KiB", 800 * 1024 / 1e6),
            ("6.64 MiB", 6.64 * 1024**2 / 1e6),
            ("3.20 GiB", 3.20 * 1024**3 / 1e6),
        ],
    )
    def test_binary_units_are_converted(self, printed, expected_mb):
        summary = parse_summary([f"Data scanned: {printed}"])
        assert summary.data_scanned_mb == pytest.approx(expected_mb)

    def test_data_read_uses_the_same_conversion(self):
        summary = parse_summary(["Data read: 2.00 GiB (ratio 1.08:1)"])
        assert summary.data_read_mb == pytest.approx(2 * 1024**3 / 1e6)

    def test_a_tiny_scan_is_not_reported_as_hundreds_of_megabytes(self):
        """The regression in its plainest form: 170 bytes is not 170 MB."""
        assert parse_summary(["Data scanned: 170 B"]).data_scanned_mb < 1

    def test_a_huge_scan_is_not_reported_as_a_handful_of_megabytes(self):
        assert parse_summary(["Data scanned: 3.20 GiB"]).data_scanned_mb > 1000

    def test_decimal_units_are_honoured_too(self):
        assert parse_summary(["Data scanned: 12.34 MB"]).data_scanned_mb == pytest.approx(12.34)

    def test_a_bare_number_is_still_read_as_megabytes(self):
        """What older ClamAV printed, and what the field is named for."""
        assert parse_summary(["Data scanned: 1204.55"]).data_scanned_mb == pytest.approx(1204.55)


class TestProgress:
    def test_fraction_is_negative_when_the_total_is_unknown(self):
        assert ScanProgress(JobState.RUNNING, scanned=10, total=0).fraction == -1.0

    def test_fraction_never_exceeds_one(self):
        assert ScanProgress(JobState.RUNNING, scanned=150, total=100).fraction == 1.0

    def test_eta_is_negative_without_a_rate(self):
        assert ScanProgress(JobState.RUNNING, scanned=0, total=100).eta_seconds == -1.0

    def test_eta_uses_the_observed_rate(self):
        progress = ScanProgress(JobState.RUNNING, scanned=50, total=100, elapsed=10.0)
        assert progress.rate == pytest.approx(5.0)
        assert progress.eta_seconds == pytest.approx(10.0)


class TestCounting:
    def test_counts_files_recursively(self, sample_tree, settings):
        assert count_files([sample_tree], settings) == 8

    def test_counts_a_single_file(self, sample_tree, settings):
        assert count_files([sample_tree / "clean0.txt"], settings) == 1

    def test_honours_exclusions(self, sample_tree, settings):
        settings.exclusions.paths = [str(sample_tree / "nested")]
        assert count_files([sample_tree], settings) == 6

    def test_skips_noisy_directories(self, sample_tree, settings):
        noisy = sample_tree / ".git"
        noisy.mkdir()
        for index in range(20):
            (noisy / f"object{index}").write_text("x")
        assert count_files([sample_tree], settings) == 8

    def test_returns_zero_when_it_runs_out_of_time(self, sample_tree, settings):
        """Zero means unknown, and the interface shows indeterminate progress."""
        assert count_files([sample_tree], settings, time_budget=-1.0) == 0

    def test_missing_targets_do_not_raise(self, tmp_path, settings):
        assert count_files([tmp_path / "absent"], settings) == 0


class TestScanJob:
    def _job(self, tools, targets, settings, **kwargs):
        return ScanJob(tools=tools, targets=targets, settings=settings, **kwargs)

    def test_runs_to_completion_and_reports_findings(self, engine_tools, sample_tree, settings):
        job = self._job(engine_tools, [sample_tree], settings)
        job.start()
        assert job.wait(60)

        assert job.state is JobState.COMPLETED
        assert job.scanned == 8
        assert len(job.detections) == 1
        assert job.detections[0].signature == "Test.Fake.Signature-1"
        assert len(job.errors) == 1
        assert job.summary.scanned_files == 8

    def test_reports_progress_as_it_goes(self, engine_tools, sample_tree, settings):
        seen: list[ScanProgress] = []
        job = self._job(engine_tools, [sample_tree], settings, on_progress=seen.append)
        job.start()
        job.wait(60)

        assert seen
        assert seen[-1].state is JobState.COMPLETED
        assert seen[-1].scanned == 8

    def test_calls_back_on_each_detection(self, engine_tools, sample_tree, settings):
        found = []
        job = self._job(engine_tools, [sample_tree], settings, on_detection=found.append)
        job.start()
        job.wait(60)
        assert [f.signature for f in found] == ["Test.Fake.Signature-1"]

    def test_a_clean_tree_reports_nothing(self, engine_tools, tmp_path, settings):
        clean = tmp_path / "clean"
        clean.mkdir()
        (clean / "a.txt").write_text("fine")
        job = self._job(engine_tools, [clean], settings)
        job.start()
        job.wait(60)
        assert job.state is JobState.COMPLETED
        assert job.detections == []

    def test_cancelling_stops_it(self, engine_tools, tmp_path, settings, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.01")
        busy = tmp_path / "busy"
        busy.mkdir()
        for index in range(400):
            (busy / f"f{index}.txt").write_text("x")

        job = self._job(engine_tools, [busy], settings)
        job.start()
        _wait_for(lambda: job.state is JobState.RUNNING)
        time.sleep(0.3)
        job.cancel()

        assert job.wait(30)
        assert job.state is JobState.CANCELLED
        assert job.scanned < 400

    def test_pause_holds_and_resume_continues(self, engine_tools, tmp_path, settings, monkeypatch):
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.01")
        busy = tmp_path / "busy"
        busy.mkdir()
        for index in range(400):
            (busy / f"f{index}.txt").write_text("x")

        job = self._job(engine_tools, [busy], settings)
        job.start()
        _wait_for(lambda: job.state is JobState.RUNNING)
        time.sleep(0.3)

        assert job.pause()
        assert job.state is JobState.PAUSED

        # SIGSTOP stops the scanner, but ClamMac's reader thread may still be
        # draining lines the child had already written into the pipe before
        # the signal landed, so the count can tick up once or twice after the
        # pause returns. Let that settle before taking the reading -- reading
        # immediately races the pipe rather than testing the pause, which is
        # what made this test fail about one run in fifteen.
        time.sleep(0.3)
        held = job.scanned
        time.sleep(0.5)
        # Half a second at ~100 files/sec: an unpaused scan would be far ahead.
        assert job.scanned == held  # genuinely stopped, not just slowed

        assert job.resume()
        assert job.state is JobState.RUNNING
        job.cancel()
        job.wait(30)

    def test_cancelling_while_paused_still_ends_the_job(
        self, engine_tools, tmp_path, settings, monkeypatch
    ):
        """A stopped process cannot act on SIGTERM until it is continued."""
        monkeypatch.setenv("FAKE_CLAMSCAN_DELAY", "0.01")
        busy = tmp_path / "busy"
        busy.mkdir()
        for index in range(400):
            (busy / f"f{index}.txt").write_text("x")

        job = self._job(engine_tools, [busy], settings)
        job.start()
        _wait_for(lambda: job.state is JobState.RUNNING)
        time.sleep(0.2)
        job.pause()
        job.cancel()

        assert job.wait(15)
        assert job.state is JobState.CANCELLED

    def test_refuses_to_start_twice(self, engine_tools, sample_tree, settings):
        job = self._job(engine_tools, [sample_tree], settings)
        job.start()
        with pytest.raises(RuntimeError, match="already running"):
            job.start()
        job.wait(30)

    def test_reports_a_failure_rather_than_raising(self, tmp_path, settings):
        from clammac.core.engine import EngineTools

        missing = EngineTools(
            root=tmp_path, clamscan=tmp_path / "nope", freshclam=tmp_path / "nope"
        )
        job = ScanJob(tools=missing, targets=[tmp_path], settings=settings)
        job.start()
        assert job.wait(30)
        assert job.state is JobState.FAILED
        assert job.failure

    def test_kind_labels_are_human_readable(self):
        assert ScanKind.QUICK.label == "Quick scan"
        assert ScanKind.SELFTEST.label == "Self-test"


def _wait_for(predicate, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition was never met")
