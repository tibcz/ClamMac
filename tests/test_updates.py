"""Reading freshclam's output, and knowing when an update is due."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from clammac.core import scheduler
from clammac.core.config import Frequency, ScheduleSettings, Settings
from clammac.core.freshclam import UpdateJob, UpdateState, parse_update_line
from clammac.core.scheduler import describe_schedule, next_occurrence, update_due


class TestUpdateOutput:
    def test_up_to_date(self):
        change, progress = parse_update_line(
            "daily.cvd database is up-to-date (version: 27700, sigs: 2050000, f-level: 90)"
        )
        assert change.name == "daily.cvd"
        assert change.version == 27700
        assert change.signatures == 2050000
        assert not change.updated
        assert progress.state is UpdateState.RUNNING

    def test_updated(self):
        change, _ = parse_update_line("main.cvd updated (version: 62, sigs: 6647427, f-level: 90)")
        assert change.name == "main.cvd"
        assert change.version == 62
        assert change.updated

    @pytest.mark.parametrize("percent", [0, 45, 100])
    def test_download_progress(self, percent):
        _, progress = parse_update_line(f"Downloading daily-27701.cdiff [{percent:3d}%]")
        assert progress.fraction == pytest.approx(percent / 100)
        assert "daily-27701.cdiff" in progress.message

    def test_verification_step(self):
        _, progress = parse_update_line("Testing database: '/x/daily.cld' ...")
        assert progress.message == "Verifying databases"

    @pytest.mark.parametrize(
        "line", ["", "ClamAV update process started at Sat Aug 30 23:00:00 2026", "   "]
    )
    def test_uninteresting_lines(self, line):
        assert parse_update_line(line) == (None, None)


class TestTimestampedOutput:
    """ClamMac's own freshclam.conf sets ``LogTime yes``.

    That makes freshclam prefix every line it prints with a timestamp and an
    arrow, so these -- not the bare messages above -- are the lines the parser
    actually receives in production. The report patterns are anchored at the
    start of the message, so without the prefix being stripped none of them
    match, no change is recorded, and a real update reports itself as "already
    up to date". clamd is then never told to reload, and real-time protection
    goes on matching against the database it loaded at startup.
    """

    PREFIX = "Mon Aug 31 08:19:52 2026 -> "

    def test_updated_line_survives_the_prefix(self):
        change, _ = parse_update_line(
            self.PREFIX
            + "daily.cld updated (version: 27001, sigs: 2050100, f-level: 90, builder: raynman)"
        )
        assert change is not None
        assert change.name == "daily.cld"
        assert change.version == 27001
        assert change.signatures == 2050100
        assert change.updated

    def test_up_to_date_line_survives_the_prefix(self):
        change, _ = parse_update_line(
            self.PREFIX
            + "main.cvd database is up-to-date (version: 62, sigs: 6647427, f-level: 90)"
        )
        assert change is not None
        assert change.name == "main.cvd"
        assert change.version == 62
        assert not change.updated

    def test_severity_marker_is_stripped_too(self):
        change, _ = parse_update_line(
            "WARNING: " + self.PREFIX + "daily.cld updated (version: 27001, sigs: 12)"
        )
        assert change is not None and change.updated

    def test_doubled_prefix_is_stripped(self):
        """freshclam sometimes folds two prefixed messages onto one line."""
        change, _ = parse_update_line(
            "WARNING: " + self.PREFIX + "WARNING: " + self.PREFIX
            + "daily.cld updated (version: 27001, sigs: 12)"
        )
        assert change is not None and change.updated

    def test_download_progress_survives_the_prefix(self):
        _, progress = parse_update_line(self.PREFIX + "Downloading daily.cvd [ 42%]")
        assert progress is not None
        assert progress.fraction == pytest.approx(0.42)

    def test_prefix_alone_is_uninteresting(self):
        assert parse_update_line(self.PREFIX) == (None, None)

    def test_bare_lines_still_parse(self):
        """Stripping the prefix must not break output logged without LogTime."""
        change, _ = parse_update_line("daily.cld updated (version: 27001, sigs: 12)")
        assert change is not None and change.updated


class TestUpdateOutcome:
    """The whole point of parsing: knowing an update actually happened."""

    def _run(self, lines):
        job = UpdateJob(tools=None)  # type: ignore[arg-type]
        for line in lines:
            change, _ = parse_update_line(line)
            if change is not None:
                job._record(change)
        return job

    PREFIX = "Mon Aug 31 08:19:52 2026 -> "

    def test_a_real_update_is_reported_as_updated(self):
        job = self._run([
            self.PREFIX + "daily.cld updated (version: 27001, sigs: 2050100, f-level: 90)",
            self.PREFIX + "main.cvd database is up-to-date (version: 62, sigs: 6647427)",
        ])
        assert any(c.updated for c in job.changes), (
            "an update that downloaded a new database must report UPDATED, "
            "otherwise clamd is never told to reload it"
        )
        assert job.total_signatures == 2050100 + 6647427

    def test_nothing_new_is_not_reported_as_updated(self):
        job = self._run([
            self.PREFIX + "daily.cvd database is up-to-date (version: 27001, sigs: 5)",
            self.PREFIX + "main.cvd database is up-to-date (version: 62, sigs: 7)",
        ])
        assert not any(c.updated for c in job.changes)


class TestNextOccurrence:
    SUNDAY_AFTERNOON = datetime(2026, 8, 30, 14, 30)

    def test_hourly_lands_on_the_next_hour(self):
        schedule = ScheduleSettings(frequency=Frequency.HOURLY, minute=0)
        assert next_occurrence(schedule, after=self.SUNDAY_AFTERNOON) == datetime(2026, 8, 30, 15, 0)

    def test_daily_rolls_to_tomorrow_when_the_time_has_passed(self):
        schedule = ScheduleSettings(frequency=Frequency.DAILY, hour=3, minute=0)
        assert next_occurrence(schedule, after=self.SUNDAY_AFTERNOON) == datetime(2026, 8, 31, 3, 0)

    def test_daily_stays_today_when_the_time_is_still_ahead(self):
        schedule = ScheduleSettings(frequency=Frequency.DAILY, hour=23, minute=0)
        assert next_occurrence(schedule, after=self.SUNDAY_AFTERNOON) == datetime(2026, 8, 30, 23, 0)

    def test_weekly_on_today_goes_a_full_week_out(self):
        schedule = ScheduleSettings(frequency=Frequency.WEEKLY, weekday=6, hour=3)
        assert next_occurrence(schedule, after=self.SUNDAY_AFTERNOON) == datetime(2026, 9, 6, 3, 0)

    def test_weekly_finds_the_next_matching_day(self):
        schedule = ScheduleSettings(frequency=Frequency.WEEKLY, weekday=2, hour=3)
        assert next_occurrence(schedule, after=self.SUNDAY_AFTERNOON) == datetime(2026, 9, 2, 3, 0)

    def test_monthly_rolls_over_the_year_end(self):
        schedule = ScheduleSettings(frequency=Frequency.MONTHLY, day_of_month=1, hour=3)
        following = next_occurrence(schedule, after=datetime(2026, 12, 15, 10, 0))
        assert following == datetime(2027, 1, 1, 3, 0)

    def test_monthly_is_clamped_to_a_day_every_month_has(self):
        schedule = ScheduleSettings(frequency=Frequency.MONTHLY, day_of_month=31, hour=3)
        assert next_occurrence(schedule, after=self.SUNDAY_AFTERNOON).day <= 28

    def test_descriptions_read_as_english(self):
        assert describe_schedule(
            ScheduleSettings(frequency=Frequency.WEEKLY, weekday=0, hour=9, minute=30)
        ) == "Every Monday at 09:30"


class TestUpdateDue:
    def test_never_updated_is_due(self):
        assert update_due(Settings()).due

    def test_not_due_immediately_after_an_update(self):
        scheduler.mark_update_run()
        assert not update_due(Settings()).due

    def test_due_again_after_the_interval(self):
        settings = Settings()
        settings.updates.frequency = Frequency.DAILY
        scheduler.mark_update_run(datetime.now(UTC) - timedelta(days=2))
        assert update_due(settings).due

    def test_never_due_when_automatic_updates_are_off(self):
        settings = Settings()
        settings.updates.auto_update = False
        result = update_due(settings)
        assert not result.due
        assert "turned off" in result.reason

    def test_the_recorded_time_survives_a_read_back(self):
        moment = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
        scheduler.mark_update_run(moment)
        assert scheduler.last_update_run() == moment

    def test_a_corrupt_stamp_reads_as_never(self):
        scheduler.mark_update_run()
        scheduler._stamp_path().write_text("not a timestamp")
        assert scheduler.last_update_run() is None
