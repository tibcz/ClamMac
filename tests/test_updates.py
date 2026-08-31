"""Reading freshclam's output, and knowing when an update is due."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from clammac.core import scheduler
from clammac.core.config import Frequency, ScheduleSettings, Settings
from clammac.core.freshclam import UpdateState, parse_update_line
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
