"""Working out when the next unattended run is due.

launchd owns the actual firing (see ``launchagent.py``). This module answers
the questions the interface needs: when is the next scan, is the definition
update overdue, and -- while ClamMac happens to be open -- has anything come
due that should be run now.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import paths
from .config import Frequency, ScheduleSettings, Settings
from .log import get_logger

log = get_logger(__name__)

__all__ = ["next_occurrence", "describe_schedule", "UpdateDue", "update_due", "mark_update_run", "last_update_run"]

_STAMP = "last-update.stamp"


def next_occurrence(schedule: ScheduleSettings, *, after: datetime | None = None) -> datetime:
    """The next time this schedule fires, strictly after ``after``."""
    now = (after or datetime.now()).replace(microsecond=0)

    if schedule.frequency is Frequency.HOURLY:
        candidate = now.replace(minute=schedule.minute, second=0)
        if candidate <= now:
            candidate += timedelta(hours=1)
        return candidate

    candidate = now.replace(hour=schedule.hour, minute=schedule.minute, second=0)

    if schedule.frequency is Frequency.DAILY:
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    if schedule.frequency is Frequency.WEEKLY:
        days_ahead = (schedule.weekday - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate

    # Monthly, clamped to a day every month actually has.
    day = max(1, min(28, schedule.day_of_month))
    candidate = candidate.replace(day=day)
    if candidate <= now:
        year, month = candidate.year, candidate.month + 1
        if month > 12:
            year, month = year + 1, 1
        day = min(day, calendar.monthrange(year, month)[1])
        candidate = candidate.replace(year=year, month=month, day=day)
    return candidate


def describe_schedule(schedule: ScheduleSettings) -> str:
    """A plain-English rendering of a schedule, for the settings screen."""
    when = f"{schedule.hour:02d}:{schedule.minute:02d}"
    if schedule.frequency is Frequency.HOURLY:
        return f"Every hour, at {schedule.minute} minutes past"
    if schedule.frequency is Frequency.DAILY:
        return f"Every day at {when}"
    if schedule.frequency is Frequency.WEEKLY:
        return f"Every {calendar.day_name[schedule.weekday]} at {when}"
    day = max(1, min(28, schedule.day_of_month))
    return f"On day {day} of each month at {when}"


def describe_target(schedule: ScheduleSettings) -> str:
    if schedule.target == "quick":
        return "Quick scan"
    if schedule.target == "full":
        return "Full scan"
    return paths.shorten(schedule.target)


# --------------------------------------------------------------------------
# definition updates
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class UpdateDue:
    due: bool
    last_run: datetime | None
    next_run: datetime | None
    reason: str = ""


def _stamp_path() -> Path:
    return paths.support_dir() / _STAMP


def mark_update_run(when: datetime | None = None) -> None:
    """Record that a definition update just completed."""
    stamp = when or datetime.now(timezone.utc)
    try:
        _stamp_path().write_text(stamp.isoformat(timespec="seconds"), encoding="utf-8")
    except OSError as exc:
        log.debug("could not record the update time: %s", exc)


def last_update_run() -> datetime | None:
    path = _stamp_path()
    if not path.is_file():
        return None
    try:
        parsed = datetime.fromisoformat(path.read_text("utf-8").strip())
    except (OSError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def update_due(settings: Settings, *, now: datetime | None = None) -> UpdateDue:
    """Is a definition update overdue?"""
    moment = now or datetime.now(timezone.utc)
    last = last_update_run()
    if not settings.updates.auto_update:
        return UpdateDue(False, last, None, "Automatic updates are turned off")
    if last is None:
        return UpdateDue(True, None, moment, "Definitions have never been updated")
    interval = timedelta(seconds=settings.updates.frequency.seconds)
    following = last + interval
    if following <= moment:
        return UpdateDue(True, last, following, "The scheduled update time has passed")
    return UpdateDue(False, last, following, "")
