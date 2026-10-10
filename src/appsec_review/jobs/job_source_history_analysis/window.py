"""Calendar-month history windows anchored to the snapshot commit, never to wall-clock time."""

from __future__ import annotations

import calendar
from datetime import datetime, timezone


WINDOW_IDENTITY = "appsec-review/history-window/calendar-months-utc/1"


def window_start(anchor_time: int, months: int) -> int:
    """Return the inclusive start of an ``months``-calendar-month window ending at ``anchor_time``.

    The anchor is read as UTC.  The start keeps the anchor's time of day and day of month; when
    that day does not exist in the target month it clamps to the month's last day.  So 31 August
    minus six months is 29 February in a leap year and 28 February otherwise, and 29 February
    minus twelve months is 28 February.
    """
    if months < 1:
        raise ValueError("history window must cover at least one month")
    anchor = datetime.fromtimestamp(anchor_time, tz=timezone.utc)
    year, month_index = divmod(anchor.year * 12 + anchor.month - 1 - months, 12)
    month = month_index + 1
    day = min(anchor.day, calendar.monthrange(year, month)[1])
    return int(anchor.replace(year=year, month=month, day=day).timestamp())
