"""
Shared "business hours" definition used by both the Policy engine
(business_hours_only / allowed_days) and the Risk engine
(OUTSIDE_BUSINESS_HOURS factor) — one definition, not two that could
silently drift apart.

PROJECT-SPECIFIC SIMPLIFICATION: business hours are fixed at 09:00–17:00
UTC, Monday–Friday. A real deployment would make this per-organization
(timezone, holidays, shift schedules) — that's explicitly out of scope
for Phase 4's deterministic, explainable engine.
"""

from datetime import datetime, timezone

BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 17
BUSINESS_DAYS = {0, 1, 2, 3, 4}  # Mon=0 .. Sun=6 (datetime.weekday())

_WEEKDAY_CODE = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


def is_business_hours(dt: datetime) -> bool:
    """True if `dt` (any tz-aware datetime; converted to UTC) falls within
    09:00–17:00 UTC on a weekday."""
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.weekday() in BUSINESS_DAYS and BUSINESS_HOURS_START <= dt_utc.hour < BUSINESS_HOURS_END


def weekday_code(dt: datetime) -> str:
    """MON/TUE/.../SUN for `dt`, in UTC — matches Policy.allowed_days values."""
    return _WEEKDAY_CODE[dt.astimezone(timezone.utc).weekday()]


def is_allowed_day(dt: datetime, allowed_days) -> bool:
    """True if `allowed_days` is empty/None (no restriction) or contains dt's weekday."""
    if not allowed_days:
        return True
    return weekday_code(dt) in allowed_days
