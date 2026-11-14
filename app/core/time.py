from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utc(value: datetime) -> datetime:
    # SQLite returns timezone-naive values for UTC columns.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return utc(value).isoformat() if value else None
