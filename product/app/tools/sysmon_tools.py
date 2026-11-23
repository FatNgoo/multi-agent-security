from datetime import datetime, timezone
from sqlalchemy import select
from app.db.database import SessionLocal
from app.db.models import Dataset, Event


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Time bounds must include timezone")
    return dt.astimezone(timezone.utc)


def search_sysmon_events(host: str, start_time: str, end_time: str, dataset_id: str) -> list[dict]:
    """Read-only, dataset-scoped search; never falls back to synthetic fixtures."""
    start, end = _parse_time(start_time), _parse_time(end_time)
    if start > end:
        raise ValueError("start_time must not exceed end_time")
    with SessionLocal() as session:
        if session.get(Dataset, dataset_id) is None:
            raise ValueError("Dataset not found")
        rows = session.scalars(
            select(Event).where(
                Event.dataset_id == dataset_id,
                Event.host == host,
                Event.timestamp >= start,
                Event.timestamp <= end,
            ).order_by(Event.timestamp, Event.record_index).limit(100)
        ).all()
        return [
            {**row.raw, "evidence_id": row.id, "dataset_id": dataset_id,
             "timestamp": row.timestamp.replace(tzinfo=timezone.utc).isoformat(),
             "host": row.host, "event_id": row.event_id, "description": row.description}
            for row in rows
        ]
