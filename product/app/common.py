"""Shared UTC helpers and structured application logging."""
import json
import logging
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


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {"at": iso(utcnow()), "level": record.levelname, "logger": record.name,
                   "event": record.getMessage()}
        for name in ("tool_trace", "investigation_id", "agent", "error_type", "invalid_fields"):
            if hasattr(record, name):
                payload[name] = getattr(record, name)
        if record.exc_info:
            payload["error_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=True)


def configure_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
