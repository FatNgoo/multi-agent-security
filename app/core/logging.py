import json
import logging
from app.core.time import iso, utcnow


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {"at": iso(utcnow()), "level": record.levelname, "logger": record.name,
                   "event": record.getMessage()}
        for name in ("tool_trace", "investigation_id", "agent", "error_type"):
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
