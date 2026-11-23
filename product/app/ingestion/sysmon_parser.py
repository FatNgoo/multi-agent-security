import json
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ValidationError, field_validator


class SysmonRecord(BaseModel):
    timestamp: datetime
    host: str = Field(min_length=1, max_length=128)
    event_id: int = Field(ge=1)
    description: str = Field(min_length=1, max_length=2000)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone (e.g. Z)")
        return value.astimezone(timezone.utc)


def parse_jsonl(data: bytes) -> list[tuple[int, SysmonRecord, dict]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Upload must be UTF-8 JSON/JSONL") from exc
    rows = []
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            json.dumps(raw, allow_nan=False)
            if not isinstance(raw, dict):
                raise ValueError("each line must be a JSON object")
            record = SysmonRecord.model_validate(raw)
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise ValueError(f"Invalid record on line {index}: {exc}") from exc
        rows.append((index, record, {**raw, "_raw_line": line}))
    if not rows:
        raise ValueError("File contains no events")
    return rows
