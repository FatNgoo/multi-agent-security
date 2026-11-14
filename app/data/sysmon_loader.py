import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[2] / "data" / "fixtures" / "sysmon.jsonl"


def load_sysmon_events() -> list[dict]:
    with FIXTURE.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
