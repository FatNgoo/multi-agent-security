import json
from scripts.paths import FIXTURES

FIXTURE = FIXTURES / "sysmon.jsonl"


def load_sysmon_events() -> list[dict]:
    with FIXTURE.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
