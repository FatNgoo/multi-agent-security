import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main
from app.db.database import Base
from app.db.models import Alert, Investigation

SAMPLES = Path(__file__).resolve().parents[1] / "logs" / "samples"


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + (tmp_path / "workspace.db").as_posix())
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(bind=engine))
    with TestClient(main.app) as http:
        yield http
    engine.dispose()


@pytest.mark.parametrize("file,source", [("sysmon-event-viewer.xml", "sysmon"), ("synthetic-conn.tsv", "zeek_conn"),
                                         ("synthetic-zeek_conn.jsonl", "zeek_conn"), ("synthetic-zeek_dns.jsonl", "zeek_dns"),
                                         ("synthetic-zeek_http.jsonl", "zeek_http"), ("synthetic-sysmon.jsonl", "sysmon")])
def test_preview_does_not_store(client, file, source):
    data = (SAMPLES / file).read_bytes()
    result = client.post("/api/v1/logs/preview", files={"file": (file, data)})
    assert result.status_code == 200, result.text
    assert result.json()["source"] == source
    assert result.json()["sha256"] == hashlib.sha256(data).hexdigest()
    assert result.json()["records"] > 0
    assert client.get("/api/v1/overview").json()["recent"] == []
    assert client.get("/api/v1/datasets").json() == []


def test_ambiguous_or_mixed_zeek_file(client):
    conn = json.loads((SAMPLES / "synthetic-zeek_conn.jsonl").read_text().splitlines()[0])
    dns = json.loads((SAMPLES / "synthetic-zeek_dns.jsonl").read_text().splitlines()[0])
    ambiguous = {key: val for key, val in conn.items() if key in ("ts", "uid", "proto") or key.startswith("id.")}
    files = {"file": ("input.log", json.dumps(ambiguous))}
    assert client.post("/api/v1/logs/preview", files=files).status_code == 422
    explicit = client.post("/api/v1/logs/preview", files=files, data={"source_type": "zeek_conn"})
    assert explicit.status_code == 200
    mixed = {"file": ("mixed.log", json.dumps(conn) + "\n" + json.dumps(dns))}
    for endpoint in ("preview", "upload"):
        r = client.post("/api/v1/logs/" + endpoint, files=mixed, data={"source_type": "auto"})
        assert r.status_code == 422 and "line 2" in r.json()["detail"]
    assert client.get("/api/v1/datasets").json() == []


def test_retry_and_overview_trace_to_xml(client):
    xml = (SAMPLES / "sysmon-event-viewer.xml").read_bytes().replace(
        b"<EventID>1</EventID>", b"<EventID>1</EventID><EventRecordID>417</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>")
    files = {"file": ("events.xml", xml)}

    def save(_):
        result = client.post("/api/v1/logs/upload", files=files, data={"source_type": "auto", "reuse_existing": True})
        assert result.status_code == 201
        return result.json()

    with ThreadPoolExecutor(max_workers=3) as pool:
        saved = list(pool.map(save, range(3)))
    assert sorted(r["imported_records"] for r in saved) == [0, 0, 2]
    identifier = saved[0]["dataset_id"]
    assert all(r["dataset_id"] == identifier for r in saved)
    assert client.post("/api/v1/logs/preview", files=files).json()["duplicate_of"] == identifier
    assert [r["dataset_id"] for r in client.get("/api/v1/datasets", params={"ids": identifier}).json()] == [identifier]
    view = client.get("/api/v1/overview", params={"source": "sysmon"}).json()
    assert view["sources"] == {"sysmon": 2}
    assert sum(b["count"] for b in view["bins"]) == 2 and sum(t["count"] for t in view["types"]) == 2
    assert [r["record_index"] for r in view["recent"]] == [2, 1]
    evidence = client.get("/api/v1/evidence/" + view["recent"][-1]["evidence_id"]).json()
    assert evidence["raw"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert evidence["raw"]["event_record_id"] == "417"
    assert evidence["raw"]["time_created"].endswith(".1234567Z")
    assert evidence["dataset_id"] == identifier


def test_overview_window_uses_event_time_and_keeps_fractional_boundaries(client):
    def event(ts):
        return json.dumps({"timestamp": ts, "event_id": 1, "host": "test", "description": "test"})
    times = ["2044-04-01T09:00:00.999998Z", "2044-04-01T09:00:00.999999Z", "2044-04-01T10:00:00.999999Z"]
    result = client.post("/api/v1/logs/upload", files={"file": ("events.jsonl", "\n".join(map(event, times)))})
    assert result.status_code == 201
    view = client.get("/api/v1/overview", params={"hours": 1}).json()
    assert view["end"].startswith("2044-04-01T10:00:00.999999")
    assert view["sources"] == {"sysmon": 2}
    assert sum(b["count"] for b in view["bins"]) == 2
    assert client.get("/api/v1/overview", params={"source": "zeek_dns"}).json()["recent"] == []

@pytest.mark.parametrize("content", [b"not an event log", b"ElfFile\x00" + bytes(4100)])
def test_invalid_evtx_atomic(client, content):
    for action in ("preview", "upload"):
        response = client.post("/api/v1/logs/" + action, files={"file": ("bad.EVTX", content)})
        assert response.status_code == 422
    assert client.get("/api/v1/datasets").json() == []


def test_real_evtx_record_and_duplicate(client):
    sample = SAMPLES.parents[2] / "testcase/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx"
    if not sample.exists():
        pytest.skip("Downloaded EVTX corpus is optional")
    data = sample.read_bytes()
    args = {"files": {"file": ("renamed.evtx", data)}, "data": {"reuse_existing": True}}
    preview = client.post("/api/v1/logs/preview", **args).json()
    assert preview["records"] == 1 and preview["source"] == "sysmon"
    assert client.post("/api/v1/logs/upload", **args).json()["imported_records"] == 1
    assert client.post("/api/v1/logs/upload", **args).json()["imported_records"] == 0
    row = client.get("/api/v1/overview").json()["recent"][0]
    evidence = client.get("/api/v1/evidence/" + row["evidence_id"]).json()
    assert evidence["event_id"] == 13 and evidence["raw"]["event_record_id"]
    assert evidence["raw"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert evidence["raw"]["event_data"] and "<EventRecordID>" in evidence["raw"]["xml"]


def test_otrf_mixed_channels_timezone_and_atomic_failure(client):
    common = {"EventID": 1, "Hostname": "LAB", "Channel": "Security", "SourceName": "Microsoft-Windows-Security-Auditing"}
    rows = [{**common, "TimeCreated": "2020-10-19 10:46:42"},
            {**common, "SourceName": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational",
             "UtcTime": "2020-10-20 02:46:43", "RecordNumber": 55},
            {**common, "@timestamp": "2020-10-20T02:46:44Z"}]
    data = "\n".join(json.dumps(r) for r in rows)
    files = {"file": ("mix.json", data)}
    preview = client.post("/api/v1/logs/preview", files=files).json()
    assert preview["records"] == 2 and preview["missing_timezone"] == 1
    assert preview["source_counts"] == {"sysmon": 1, "windows_event": 1}
    result = client.post("/api/v1/logs/upload", files=files)
    assert result.status_code == 201
    for src, line in [("sysmon", 2), ("windows_event", 3)]:
        view = client.get("/api/v1/overview", params={"source": src}).json()
        assert view["sources"] == {src: 1} and view["recent"][0]["record_index"] == line
        evidence = client.get("/api/v1/evidence/" + view["recent"][0]["evidence_id"]).json()
        assert evidence["raw"] == rows[line - 1]
    invalid = client.post("/api/v1/logs/upload", files={"file": ("mix.json", data + "\n{")})
    assert invalid.status_code == 422 and len(client.get("/api/v1/datasets").json()) == 1

def test_metrics_uses_job_and_alert_times_with_binary_data_in_evidence(client):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with main.SessionLocal.begin() as db:
        db.add(Investigation(id="test", status="completed", request={}, config_snapshot={}, created_at=start, started_at=start,
                             finished_at=start + timedelta(milliseconds=12.345), result={"evidence": [{"raw": "\x00"}]}))
        db.flush()
        db.add(Alert(id="alert", investigation_id="test", severity="high", confidence="high", status="new",
                     detected_at=start, created_at=start + timedelta(milliseconds=2.5), detection_to_alert_ms=2.5))
    metrics = client.get("/api/v1/metrics").json()
    assert metrics["runtime"] == {"samples": 1, "p50_ms": 12.345, "p95_ms": 12.345}
    assert metrics["detection_to_alert"] == {"samples": 1, "p50_ms": 2.5, "p95_ms": 2.5}
