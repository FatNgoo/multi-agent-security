import os
import pytest
from pathlib import Path


from fastapi.testclient import TestClient
from app.main import app

FIXTURE = Path(__file__).resolve().parents[1] / "logs" / "samples" / "sysmon.jsonl"


def test_health_and_upload_investigate():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "healthy"
        with FIXTURE.open("rb") as fh:
            r = client.post("/api/v1/logs/upload", files={"file": ("sysmon.jsonl", fh, "application/json")})
        assert r.status_code == 201, r.text
        dataset_id = r.json()["dataset_id"]
        assert r.json()["imported_records"] == 4
        datasets = client.get("/api/v1/datasets").json()
        assert any(d["dataset_id"] == dataset_id for d in datasets)
        req = {"dataset_id": dataset_id, "host": "WIN-LAB-01",
               "start_time": "2026-10-14T08:00:00Z", "end_time": "2026-10-14T09:00:00Z"}
        result = client.post("/api/v1/investigate", json=req)
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["route"] == "persistence"
        assert body["mode"] == "offline"
        assert len(body["evidence"]) == 3
        assert {e["raw"]["description"] for e in body["evidence"]} == {
            "powershell.exe spawned from explorer.exe",
            r"Registry value set under HKCU\Software\Microsoft\Windows\CurrentVersion\Run (lab simulation)",
            "notepad.exe started (benign example)",
        }
        evidence_id = body["evidence"][0]["evidence_id"]
        assert client.get(f"/api/v1/evidence/{evidence_id}").status_code == 200
        # Dataset isolation: same host/time in another upload has independent IDs.
        with FIXTURE.open("rb") as fh:
            other = client.post("/api/v1/logs/upload", files={"file": ("sysmon.jsonl", fh)})
        other_id = other.json()["dataset_id"]
        other_events = client.get("/api/v1/events", params={**req, "dataset_id": other_id})
        assert other_events.status_code == 200
        assert {e["evidence_id"] for e in other_events.json()}.isdisjoint(
            {e["evidence_id"] for e in body["evidence"]}
        )


def test_invalid_upload_and_unknown_dataset():
    with TestClient(app) as client:
        bad = client.post("/api/v1/logs/upload", files={"file": ("bad.jsonl", b'{"x": 1}\n')})
        assert bad.status_code == 422
        wrong_ext = client.post("/api/v1/logs/upload", files={"file": ("test.exe", b"hi")})
        assert wrong_ext.status_code == 415
        response = client.post("/api/v1/investigate", json={
            "dataset_id": "00000000-0000-0000-0000-000000000000", "host": "WIN-LAB-01",
            "start_time": "2026-10-14T08:00:00Z", "end_time": "2026-10-14T09:00:00Z"})
        assert response.status_code == 404


@pytest.mark.parametrize("field", ["start_time", "end_time"])
def test_investigation_requires_timezone_before_execution(field):
    request = {
        "dataset_id": "00000000-0000-0000-0000-000000000000",
        "host": "WIN-LAB-01",
        "start_time": "2026-10-14T08:00:00Z",
        "end_time": "2026-10-14T09:00:00Z",
    }
    request[field] = request[field].removesuffix("Z")
    with TestClient(app) as client:
        response = client.post("/api/v1/investigate", json=request)
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"] == ["body", field]
