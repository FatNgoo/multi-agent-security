"""Upload to SQLite, query dataset/evidence, validate invalid XML."""
import os
import pytest
from fastapi.testclient import TestClient
from app.api.main import app
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "data/fixtures/sysmon-event-viewer.xml"


def test_xml_upload_and_query():
    with TestClient(app) as client:
        with FIXTURE.open("rb") as fh:
            upload = client.post("/api/v1/logs/upload", files={"file": ("export.xml", fh, "application/xml")})
        assert upload.status_code == 201, upload.text
        assert upload.json()["imported_records"] == 2
        dataset_id = upload.json()["dataset_id"]
        res = client.get("/api/v1/events", params={
            "dataset_id":dataset_id, "host":"WIN-LAB-01",
            "start_time":"2026-10-14T08:00:00Z", "end_time":"2026-10-14T09:00:00Z"})
        assert res.status_code == 200, res.text
        assert len(res.json()) == 2
        evidence_id = res.json()[0]["evidence_id"]
        ev = client.get(f"/api/v1/evidence/{evidence_id}")
        assert ev.status_code == 200
        assert ev.json()["raw"]["format"] == "windows_event_xml"


def test_xml_rejects_unrelated_events():
    with TestClient(app) as client:
        bad = b'<Event><System><Provider Name="Other"/></System></Event>'
        res = client.post('/api/v1/logs/upload', files={'file': ('bad.xml',bad,'application/xml')})
        assert res.status_code == 422


@pytest.mark.parametrize("data", [
    b'<!DOCTYPE Event><Event><System><Provider Name="Microsoft-Windows-Sysmon"/>'
    b'<EventID>1</EventID><TimeCreated SystemTime="2026-10-14T08:00:00Z"/>'
    b'<Computer>WIN-LAB-01</Computer></System></Event>',
    b'<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///nonexistent-lab-file">]><Event>&xxe;</Event>',
    b'<Events><Event></Events>',
])
def test_invalid_or_forbidden_xml_returns_422_without_import(data):
    with TestClient(app) as client:
        before = client.get("/api/v1/datasets").json()
        response = client.post(
            "/api/v1/logs/upload",
            files={"file": ("invalid.xml", data, "application/xml")},
        )
        assert response.status_code == 422, response.text
        assert "Invalid Windows Event XML" in response.json()["detail"]
        assert client.get("/api/v1/datasets").json() == before
