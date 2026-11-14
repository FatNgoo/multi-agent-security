import json
import pytest
from fastapi.testclient import TestClient
from app.api.main import app
from app.analysis.findings import persistence_findings
from app.analysis.risk import assess
from app.core.config import settings
from app.schemas.investigation import InvestigationRequest
from evaluation.scenarios import jsonl
from tests.test_multisource import upload_case


@pytest.mark.parametrize("raw,rule", [
    ({"event_id": 1, "image": r"C:\Windows\System32\schtasks.exe", "command_line": "schtasks /Create /TN Lab /TR lab.exe"}, "scheduled_task"),
    ({"event_id": 13, "target_object": r"HKLM\SYSTEM\CurrentControlSet\Services\Lab\ImagePath"}, "service"),
    ({"event_id": 11, "target_object": r"C:\Users\Lab\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\lab.lnk"}, "startup"),
])
def test_persistence_rule_metadata(raw, rule):
    event = {"source": "sysmon", "event_id": raw["event_id"], "evidence_id": "real-evidence", "normalized": raw}
    finding = persistence_findings([event])[0]
    assert finding["rule_id"] == rule
    assert finding["evidence_ids"] == ["real-evidence"]
    assert finding["limitations"]


@pytest.mark.parametrize("extra", [{"event_data": []}, {"process_guid": []}, {"source_ip": []}, {"unexpected": float("nan")}])
def test_optional_malformed_fields_reject_atomic_upload(extra):
    row = {"timestamp": "2026-10-14T08:00:00Z", "host": "HOST", "event_id": 1, "description": "Synthetic test", **extra}
    with TestClient(app) as client:
        before = client.get("/api/v1/datasets?limit=1000").headers["X-Total-Count"]
        response = client.post("/api/v1/logs/upload", files={"file": ("bad.jsonl", jsonl([row]))})
        assert response.status_code == 422, response.text
        assert client.get("/api/v1/datasets?limit=1000").headers["X-Total-Count"] == before


def test_no_scope_leak_on_empty_window_and_confidence_threshold(monkeypatch):
    with TestClient(app) as client:
        scope = upload_case(client)
        scope["start_time"] = "2026-10-15T08:00:00Z"
        scope["end_time"] = "2026-10-15T09:00:00Z"
        result = client.post("/api/v1/investigate", json=scope).json()
        assert result["route"] == "insufficient_evidence" and not result["evidence"]
        scope = upload_case(client, "ambiguous")
        monkeypatch.setattr(settings, "alert_min_confidence", "high")
        result = client.post("/api/v1/investigate", json=scope).json()
        assert result["timings"]["detection_to_alert_ms"] is None
        assert all(a["investigation_id"] != result["investigation_id"] for a in client.get("/api/v1/alerts").json())


def test_supported_connection_without_network_hypothesis_stays_medium():
    request = InvestigationRequest(dataset_id="00000000-0000-0000-0000-000000000001",
                                   start_time="2026-10-14T08:00:00Z", end_time="2026-10-14T09:00:00Z")
    findings = [{"id": "finding", "rule_id": "run_key", "agent": "persistence", "classification": "observed", "evidence_ids": ["e1"]}]
    relationships = [{"finding_id": "finding", "type": "supported_correlation", "evidence_ids": ["e1", "e2"]}]
    assert assess(findings, relationships, request)["severity"] == "medium"


def test_record_cap_reports_partial_coverage(monkeypatch):
    with TestClient(app) as client:
        scope = upload_case(client)
        monkeypatch.setattr(settings, "max_records", 10)
        response = client.post("/api/v1/investigate", json=scope)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["coverage"]["truncated"]
        assert result["coverage"]["matching_records"] > len(result["evidence"])
        assert len(result["evidence"]) <= 10
        assert any("partial" in warning.lower() for warning in result["warnings"])


def test_legacy_python_agent_preserves_scoped_contract():
    from app.agents.persistence_agent import run_persistence_agent
    with TestClient(app) as client:
        scope = upload_case(client)
        result = run_persistence_agent("WIN-LAB-01", scope["start_time"], scope["end_time"], scope["dataset_ids"][0])
        assert result["mode"] == "offline"
        assert result["summary"] and result["trace"]
        assert all(e["dataset_id"] == scope["dataset_ids"][0] for e in result["events"])
