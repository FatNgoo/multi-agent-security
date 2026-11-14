import json
import pytest
from fastapi.testclient import TestClient
from app.api.main import app
from app.data.zeek_parser import parse_zeek
from evaluation.scenarios import scenario, jsonl, conn_tsv


def upload_case(client, name="combined"):
    identifiers = []
    for source, records in scenario(name).items():
        response = client.post("/api/v1/logs/upload", data={"source_type": source},
                               files={"file": (source + ".jsonl", jsonl(records))})
        assert response.status_code == 201, response.text
        identifiers.append(response.json()["dataset_id"])
    return {"dataset_ids": identifiers, "host": "WIN-LAB-01", "mode": "offline",
            "start_time": "2026-10-14T08:00:00Z", "end_time": "2026-10-14T09:00:00Z",
            "host_mappings": [{"host": "WIN-LAB-01", "ip": "192.0.2.10", "start_time": "2026-10-14T08:00:00Z",
                               "end_time": "2026-10-14T09:00:00Z"}]}


@pytest.mark.parametrize("source", ["zeek_conn", "zeek_dns", "zeek_http"])
def test_zeek_json_normalizes_and_preserves(source):
    rows = parse_zeek(jsonl(scenario()[source]), source)
    assert rows[0][1]["source_ip"] == "192.0.2.10"
    assert rows[0][1]["timestamp"].utcoffset().total_seconds() == 0
    assert "_raw_line" in rows[0][2]


def test_tsv_matches_json_and_validates_columns():
    records = scenario()["zeek_conn"]
    tsv = parse_zeek(conn_tsv(records), "zeek_conn")
    js = parse_zeek(jsonl(records), "zeek_conn")
    assert tsv[0][1]["dest_port"] == js[0][1]["dest_port"] == 443
    assert len(tsv) == 8
    with pytest.raises(ValueError, match="column count"):
        parse_zeek(conn_tsv(records) + b"123\tbad\n", "zeek_conn")


@pytest.mark.parametrize("field,value", [("ts", float("nan")), ("id.orig_h", "invalid"), ("id.resp_p", 65536)])
def test_zeek_rejects_bad_values(field, value):
    raw = scenario()["zeek_conn"][0]
    raw[field] = value
    with pytest.raises(ValueError):
        parse_zeek(jsonl([raw]), "zeek_conn")


def test_combined_evidence_alert_review_and_report():
    with TestClient(app) as client:
        scope = upload_case(client)
        response = client.post("/api/v1/investigate", json=scope)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["risk"]["severity"] == "high"
        assert any(r["type"] == "supported_correlation" for r in result["relationships"])
        assert result["timings"]["detection_to_alert_ms"] >= 0
        assert result["timings"]["llm_calls"] == 0
        assert result["verification"]["status"] == "passed"
        ids = {e["evidence_id"] for e in result["evidence"]}
        for finding in result["findings"]:
            assert set(finding["evidence_ids"]) <= ids
            assert finding["recommendations"]
        investigation = result["investigation_id"]
        alerts = client.get("/api/v1/alerts").json()
        alert = next(a for a in alerts if a["investigation_id"] == investigation)
        assert client.patch(f"/api/v1/alerts/{alert['alert_id']}", json={"status": "acknowledged", "note": "Lab review"}).status_code == 200
        finding = result["findings"][0]
        review = client.patch(f"/api/v1/investigations/{investigation}/findings/{finding['id']}", json={
            "severity": "low", "note": "Approved lab simulation", "recommendation_id": finding["recommendations"][0]["id"],
            "recommendation_status": "completed"})
        assert review.status_code == 200, review.text
        assert review.json()["recommendations"][0]["status"] == "completed"
        assert client.get(f"/api/v1/investigations/{investigation}/audit").json()
        report = client.get(f"/api/v1/investigations/{investigation}/report?format=markdown")
        assert "Response recommendations" in report.text
        assert "attack.mitre.org" in report.text


def test_ambiguous_join_and_benign_context():
    with TestClient(app) as client:
        ambiguous = client.post("/api/v1/investigate", json=upload_case(client, "ambiguous")).json()
        assert ambiguous["relationships"]
        assert all(r["type"] == "hypothesis" for r in ambiguous["relationships"])
        assert ambiguous["risk"]["severity"] == "medium"
        benign_scope = upload_case(client, "benign")
        benign_scope["benign_destinations"] = ["198.51.100.20"]
        benign = client.post("/api/v1/investigate", json=benign_scope).json()
        assert benign["risk"]["severity"] == "low"
        assert all(f["classification"] == "benign_possible" for f in benign["findings"])


def test_scope_pagination_and_cancelled_queue():
    with TestClient(app) as client:
        scope = upload_case(client)
        params = {"dataset_id": scope["dataset_ids"][1], "start_time": scope["start_time"], "end_time": scope["end_time"], "limit": 2}
        page = client.get("/api/v1/events", params=params)
        assert len(page.json()) == 2 and page.headers["X-Has-More"] == "true"
        scope["host_mappings"] = []
        result = client.post("/api/v1/investigate", json=scope).json()
        assert all(e["source"] == "sysmon" for e in result["evidence"])
        assert result["warnings"]
        job = client.post("/api/v1/investigations", json=scope).json()["investigation_id"]
        assert client.post(f"/api/v1/investigations/{job}/cancel").json()["status"] == "cancelled"
        assert client.get(f"/api/v1/investigations/{job}/report").status_code == 409
