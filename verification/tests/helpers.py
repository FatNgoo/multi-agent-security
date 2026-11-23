"""Shared API test helpers."""
from scripts.scenarios import scenario, jsonl


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


