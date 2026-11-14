"""Validate a seeded synthetic investigation through a running HTTP stack."""
import argparse
import json
from pathlib import Path
import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--result", default="artifacts/demo-postgres.json")
    parser.add_argument("--expect-database", default="postgresql")
    parser.add_argument("--output", default="artifacts/stack-check.json")
    args = parser.parse_args()
    result = json.loads(Path(args.result).read_text(encoding="utf-8"))
    identifier = result["investigation_id"]
    with httpx.Client(base_url=args.api_url, timeout=20) as client:
        health = client.get("/health").json()
        assert health["database"] == args.expect_database, health
        stored = client.get(f"/api/v1/investigations/{identifier}").json()
        assert stored["status"] == "completed"
        assert stored["result"]["risk"]["severity"] == "high"
        for evidence in result["evidence"]:
            response = client.get(f"/api/v1/evidence/{evidence['evidence_id']}")
            response.raise_for_status()
            assert response.json()["dataset_id"] in result["dataset_ids"]
            assert response.json()["timestamp"].endswith("+00:00")
        for format in ("json", "markdown"):
            client.get(f"/api/v1/investigations/{identifier}/report", params={"format": format}).raise_for_status()
        metrics = client.get("/api/v1/metrics")
        metrics.raise_for_status()
        assert metrics.json()["detection_to_alert"]["samples"] >= 1
        alert = next(a for a in client.get("/api/v1/alerts").json() if a["investigation_id"] == identifier)
        client.patch(f"/api/v1/alerts/{alert['alert_id']}", json={"status": "acknowledged", "note": "Synthetic stack verification"}).raise_for_status()
        finding = result["findings"][0]
        client.patch(f"/api/v1/investigations/{identifier}/findings/{finding['id']}", json={
            "recommendation_id": finding["recommendations"][0]["id"], "recommendation_status": "completed",
            "note": "Synthetic stack verification"}).raise_for_status()
        assert client.get(f"/api/v1/investigations/{identifier}/audit").json()
        output = {"database": health["database"], "investigation_id": identifier, "evidence_checked": len(result["evidence"]),
                  "checks": ["background execution", "evidence resolution", "UTC", "JSON report", "Markdown report",
                             "metrics", "alert acknowledgment", "recommendation progress", "audit"], "status": "passed"}
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(json.dumps(output))


if __name__ == "__main__":
    main()
