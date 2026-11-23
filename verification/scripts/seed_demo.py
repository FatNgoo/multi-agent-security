"""Upload synthetic lab logs and run an offline background investigation."""
from scripts.paths import ARTIFACTS
from scripts.target import VERIFICATION_API, require_verification_api
import argparse
import json
import time
from pathlib import Path
import httpx
from scripts.scenarios import scenario, jsonl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default=VERIFICATION_API)
    parser.add_argument("--output", default=str(ARTIFACTS / "demo-result.json"))
    args = parser.parse_args()
    require_verification_api(args.api_url)
    with httpx.Client(base_url=args.api_url, timeout=20) as client:
        identifiers = []
        for source, records in scenario().items():
            response = client.post("/api/v1/logs/upload", data={"source_type": source},
                                   files={"file": (f"synthetic-{source}.jsonl", jsonl(records))})
            response.raise_for_status()
            identifiers.append(response.json()["dataset_id"])
        request = {"dataset_ids": identifiers, "host": "WIN-LAB-01", "mode": "offline",
                   "start_time": "2026-10-14T08:00:00Z", "end_time": "2026-10-14T09:00:00Z",
                   "host_mappings": [{"host": "WIN-LAB-01", "ip": "192.0.2.10", "start_time": "2026-10-14T08:00:00Z",
                                      "end_time": "2026-10-14T09:00:00Z"}]}
        response = client.post("/api/v1/investigations", json=request)
        response.raise_for_status()
        identifier = response.json()["investigation_id"]
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            response = client.get(f"/api/v1/investigations/{identifier}")
            response.raise_for_status()
            job = response.json()
            if job["status"] == "completed":
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(job["result"], indent=2, ensure_ascii=False), encoding="utf-8")
                print(json.dumps({"investigation_id": identifier, "severity": job["result"]["risk"]["severity"],
                                  "timings": job["result"]["timings"], "output": str(output)}, ensure_ascii=False))
                return
            if job["status"] in {"failed", "cancelled", "timed_out"}:
                raise RuntimeError(f"Demo investigation ended as {job['status']}: {job['error']}")
            time.sleep(0.25)
        raise TimeoutError(f"Job {identifier} did not finish; inspect the backend worker")


if __name__ == "__main__":
    main()
