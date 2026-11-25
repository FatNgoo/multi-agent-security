"""Verify local testcase logs through the real API, including offline investigation."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import requests
from scripts.paths import ARTIFACTS
from scripts.target import VERIFICATION_API, require_verification_api


def checked(response):
    response.raise_for_status()
    return response.json()


def verify_file(http, api, path, native_count=None):
    def post_file(endpoint):
        with path.open("rb") as fh:
            return checked(http.post(f"{api}/api/v1/logs/{endpoint}", files={"file": (path.name, fh)},
                                     data={"source_type": "auto", "reuse_existing": "true"}, timeout=240))
    preview = post_file("preview")
    with path.open("rb") as fh:
        assert hashlib.file_digest(fh, "sha256").hexdigest() == preview["sha256"]
    if native_count is not None:
        assert preview["records"] == native_count, (path.name, native_count, preview["records"])
    saved = post_file("upload")
    assert saved["sha256"] == preview["sha256"]
    scope = dict(dataset_id=saved["dataset_id"], start_time=preview["start_time"], end_time=preview["end_time"])
    page = http.get(f"{api}/api/v1/events", params={**scope, "limit": 1}, timeout=30)
    first = checked(page)[0]
    assert int(page.headers["X-Total-Count"]) == preview["records"]
    evidence = checked(http.get(f"{api}/api/v1/evidence/{first['evidence_id']}", timeout=30))
    assert evidence["dataset_id"] == scope["dataset_id"] and evidence["raw"] == first["raw"]
    result = checked(http.post(f"{api}/api/v1/investigate", json={**scope, "mode": "offline"}, timeout=240))
    assert result["status"] == "completed" and result["coverage"]["matching_records"] == preview["records"]
    assert result["timings"]["llm_calls"] == 0
    return {"records": preview["records"], "sources": preview["source_counts"], "missing_timezone": preview["missing_timezone"],
            "sha256": preview["sha256"], "dataset_id": saved["dataset_id"], "investigation_id": result["investigation_id"],
            "reviewed": result["coverage"]["returned_records"], "findings": len(result["findings"]),
            "route": result["route"], "severity": result["risk"]["severity"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default=VERIFICATION_API)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[2] / "testcase")
    parser.add_argument("--windows-counts", type=Path, help="JSON map of filenames to Get-WinEvent counts")
    parser.add_argument("--output", type=Path, default=ARTIFACTS / "downloaded-logs.json")
    args = parser.parse_args()
    require_verification_api(args.api_url)
    root = args.directory.resolve(strict=True)
    counts = json.loads(args.windows_counts.read_text(encoding="utf-8-sig")) if args.windows_counts else {}
    results = {}
    paths = [p for p in sorted(root.rglob("*")) if p.is_file() and p.suffix.lower() in
             (".evtx", ".json", ".jsonl", ".txt", ".log", ".tsv", ".xml", ".pcap")]
    if not paths:
        raise SystemExit("No testcase logs found")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with requests.Session() as http, TemporaryDirectory() as temp:
        for i, path in enumerate(paths):
            name = path.relative_to(root).as_posix()
            try:
                if path.suffix.lower() == ".pcap":
                    dest = Path(temp, str(i))
                    dest.mkdir()
                    subprocess.run(["docker", "run", "--rm", "--network", "none", "--mount",
                                    f"type=bind,source={path},target=/capture.pcap,readonly", "--mount",
                                    f"type=bind,source={dest},target=/out", "-w", "/out", "zeek/zeek:lts",
                                    "zeek", "-C", "-r", "/capture.pcap", "LogAscii::use_json=T"], check=True, timeout=180)
                    derived = {p.name: verify_file(http, args.api_url, p) for p in sorted(dest.glob("*.log"))
                               if p.name in ("conn.log", "dns.log", "http.log")}
                    assert derived, "PCAP produced no supported Zeek logs"
                    results[name] = {"zeek": derived}
                else:
                    native = counts[path.name] if args.windows_counts and path.suffix.lower() == ".evtx" else None
                    results[name] = verify_file(http, args.api_url, path, native)
                print("OK", name, flush=True)
            except Exception as exc:
                results[name] = {"error": str(exc)}
                print("FAIL", name, exc, flush=True)
            args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        metrics = checked(http.get(f"{args.api_url}/api/v1/metrics", timeout=30))
        assert metrics["runtime"]["samples"] > 0
    if any("error" in r for r in results.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
