"""Reproducible synthetic evaluation through the public API in an isolated database."""
from scripts.paths import ARTIFACTS
import argparse
import json
import os
import tempfile
import importlib.metadata
import logging
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from scripts.scenarios import scenario, jsonl


def run_case(client, case, strategy, mode):
    records = scenario(case)
    ids = []
    for source, rows in records.items():
        response = client.post("/api/v1/logs/upload", data={"source_type": source},
                               files={"file": (f"synthetic-{case}-{source}.jsonl", jsonl(rows))})
        response.raise_for_status()
        ids.append(response.json()["dataset_id"])
    scope = {"dataset_ids": ids, "host": "WIN-LAB-01", "strategy": strategy, "mode": mode,
             "start_time": "2026-10-14T08:00:00Z", "end_time": "2026-10-14T09:00:00Z",
             "host_mappings": [{"host": "WIN-LAB-01", "ip": "192.0.2.10", "start_time": "2026-10-14T08:00:00Z",
                                "end_time": "2026-10-14T09:00:00Z"}],
             "benign_destinations": ["198.51.100.20"] if case == "benign" else []}
    response = client.post("/api/v1/investigate", json=scope)
    response.raise_for_status()
    result = response.json()
    expected_rules = {"combined": {"run_key", "periodic_connection"}, "ambiguous": {"run_key", "periodic_connection"},
                      "benign": {"periodic_connection"}, "negative": set()}[case]
    predicted = {f["rule_id"] for f in result["findings"]}
    by_id = {e["evidence_id"]: e for e in result["evidence"]}
    refs = [ref for f in result["findings"] + result["relationships"] for ref in f["evidence_ids"]]
    refs += [ref for a in result["assessments"] if a.get("assessment") for ref in a["assessment"]["evidence_ids"]]
    relevant = set()
    if case != "negative":
        relevant.update(("zeek_conn", i) for i in range(1, len(records["zeek_conn"]) + 1))
        relevant.update(("sysmon", i) for i, raw in enumerate(records["sysmon"], 1) if raw["event_id"] in {3, 13})
    recovered = {(by_id[ref]["source"], by_id[ref]["record_index"]) for ref in refs if ref in by_id}
    true_positive = len(predicted & expected_rules)
    precision = true_positive / len(predicted) if predicted else None
    recall = true_positive / len(expected_rules) if expected_rules else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    expected_severity = {"combined": "high", "ambiguous": "medium", "benign": "low", "negative": "unknown"}[case]
    expected_relationship = {"combined": "supported_correlation", "ambiguous": "hypothesis", "benign": None, "negative": None}[case]
    relationships = {r["type"] for r in result["relationships"]}
    return {"case": case, "strategy": strategy, "mode": result["mode"], "investigation_id": result["investigation_id"],
            "finding_unit": "distinct deterministic rule_id per scenario",
            "rules_expected": sorted(expected_rules), "rules_observed": sorted(predicted), "rule_set_exact": predicted == expected_rules,
            "finding_precision": precision, "finding_recall": recall, "finding_f1": f1,
            "evidence_validity": sum(ref in by_id for ref in refs) / len(refs) if refs else None,
            "evidence_completeness": len(recovered & relevant) / len(relevant) if relevant else None,
            "severity": result["risk"]["severity"], "severity_match": result["risk"]["severity"] == expected_severity,
            "relationship_match": expected_relationship in relationships if expected_relationship else not relationships,
            "unsupported_claim_rate": None, "semantic_claim_review": "Requires analyst-labeled claim annotations",
            "runtime_ms": result["timings"]["total_ms"], "detection_to_alert_ms": result["timings"]["detection_to_alert_ms"],
            "tool_calls": len(result["timings"]["tool_trace"]), "llm_calls": result["timings"]["llm_calls"],
            "tokens": result["timings"]["tokens"], "provider_assessments": result["assessments"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["offline", "gemini", "deepseek"], default="offline")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", default=str(ARTIFACTS / "evaluation.json"))
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    directory = Path(tempfile.mkdtemp(prefix="multi-agent-evaluation-"))
    os.environ["DATABASE_URL"] = "sqlite:///" + (directory / "evaluation.db").as_posix()
    os.environ["WORKER_ENABLED"] = "false"
    os.environ["AGENT_MODE"] = "offline"
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings
    from app.tools.attack import CORPUS_VERSION
    from app.services.risk import RUBRIC_VERSION
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    logging.getLogger("app.tools.shared").setLevel(logging.WARNING)
    rows = []
    with TestClient(app) as client:
        for iteration in range(args.runs):
            for case in ("combined", "ambiguous", "benign", "negative"):
                for strategy in ("heuristic", "single_agent", "multi_agent"):
                    row = run_case(client, case, strategy, args.mode)
                    row["run"] = iteration + 1
                    rows.append(row)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"created_at": datetime.now(timezone.utc).isoformat(), "data_origin": "synthetic labeled lab simulation",
              "configuration": {"mode": args.mode, "model": getattr(settings, f"{args.mode}_model", None),
                                "corpus_version": CORPUS_VERSION, "rubric_version": RUBRIC_VERSION,
                                "max_records": settings.max_records, "max_tool_calls": settings.max_tool_calls,
                                "max_llm_calls": settings.max_llm_calls, "max_llm_tokens": settings.max_llm_tokens},
              "packages": {name: importlib.metadata.version(name) for name in ("fastapi", "langgraph", "openai", "sqlalchemy", "pydantic")},
              "database": str(directory / "evaluation.db"), "runs_per_case_strategy": args.runs,
              "limitations": ["Same deterministic detection and verification substrate in all strategies.",
                              "Offline runs do not evaluate LLM quality or multi-agent superiority.",
                              "Semantic unsupported-claim rate needs analyst annotation.",
                              "Synthetic severity agreement is not real-world detection accuracy."],
              "summary": {"evaluations": len(rows), "rule_set_matches": sum(r["rule_set_exact"] for r in rows),
                          "severity_matches": sum(r["severity_match"] for r in rows),
                          "relationship_matches": sum(r["relationship_match"] for r in rows),
                          "median_runtime_ms": median(r["runtime_ms"] for r in rows)}, "results": rows}
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report["summary"]))
    print(f"Saved {output.resolve()}")


if __name__ == "__main__":
    main()
