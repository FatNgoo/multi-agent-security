"""One bounded, real-provider experiment using synthetic logs in a temporary DB."""
import argparse
import json
import os
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["gemini", "deepseek"], default="gemini")
    parser.add_argument("--output", default="artifacts/provider-smoke.json")
    parser.add_argument("--model", help="Explicit model override for this isolated experiment")
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="multi-agent-provider-"))
    os.environ["DATABASE_URL"] = "sqlite:///" + (directory / "provider.db").as_posix()
    os.environ["WORKER_ENABLED"] = "false"
    if args.model:
        os.environ[f"{args.mode.upper()}_MODEL"] = args.model
    from fastapi.testclient import TestClient
    from app.api.main import app
    from app.core.config import settings
    from app.knowledge.attack import CORPUS_VERSION
    from evaluation.run import run_case
    with TestClient(app) as client:
        result = run_case(client, "combined", "multi_agent", args.mode)
    result["database"] = str(directory / "provider.db")
    result["model"] = getattr(settings, f"{args.mode}_model")
    result["corpus_version"] = CORPUS_VERSION
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"mode": result["mode"], "model": result["model"], "runtime_ms": result["runtime_ms"],
                      "llm_calls": result["llm_calls"], "tokens": result["tokens"],
                      "statuses": [{"agent": a["agent"], "status": a["status"], "error": a.get("error")}
                                   for a in result["provider_assessments"]]}))


if __name__ == "__main__":
    main()
