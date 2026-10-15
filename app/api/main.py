from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import FastAPI, File, HTTPException, UploadFile
from sqlalchemy import select
from app.core.config import settings
from app.data.sysmon_parser import parse_jsonl
from app.data.sysmon_xml_parser import parse_sysmon_xml
from app.db.database import SessionLocal, init_db
from app.db.models import Dataset, Event
from app.schemas.investigation import InvestigationRequest, InvestigationResponse, Evidence
from app.tools.sysmon_tools import search_sysmon_events
from app.workflows.investigation_graph import investigation_graph


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Multi-Agent Security Investigation — v0.4", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "healthy", "mode": settings.agent_mode}


@app.post("/api/v1/logs/upload", status_code=201)
async def upload_log(file: UploadFile = File(...)):
    filename = file.filename or ""
    if not filename.lower().endswith((".jsonl", ".json", ".xml")):
        raise HTTPException(status_code=415, detail="Supported Sysmon uploads: .jsonl, .json (JSON Lines), .xml (Windows Event XML)")
    data = await file.read(settings.max_upload_bytes + 1)
    await file.close()
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")
    try:
        rows = parse_sysmon_xml(data) if filename.lower().endswith(".xml") else parse_jsonl(data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    dataset_id = str(uuid4())
    with SessionLocal.begin() as db:
        db.add(Dataset(id=dataset_id, filename=filename[:255], source="sysmon",
                       total_records=len(rows), created_at=datetime.now(timezone.utc)))
        db.add_all([
            Event(id=str(uuid4()), dataset_id=dataset_id, record_index=index,
                  timestamp=record.timestamp, host=record.host,
                  event_id=record.event_id, description=record.description, raw=raw)
            for index, record, raw in rows
        ])
    return {"dataset_id": dataset_id, "filename": filename, "source": "sysmon",
            "imported_records": len(rows), "status": "completed"}


@app.get("/api/v1/datasets")
def list_datasets():
    with SessionLocal() as db:
        rows = db.scalars(select(Dataset).order_by(Dataset.created_at.desc())).all()
        return [{"dataset_id": d.id, "filename": d.filename, "source": d.source,
                 "total_records": d.total_records} for d in rows]


@app.get("/api/v1/events")
def list_events(dataset_id: str, host: str, start_time: datetime, end_time: datetime):
    try:
        return search_sysmon_events(host, start_time.isoformat(), end_time.isoformat(), dataset_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/evidence/{evidence_id}")
def get_evidence(evidence_id: str):
    with SessionLocal() as db:
        event = db.get(Event, evidence_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Evidence not found")
        return {"evidence_id": event.id, "dataset_id": event.dataset_id,
                "timestamp": event.timestamp.isoformat(), "host": event.host,
                "event_id": event.event_id, "description": event.description, "raw": event.raw}


@app.post("/api/v1/investigate", response_model=InvestigationResponse)
def investigate(request: InvestigationRequest):
    if request.start_time > request.end_time:
        raise HTTPException(status_code=422, detail="start_time must precede end_time")
    with SessionLocal() as db:
        if db.get(Dataset, request.dataset_id) is None:
            raise HTTPException(status_code=404, detail="Dataset not found")
    if settings.agent_mode not in {"offline", "deepseek", "gemini"}:
        raise HTTPException(status_code=500, detail="Invalid AGENT_MODE configuration")
    try:
        state = investigation_graph.invoke({
            "host": request.host,
            "dataset_id": request.dataset_id,
            "start_time": request.start_time.isoformat(),
            "end_time": request.end_time.isoformat(),
        })
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=502, detail="Investigation failed; check application logs")
    outcome = state["agent_result"]
    return InvestigationResponse(
        status="completed", dataset_id=request.dataset_id,
        route=state["route"], mode=outcome["mode"],
        host=request.host, summary=outcome["summary"],
        evidence=[Evidence(
            evidence_id=e["evidence_id"], timestamp=e["timestamp"],
            host=e["host"], event_id=e["event_id"],
            description=e["description"], raw=e,
        ) for e in outcome["events"]],
        tool_trace=outcome["trace"],
        warning=("OFFLINE DEMO: deterministic analysis, no LLM was called"
                 if outcome["mode"] == "offline" else None),
    )
