import copy
import json
import math
from contextlib import asynccontextmanager
from typing import Literal
from uuid import uuid4
from fastapi import FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import AwareDatetime
from sqlalchemy import select, func, text, insert
from app.config import settings
from app.common import configure_logging, iso, utcnow
from app.ingestion.upload import LogImport
from app.db.database import SessionLocal, init_db, engine
from app.db.models import Dataset, Event, event_source, Investigation, Finding, Alert, AuditEntry
from app.schemas.investigation import InvestigationRequest, InvestigationResponse
from app.schemas.domain import AlertUpdate, ReviewUpdate
from app.services.investigations import create_job, run_claimed_job, JobWorker
from app.services.reports import markdown_report
from app.services.overview import overview
from app.tools.shared import SharedTools, serialize_event
from app.services.risk import SEVERITY_ORDER
from app.tools.attack import lookup, CORPUS_VERSION

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    current_worker = JobWorker()
    current_worker.start()
    yield
    current_worker.stop()


app = FastAPI(title="Persistence and C2 Investigation", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "healthy", "environment": settings.deployment_environment,
            "mode": settings.agent_mode, "database": engine.dialect.name,
            "worker_enabled": settings.worker_enabled, "knowledge_version": CORPUS_VERSION}


LogSource = Literal["auto", "sysmon", "zeek_conn", "zeek_dns", "zeek_http", "windows_event", "web_access"]


@app.post("/api/v1/logs/preview")
def preview_log(file: UploadFile = File(...), source_type: LogSource = Form("auto")):
    upload = LogImport(file, source_type)
    source, count, meta = upload.summarize()
    sha256 = upload.sha256
    with SessionLocal() as db:
        duplicate = db.scalar(select(Dataset.id).where(Dataset.sha256 == sha256, Dataset.source == source)
                              .order_by(Dataset.created_at, Dataset.id).limit(1))
    return {"filename": upload.filename, "source": source, "records": count, "sha256": sha256,
            "source_counts": meta["source_counts"], "missing_timezone": meta["missing_timezone"],
            "start_time": meta["start_time"], "end_time": meta["end_time"], "duplicate_of": duplicate}


@app.post("/api/v1/logs/upload", status_code=201)
def upload_log(file: UploadFile = File(...), source_type: LogSource = Form("auto"),
               reuse_existing: bool = Form(False)):
    upload = LogImport(file, source_type)
    source_type, count, metadata = upload.summarize()
    filename, sha256 = upload.filename, upload.sha256
    identifier = str(uuid4())
    with SessionLocal.begin() as db:
        if reuse_existing:
            if db.bind.dialect.name == "postgresql":
                db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": int(sha256[:15], 16)})
            else:
                db.execute(text("BEGIN IMMEDIATE"))
        duplicate = db.scalar(select(Dataset.id).where(Dataset.sha256 == sha256, Dataset.source == source_type)
                              .order_by(Dataset.created_at, Dataset.id).limit(1))
        if reuse_existing and duplicate:
            return {"dataset_id": duplicate, "filename": filename, "source": source_type, "status": "reused",
                    "imported_records": 0, "sha256": sha256, "metadata": metadata}
        metadata["duplicate_of"] = duplicate
        db.add(Dataset(id=identifier, filename=filename[:255], source=source_type, total_records=count,
                       created_at=utcnow(), sha256=sha256, metadata_json=metadata))
        db.flush()
        batch = []
        for idx, ts, host, eid, description, normalized, raw, source in upload.rows():
            batch.append(dict(id=str(uuid4()), dataset_id=identifier, record_index=idx, timestamp=ts,
                              host=host, event_id=eid, description=description, raw=raw, normalized=normalized,
                              log_source=source, source_ip=normalized.get("source_ip"), dest_ip=normalized.get("dest_ip"),
                              process_guid=normalized.get("process_guid")))
            if len(batch) == 250:
                db.execute(insert(Event), batch)
                batch.clear()
        if batch:
            db.execute(insert(Event), batch)
    return {"dataset_id": identifier, "filename": filename, "source": source_type,
            "imported_records": count, "status": "completed", "sha256": sha256, "metadata": metadata}


@app.get("/api/v1/datasets")
def datasets(response: Response, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
             ids: list[str] | None = Query(None, max_length=20)):
    with SessionLocal() as db:
        criteria = (Dataset.id.in_(ids),) if ids else ()
        response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(Dataset).where(*criteria)))
        rows = db.scalars(select(Dataset).where(*criteria).order_by(Dataset.created_at.desc(), Dataset.id).offset(offset).limit(limit)).all()
        return [{"dataset_id": d.id, "filename": d.filename, "source": d.source, "total_records": d.total_records,
                 "created_at": iso(d.created_at), "sha256": d.sha256, "metadata": d.metadata_json or {}} for d in rows]


@app.get("/api/v1/events")
def events(response: Response, dataset_id: str, start_time: AwareDatetime, end_time: AwareDatetime,
           host: str | None = None, ip: str | None = None,
           limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    try:
        request = InvestigationRequest(dataset_id=dataset_id, host=host, ip=ip, start_time=start_time, end_time=end_time)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    tools = SharedTools(request)
    with SessionLocal() as db:
        if db.get(Dataset, dataset_id) is None:
            raise HTTPException(404, "Dataset not found")
        query = select(Event, event_source).join(Dataset).where(*tools.conditions())
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        response.headers["X-Total-Count"] = str(total)
        response.headers["X-Has-More"] = str(offset + limit < total).lower()
        rows = db.execute(query.order_by(Event.timestamp, Event.record_index).offset(offset).limit(limit)).all()
        return [serialize_event(e, source) for e, source in rows]


@app.get("/api/v1/evidence/{evidence_id}")
def evidence(evidence_id: str):
    with SessionLocal() as db:
        row = db.execute(select(Event, event_source).join(Dataset).where(Event.id == evidence_id)).first()
        if row is None:
            raise HTTPException(404, "Evidence not found")
        return serialize_event(*row)


def _create(request, owner=None):
    try:
        return create_job(request, owner)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except OverflowError as exc:
        raise HTTPException(429, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _job(db, identifier, lock=False):
    if lock and db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))
    query = select(Investigation).where(Investigation.id == identifier)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None:
        raise HTTPException(404, "Investigation not found")
    return row


@app.post("/api/v1/investigate", response_model=InvestigationResponse)
def investigate(request: InvestigationRequest):
    owner = str(uuid4())
    identifier = _create(request, owner)
    run_claimed_job(identifier, owner)
    with SessionLocal() as db:
        job = _job(db, identifier)
        if job.status != "completed":
            raise HTTPException(504 if job.status == "timed_out" else 502,
                                {"investigation_id": identifier, "status": job.status, "error": job.error})
        return job.result


@app.post("/api/v1/investigations", status_code=202)
def enqueue(request: InvestigationRequest):
    return {"investigation_id": _create(request), "status": "queued"}


@app.get("/api/v1/investigations")
def history(response: Response, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    with SessionLocal() as db:
        response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(Investigation)))
        rows = db.scalars(select(Investigation).order_by(Investigation.created_at.desc()).offset(offset).limit(limit)).all()
        return [{"investigation_id": j.id, "status": j.status, "progress": j.progress, "created_at": iso(j.created_at),
                 "severity": j.result["risk"]["severity"] if j.result else None, "scope": j.request} for j in rows]


@app.get("/api/v1/investigations/{identifier}")
def job_status(identifier: str):
    with SessionLocal() as db:
        job = _job(db, identifier)
        return {"investigation_id": job.id, "status": job.status, "progress": job.progress,
                "created_at": iso(job.created_at), "started_at": iso(job.started_at), "finished_at": iso(job.finished_at),
                "error": job.error, "config": job.config_snapshot, "result": job.result}


@app.post("/api/v1/investigations/{identifier}/cancel")
def cancel(identifier: str):
    with SessionLocal.begin() as db:
        job = _job(db, identifier, lock=True)
        if job.status in {"queued", "running"}:
            job.status, job.progress, job.finished_at, job.lease_until = "cancelled", "cancelled", utcnow(), None
        return {"investigation_id": identifier, "status": job.status}


@app.get("/api/v1/investigations/{identifier}/report")
def export_report(identifier: str, format: Literal["json", "markdown"] = "json"):
    with SessionLocal() as db:
        job = _job(db, identifier)
        if job.status != "completed":
            raise HTTPException(409, "Investigation result is not ready")
        if format == "markdown":
            return PlainTextResponse(markdown_report(job.result), media_type="text/markdown",
                                     headers={"Content-Disposition": f'attachment; filename="investigation-{identifier}.md"'})
        return job.result


@app.get("/api/v1/alerts")
def alerts(response: Response, status: str | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    with SessionLocal() as db:
        query = select(Alert)
        if status:
            query = query.where(Alert.status == status)
        response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(query.subquery())))
        rows = db.scalars(query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)).all()
        return [{"alert_id": a.id, "investigation_id": a.investigation_id, "severity": a.severity,
                 "confidence": a.confidence, "status": a.status, "detected_at": iso(a.detected_at),
                 "alert_created_at": iso(a.created_at), "acknowledged_at": iso(a.acknowledged_at),
                 "detection_to_alert_ms": a.detection_to_alert_ms, "history": a.history} for a in rows]


@app.patch("/api/v1/alerts/{identifier}")
def update_alert(identifier: str, request: AlertUpdate):
    with SessionLocal.begin() as db:
        if db.bind.dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        alert = db.scalar(select(Alert).where(Alert.id == identifier).with_for_update())
        if alert is None:
            raise HTTPException(404, "Alert not found")
        alert.history = [*alert.history, {**request.model_dump(), "at": iso(utcnow()), "previous_status": alert.status}]
        alert.status = request.status
        if request.status in {"acknowledged", "investigating", "closed"} and alert.acknowledged_at is None:
            alert.acknowledged_at = utcnow()
        return {"alert_id": identifier, "status": alert.status}


@app.patch("/api/v1/investigations/{identifier}/findings/{finding_id}")
def review_finding(identifier: str, finding_id: str, request: ReviewUpdate):
    with SessionLocal.begin() as db:
        job = _job(db, identifier, lock=True)
        if job.status != "completed":
            raise HTTPException(409, "Investigation result is not ready")
        result = copy.deepcopy(job.result)
        item = next((f for f in result["findings"] if f["id"] == finding_id), None)
        if item is None:
            raise HTTPException(404, "Finding not found")
        previous = {"severity": item["severity"]}
        if request.severity:
            item.update(severity=request.severity, severity_reason=f"Analyst review: {request.note}")
            result["risk"]["severity"] = max((f["severity"] for f in result["findings"]), key=SEVERITY_ORDER.get)
            result["risk"]["reason"] = "Includes analyst severity review. See audit history."
            result["summary"] = f"{len(result['findings'])} findings from {len(result['evidence'])} scoped records. Overall triage: {result['risk']['severity']}."
            alert = db.scalar(select(Alert).where(Alert.investigation_id == identifier))
            if alert:
                alert.severity = result["risk"]["severity"]
        if request.recommendation_id:
            recommendation = next((r for r in item["recommendations"] if r["id"] == request.recommendation_id), None)
            if recommendation is None:
                raise HTTPException(404, "Recommendation not found")
            if request.recommendation_status is None:
                raise HTTPException(422, "recommendation_status is required")
            previous["recommendation_status"] = recommendation["status"]
            recommendation["status"] = request.recommendation_status
        if not request.severity and not request.recommendation_id:
            raise HTTPException(422, "Supply severity or recommendation_id")
        row = db.get(Finding, finding_id)
        row.payload = item
        job.result = result
        db.add(AuditEntry(id=str(uuid4()), investigation_id=identifier, action="finding_review",
                          details={"finding_id": finding_id, "previous": previous, **request.model_dump()}, created_at=utcnow()))
        return item


@app.get("/api/v1/investigations/{identifier}/audit")
def audit(identifier: str):
    with SessionLocal() as db:
        _job(db, identifier)
        rows = db.scalars(select(AuditEntry).where(AuditEntry.investigation_id == identifier).order_by(AuditEntry.created_at)).all()
        return [{"action": a.action, "details": a.details, "created_at": iso(a.created_at)} for a in rows]


@app.get("/api/v1/knowledge")
def knowledge(query: str = Query("persistence c2", max_length=200)):
    return {"version": CORPUS_VERSION, "results": lookup(query)}


@app.get("/api/v1/overview")
def dashboard_overview(source: Literal["all", "sysmon", "zeek_conn", "zeek_dns", "zeek_http", "windows_event", "web_access"] = "all",
                       hours: int = Query(0, ge=0, le=8760)):
    with SessionLocal() as db:
        return overview(db, source, hours)


@app.get("/api/v1/metrics")
def metrics():
    with SessionLocal() as db:
        # Read scalar columns. PostgreSQL JSON traversal can fail on raw evidence containing NUL.
        timings = db.execute(select(Investigation.started_at, Investigation.finished_at, Alert.detection_to_alert_ms)
                             .outerjoin(Alert, Alert.investigation_id == Investigation.id)
                             .where(Investigation.status == "completed")
                             .order_by(Investigation.finished_at.desc(), Investigation.id).limit(1000)).all()
        latency = sorted(round(ms, 3) for _, _, ms in timings if ms is not None)
        runtime = sorted(round((end - start).total_seconds() * 1000, 3) for start, end, _ in timings
                         if start is not None and end is not None)

        def distribution(values):
            return {"samples": len(values), "p50_ms": values[math.ceil(len(values) * 0.5) - 1] if values else None,
                    "p95_ms": values[math.ceil(len(values) * 0.95) - 1] if values else None}

        return {"datasets": db.scalar(select(func.count()).select_from(Dataset)),
                "events": db.scalar(select(func.count()).select_from(Event)),
                "investigations": dict(db.execute(select(Investigation.status, func.count()).group_by(Investigation.status)).all()),
                "alerts": dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all()),
                "severity": dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()),
                "detection_to_alert": distribution(latency), "runtime": distribution(runtime),
                "sample_policy": "Latest 1000 completed investigations; alert timing ends at server alert creation."}
