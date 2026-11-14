import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from uuid import uuid4
from sqlalchemy import select, update, func, text
from app.analysis.risk import SEVERITY_ORDER
from app.core.config import settings
from app.core.time import iso, utcnow, utc
from app.db.database import SessionLocal
from app.db.models import Dataset, Investigation, Finding, Alert
from app.schemas.investigation import InvestigationRequest
from app.tools.shared import SharedTools, BudgetExceeded, Cancelled
from app.workflows.investigation_graph import investigation_graph

logger = logging.getLogger(__name__)
TERMINAL = {"completed", "failed", "cancelled", "timed_out"}


def create_job(request, owner=None):
    mode = "offline" if request.strategy == "heuristic" else request.mode or settings.agent_mode
    if mode not in {"offline", "gemini", "deepseek"}:
        raise ValueError("Invalid AGENT_MODE configuration")
    with SessionLocal.begin() as db:
        if db.bind.dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        elif db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(72419422)"))
        found = db.scalars(select(Dataset.id).where(Dataset.id.in_(request.dataset_ids))).all()
        if set(found) != set(request.dataset_ids):
            raise LookupError("Dataset not found")
        pending = db.scalar(select(func.count()).select_from(Investigation).where(Investigation.status.in_(["queued", "running"])))
        if pending >= settings.max_pending_jobs:
            raise OverflowError("Investigation queue is full")
        identifier = str(uuid4())
        snapshot = {"mode": mode, "strategy": request.strategy,
                    "model": getattr(settings, f"{mode}_model", None),
                    "max_records": settings.max_records, "max_tool_calls": settings.max_tool_calls,
                    "deadline_seconds": settings.investigation_timeout_seconds,
                    "max_agent_iterations": settings.max_agent_iterations,
                    "beacon_min_connections": settings.beacon_min_connections,
                    "beacon_max_cv": settings.beacon_max_cv}
        db.add(Investigation(id=identifier, status="running" if owner else "queued", request=request.model_dump(mode="json"),
                             config_snapshot=snapshot, progress="starting" if owner else "queued", created_at=utcnow(),
                             worker_id=owner, started_at=utcnow() if owner else None,
                             lease_until=utcnow() + timedelta(seconds=settings.investigation_timeout_seconds + 60) if owner else None))
    return identifier


def claim_job(identifier, owner):
    now = utcnow()
    with SessionLocal.begin() as db:
        changed = db.execute(update(Investigation).where(Investigation.id == identifier, Investigation.status == "queued")
                             .values(status="running", worker_id=owner, started_at=now, progress="starting",
                                     lease_until=now + timedelta(seconds=settings.lease_seconds))).rowcount
    return changed == 1


def run_claimed_job(identifier, owner):
    with SessionLocal() as db:
        job = db.get(Investigation, identifier)
        request = InvestigationRequest.model_validate(job.request)
        mode = job.config_snapshot["mode"]

    def cancelled():
        with SessionLocal() as db:
            job = db.get(Investigation, identifier)
            return job is None or job.status != "running" or job.worker_id != owner

    def progress(name):
        with SessionLocal.begin() as db:
            db.execute(update(Investigation).where(Investigation.id == identifier, Investigation.status == "running",
                                                 Investigation.worker_id == owner).values(progress=name))

    tools = SharedTools(request, cancelled, progress)
    try:
        state = investigation_graph.invoke({"tools": tools, "mode": mode}, {"recursion_limit": 16})
        tools.checkpoint()
        findings, events = state["findings"], tools.events()
        warnings = []
        if mode == "offline":
            warnings.append("OFFLINE: deterministic investigation; no LLM was called.")
        if not events:
            warnings.append("Insufficient evidence: no records match the requested scope.")
        if tools.coverage["truncated"]:
            warnings.append("Evidence coverage is partial: record limit reached. Narrow the time window or datasets.")
        if len(state["relationships"]) >= 500:
            warnings.append("Relationship presentation reached its 500-link cap; narrow the investigation scope.")
        if request.host and not request.ip and not request.host_mappings:
            warnings.append("Host scope has no explicit IP mapping. Zeek events cannot be attributed to this host.")
        if any(a["status"] not in {"completed", "offline"} for a in state["assessments"]):
            warnings.append("Some provider assessments were unavailable or incomplete; inspect assessment statuses.")
        result = {
            "investigation_id": identifier, "status": "completed", "route": state["route"],
            "dataset_id": request.dataset_id or request.dataset_ids[0], "dataset_ids": request.dataset_ids,
            "host": request.host, "scope": request.model_dump(mode="json"), "mode": mode,
            "strategy": request.strategy, "summary": f"{len(findings)} findings from {len(events)} scoped records. Overall triage: {state['risk']['severity']}.",
            "evidence": events, "findings": findings, "relationships": state["relationships"],
            "risk": state["risk"], "assessments": state["assessments"], "plan": state["plan"],
            "process_tree": state["process_tree"],
            "coverage": tools.coverage, "warning": " ".join(warnings) or None,
            "warnings": warnings, "verification": {"evidence_validity": 1.0 if findings else None,
                                                       "checked_findings": len(findings), "status": "passed"},
            "timeline": [{key: event.get(key) for key in ("timestamp", "source", "host", "description", "evidence_id", "dataset_id")}
                         for event in events],
            "tool_trace": [f"{t['agent']}/{t['tool']}: {t['result_count']} results in {t['runtime_ms']} ms" for t in tools.trace],
            "timings": {"analysis_ms": round((time.monotonic() - tools.started) * 1000, 3),
                        "tool_trace": tools.trace, "llm_calls": tools.llm_calls, "tokens": tools.tokens,
                        "detected_at": state["detected_at"], "alert_created_at": None, "detection_to_alert_ms": None},
        }
        with SessionLocal.begin() as db:
            if db.bind.dialect.name == "sqlite":
                db.execute(text("BEGIN IMMEDIATE"))
            job = db.scalar(select(Investigation).where(Investigation.id == identifier).with_for_update())
            if job.status != "running" or job.worker_id != owner:
                return
            job.finished_at = utcnow()
            result["timings"].update(started_at=iso(job.started_at), finished_at=iso(job.finished_at),
                                      total_ms=round((utc(job.finished_at) - utc(job.started_at)).total_seconds() * 1000, 3))
            confidence_order = {"low": 0, "medium": 1, "high": 2}
            eligible = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER[settings.alert_min_severity]
                        and confidence_order[f["confidence"]] >= confidence_order[settings.alert_min_confidence]]
            if eligible:
                created = utcnow()
                detected = datetime.fromisoformat(state["detected_at"])
                latency = max(0, (created - detected).total_seconds() * 1000)
                alert_severity = max((f["severity"] for f in eligible), key=SEVERITY_ORDER.get)
                confidence = max((f["confidence"] for f in eligible if f["severity"] == alert_severity), key=confidence_order.get)
                db.add(Alert(id=str(uuid4()), investigation_id=identifier, severity=alert_severity,
                             confidence=confidence, status="new", detected_at=detected, created_at=created,
                             detection_to_alert_ms=latency, history=[]))
                result["timings"].update(alert_created_at=iso(created), detection_to_alert_ms=round(latency, 3))
            job.status, job.progress, job.result, job.lease_until = "completed", "completed", result, None
            for item in findings:
                db.add(Finding(id=item["id"], investigation_id=identifier, payload=item))
    except Exception as exc:
        status = "cancelled" if isinstance(exc, Cancelled) else "timed_out" if isinstance(exc, BudgetExceeded) else "failed"
        logger.exception("investigation_failed", extra={"investigation_id": identifier})
        with SessionLocal.begin() as db:
            db.execute(update(Investigation).where(Investigation.id == identifier, Investigation.status == "running",
                                                 Investigation.worker_id == owner)
                       .values(status=status, progress=status, error=f"{type(exc).__name__}: {str(exc)[:300]}",
                               finished_at=utcnow(), lease_until=None))


class JobWorker:
    """Database queue with atomic claims and renewable leases across API processes."""
    def __init__(self):
        self.owner = str(uuid4())
        self.stop_event = threading.Event()
        self.thread = None
        self.executor = None

    def start(self):
        if not settings.worker_enabled:
            return
        self.executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_jobs, thread_name_prefix="investigation")
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        active = {}
        while not self.stop_event.is_set():
            try:
                active = {key: future for key, future in active.items() if not future.done()}
                now = utcnow()
                with SessionLocal.begin() as db:
                    db.execute(update(Investigation).where(Investigation.status == "running", Investigation.lease_until < now)
                               .values(status="failed", progress="interrupted", error="Worker lease expired; rerun investigation",
                                       finished_at=now, lease_until=None))
                    if active:
                        db.execute(update(Investigation).where(Investigation.id.in_(active), Investigation.worker_id == self.owner,
                                                             Investigation.status == "running")
                                   .values(lease_until=now + timedelta(seconds=settings.lease_seconds)))
                    candidates = db.scalars(select(Investigation.id).where(Investigation.status == "queued")
                                            .order_by(Investigation.created_at).limit(settings.max_concurrent_jobs - len(active))).all()
                for identifier in candidates:
                    if claim_job(identifier, self.owner):
                        active[identifier] = self.executor.submit(run_claimed_job, identifier, self.owner)
            except Exception:
                logger.exception("worker_tick_failed")
            self.stop_event.wait(0.5)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
