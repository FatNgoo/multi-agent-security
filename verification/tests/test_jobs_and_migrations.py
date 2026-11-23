import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text, select
from app.main import app
from app.config import settings
from app.common import utcnow
from app.db.database import Base, SessionLocal
from app.db.migrations import migrate
from app.db.models import Investigation
from app.services.investigations import claim_job
from tests.helpers import upload_case


def test_worker_completes_background_job_and_recovers_expired_lease(monkeypatch):
    monkeypatch.setattr(settings, "worker_enabled", True)
    with TestClient(app) as client:
        scope = upload_case(client)
        identifier = client.post("/api/v1/investigations", json=scope).json()["investigation_id"]
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = client.get(f"/api/v1/investigations/{identifier}").json()
            if job["status"] in {"completed", "failed", "timed_out"}:
                break
            time.sleep(0.05)
        assert job["status"] == "completed", job
        assert job["result"]["risk"]["severity"] == "high"
        with SessionLocal.begin() as db:
            row = db.get(Investigation, identifier)
            row.status = "running"
            row.worker_id = "dead-worker"
            row.result = None
            row.lease_until = utcnow() - timedelta(seconds=1)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            recovered = client.get(f"/api/v1/investigations/{identifier}").json()
            if recovered["status"] == "failed":
                break
            time.sleep(0.05)
        assert recovered["status"] == "failed"
        assert "lease expired" in recovered["error"]


def test_atomic_claim_and_tool_budget(monkeypatch):
    with TestClient(app) as client:
        scope = upload_case(client)
        identifier = client.post("/api/v1/investigations", json=scope).json()["investigation_id"]
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda owner: claim_job(identifier, owner), ["worker-a", "worker-b"]))
        assert sorted(outcomes) == [False, True]
        client.post(f"/api/v1/investigations/{identifier}/cancel")
        monkeypatch.setattr(settings, "max_tool_calls", 2)
        response = client.post("/api/v1/investigate", json=scope)
        assert response.status_code == 504
        assert response.json()["detail"]["status"] == "timed_out"


def test_additive_migration_preserves_v04_records(tmp_path):
    engine = create_engine("sqlite:///" + (tmp_path / "legacy.db").as_posix())
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE datasets (id VARCHAR(36) PRIMARY KEY, filename VARCHAR(255), source VARCHAR(20), total_records INTEGER, created_at DATETIME)"))
        conn.execute(text("CREATE TABLE events (id VARCHAR(36) PRIMARY KEY, dataset_id VARCHAR(36), record_index INTEGER, timestamp DATETIME, host VARCHAR(128), event_id INTEGER, description VARCHAR(2000), raw JSON)"))
        conn.execute(text("INSERT INTO datasets VALUES ('legacy', 'original.jsonl', 'sysmon', 1, '2026-10-14 08:00:00')"))
        conn.execute(text("INSERT INTO events VALUES ('evidence-original', 'legacy', 1, '2026-10-14 08:00:00', 'HOST', 13, 'original record', '{}')"))
        migrate(conn, Base.metadata)
        migrate(conn, Base.metadata)
        assert conn.scalar(text("SELECT description FROM events WHERE id='evidence-original'")) == "original record"
        assert conn.scalar(text("SELECT count(*) FROM schema_migrations")) == 1
        assert conn.scalar(text("SELECT total_records FROM datasets WHERE id='legacy'")) == 1
    engine.dispose()
