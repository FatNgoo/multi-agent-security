"""Check legacy-schema migration in an isolated PostgreSQL schema."""
import json
import re
from uuid import uuid4
from sqlalchemy import text
from app.db.database import engine, Base
from app.db import models
from app.db.migrations import migrate


def main():
    if engine.dialect.name != "postgresql":
        raise RuntimeError("Run against the PostgreSQL verification stack")
    schema = "migration_check_" + uuid4().hex[:12]
    assert re.fullmatch(r"migration_check_[a-f0-9]{12}", schema)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
        connection.execute(text("CREATE TABLE datasets (id VARCHAR(36) PRIMARY KEY, filename VARCHAR(255), source VARCHAR(20), total_records INTEGER, created_at TIMESTAMPTZ)"))
        connection.execute(text("CREATE TABLE events (id VARCHAR(36) PRIMARY KEY, dataset_id VARCHAR(36), record_index INTEGER, timestamp TIMESTAMPTZ, host VARCHAR(128), event_id INTEGER, description VARCHAR(2000), raw JSON)"))
        connection.execute(text("INSERT INTO datasets VALUES ('legacy', 'lab.jsonl', 'sysmon', 1, '2026-10-14T08:00:00Z')"))
        connection.execute(text("INSERT INTO events VALUES ('original-evidence', 'legacy', 1, '2026-10-14T08:00:00Z', 'HOST', 3, 'synthetic legacy', :raw)"),
                           {"raw": json.dumps({"source_ip": "192.0.2.10", "process_guid": "LAB-GUID"})})
        migrate(connection, Base.metadata)
        migrate(connection, Base.metadata)
        assert connection.scalar(text("SELECT process_guid FROM events WHERE id='original-evidence'")) == "LAB-GUID"
        assert connection.scalar(text("SELECT source_ip FROM events WHERE id='original-evidence'")) == "192.0.2.10"
        assert connection.scalar(text("SELECT count(*) FROM schema_migrations")) == 1
        connection.execute(text('SET LOCAL search_path TO public'))
        connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    print("PASS PostgreSQL legacy migration, backfill, evidence preservation and idempotence")


if __name__ == "__main__":
    main()
