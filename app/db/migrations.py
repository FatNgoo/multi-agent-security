"""Versioned additive migrations for the v0.4 SQLite/PostgreSQL schema."""
from sqlalchemy import inspect, text, select, update


def migrate(connection, metadata):
    if connection.dialect.name == "postgresql":
        connection.execute(text("SELECT pg_advisory_xact_lock(72419421)"))
    metadata.create_all(connection)
    connection.execute(text(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version VARCHAR(32) PRIMARY KEY, applied_at VARCHAR(40) NOT NULL)"
    ))
    additions = {
        "datasets": {"sha256": "VARCHAR(64)", "metadata_json": "JSON"},
        "events": {"normalized": "JSON", "source_ip": "VARCHAR(45)",
                   "dest_ip": "VARCHAR(45)", "process_guid": "VARCHAR(128)"},
    }
    for table, columns in additions.items():
        existing = {column["name"] for column in inspect(connection).get_columns(table)}
        for name, sql_type in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
    for table, columns in {"datasets": ["sha256"], "events": ["source_ip", "dest_ip", "process_guid"]}.items():
        for name in columns:
            connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_{name} ON {table} ({name})"))
    from app.core.time import iso, utcnow
    if not connection.scalar(text("SELECT version FROM schema_migrations WHERE version='0002_multisource'")):
        from app.data.normalize import normalize_sysmon
        events, datasets = metadata.tables["events"], metadata.tables["datasets"]
        while True:
            rows = connection.execute(select(events.c.id, events.c.raw).join(datasets, events.c.dataset_id == datasets.c.id)
                                      .where(events.c.normalized.is_(None), datasets.c.source == "sysmon").limit(500)).all()
            if not rows:
                break
            for identifier, raw in rows:
                try:
                    normalized = normalize_sysmon(raw)
                except ValueError:
                    # Legacy JSONL allowed arbitrary optional fields; retain raw evidence unchanged.
                    normalized = {}
                connection.execute(update(events).where(events.c.id == identifier).values(
                    normalized=normalized, source_ip=normalized.get("source_ip"),
                    dest_ip=normalized.get("dest_ip"), process_guid=normalized.get("process_guid")))
        connection.execute(text(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (:version, :at)"
        ), {"version": "0002_multisource", "at": iso(utcnow())})
