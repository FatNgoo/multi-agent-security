"""Bounded aggregates over imported event time; alert counts use their own lifecycle."""
from datetime import timedelta

from sqlalchemy import BigInteger, String, cast, extract, func, select

from app.common import iso, utc
from app.db.models import Alert, Dataset, Event


def overview(db, source, hours):
    filters = [] if source == "all" else [Dataset.source == source]

    def query(*cols):
        return select(*cols).select_from(Event).join(Dataset).where(*filters)

    first, last = db.execute(query(func.min(Event.timestamp), func.max(Event.timestamp))).one()
    alerts = dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    data = dict(start=None, end=None, alerts=alerts, bins=[], sources={}, types=[], recent=[])
    if last is None:
        return data
    end = utc(last)
    start = end - timedelta(hours=hours) if hours else utc(first)
    filters.extend([Event.timestamp >= start, Event.timestamp <= end])
    span = (end - start).total_seconds()
    step = next((s for s in (1, 5, 15, 60, 300, 900, 3600, 21600, 86400, 604800) if s * 36 >= span),
                max(1, int(span // 36) + 1))
    epoch = (cast(func.strftime("%s", func.substr(cast(Event.timestamp, String), 1, 19)), BigInteger) if db.bind.dialect.name == "sqlite"
             else func.floor(extract("epoch", Event.timestamp)))
    bucket = cast(func.floor(epoch / step), BigInteger)
    bins = db.execute(query(bucket, Dataset.source, func.count()).group_by(bucket, Dataset.source).order_by(bucket)).all()
    for slot, name, count in bins:
        data["bins"].append({"ts": slot * step, "source": name, "count": count})
        data["sources"][name] = data["sources"].get(name, 0) + count
    types = db.execute(query(Dataset.source, Event.event_id, func.count()).group_by(Dataset.source, Event.event_id)
                       .order_by(func.count().desc(), Dataset.source, Event.event_id).limit(8))
    data["types"] = [{"source": name, "event_id": eid, "count": count} for name, eid, count in types]
    rows = db.execute(query(Event.id, Event.timestamp, Dataset.source, Dataset.filename, Event.host,
                            Event.event_id, Event.record_index)
                      .order_by(Event.timestamp.desc(), Event.id).limit(12))
    data["recent"] = [dict(evidence_id=eid, timestamp=iso(ts), source=name, filename=file, host=host,
                           event_id=kind, record_index=idx)
                      for eid, ts, name, file, host, kind, idx in rows]
    data.update(start=iso(start), end=iso(end), step=step)
    return data
