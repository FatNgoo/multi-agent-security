"""Read-only tools with immutable server-side dataset/host/IP/time scope."""
import logging
import time
from collections import defaultdict
from statistics import mean, median, pstdev
from sqlalchemy import and_, or_, select, func
from app.config import settings
from app.common import iso
from app.ingestion.normalize import normalize_sysmon
from app.db.database import SessionLocal
from app.db.models import Dataset, Event, event_source

logger = logging.getLogger(__name__)


class BudgetExceeded(RuntimeError):
    pass


class Cancelled(RuntimeError):
    pass


def serialize_event(event, source: str) -> dict:
    normalized = event.normalized if event.normalized is not None else (normalize_sysmon(event.raw) if source == "sysmon" else {})
    return {**event.raw, "evidence_id": event.id, "dataset_id": event.dataset_id,
            "source": source, "timestamp": iso(event.timestamp), "host": event.host,
            "event_id": event.event_id, "description": event.description,
            "normalized": normalized, "raw": event.raw, "record_index": event.record_index}


class SharedTools:
    def __init__(self, request, check_cancel=None, progress=None):
        self.request = request
        self.started = time.monotonic()
        self.check_cancel = check_cancel or (lambda: False)
        self.progress = progress or (lambda name: None)
        self.trace = []
        self.calls = 0
        self.cache = None
        self.coverage = {}
        self.tokens = {"prompt": 0, "completion": 0}
        self.llm_calls = 0

    def checkpoint(self):
        if self.check_cancel():
            raise Cancelled("Investigation cancelled")
        if self.remaining() <= 0:
            raise BudgetExceeded("Investigation deadline reached")

    def remaining(self):
        return settings.investigation_timeout_seconds - (time.monotonic() - self.started)

    def run(self, agent: str, tool: str, **arguments):
        self.checkpoint()
        if self.calls >= settings.max_tool_calls:
            raise BudgetExceeded("Tool call budget reached")
        self.calls += 1
        self.progress(agent)
        start = time.monotonic()
        result = self._dispatch(tool, **arguments)
        entry = {"agent": agent, "tool": tool, "runtime_ms": round((time.monotonic() - start) * 1000, 3),
                 "result_count": len(result) if isinstance(result, list) else 1}
        self.trace.append(entry)
        logger.info("investigation_tool", extra={"tool_trace": entry})
        self.checkpoint()
        return result

    def _dispatch(self, tool, **arguments):
        if tool == "query_events":
            source = arguments.get("source", "all")
            if source not in {"all", "sysmon", "zeek_conn", "zeek_dns", "zeek_http", "windows_event", "web_access"}:
                raise ValueError("Unsupported source filter")
            return [event for event in self.events() if source == "all" or event["source"] == source]
        if tool == "beacon_statistics":
            return self.beacons()
        if tool == "process_tree":
            nodes = [{"evidence_id": e["evidence_id"], "host": e["host"], **e["normalized"]}
                     for e in self.events() if e["source"] == "sysmon" and e["event_id"] == 1]
            by_guid = defaultdict(list)
            for node in nodes:
                if node.get("process_guid"):
                    by_guid[(node["host"], node["process_guid"])].append(node["evidence_id"])
            for node in nodes:
                node["parent_evidence_ids"] = by_guid.get((node["host"], node.get("parent_process_guid")), [])
            return nodes
        if tool == "attack_lookup":
            from app.tools.attack import lookup
            return lookup(arguments.get("query", "persistence command control"))
        raise ValueError("Unsupported tool")

    def conditions(self):
        request = self.request
        bounds = [Event.dataset_id.in_(request.dataset_ids),
                  Event.timestamp >= request.start_time, Event.timestamp <= request.end_time]
        targets = []
        if request.host:
            targets.append(and_(event_source.in_(("sysmon", "windows_event")), Event.host == request.host))
            for mapping in request.host_mappings:
                if mapping.host == request.host:
                    targets.append(and_(Event.timestamp >= mapping.start_time, Event.timestamp <= mapping.end_time,
                                        or_(Event.source_ip == str(mapping.ip), Event.dest_ip == str(mapping.ip))))
        if request.ip:
            ip_filter = or_(Event.source_ip == str(request.ip), Event.dest_ip == str(request.ip))
            if targets:
                # Host+IP is an intersection for mapped network records; host process records remain relevant.
                targets = [and_(or_(*targets), or_(event_source.in_(("sysmon", "windows_event")), ip_filter))]
            else:
                targets.append(ip_filter)
        if targets:
            bounds.append(or_(*targets))
        return bounds

    def events(self):
        if self.cache is not None:
            return self.cache
        self.checkpoint()
        with SessionLocal() as db:
            base = select(Event, event_source).join(Dataset).where(*self.conditions())
            total = db.scalar(select(func.count()).select_from(base.subquery()))
            # Cap each source independently so a large endpoint dataset cannot hide network evidence.
            rows = []
            sources = db.scalars(select(event_source).select_from(Event).join(Dataset).where(*self.conditions()).distinct()).all()
            per_source = max(1, settings.max_records // max(1, len(sources)))
            for source in sources:
                rows.extend(db.execute(base.where(event_source == source)
                            .order_by(Event.timestamp, Event.id).limit(per_source)).all())
            self.cache = sorted([serialize_event(e, source) for e, source in rows],
                                key=lambda e: (e["timestamp"], e["evidence_id"]))
        self.coverage = {"matching_records": total, "returned_records": len(self.cache),
                         "truncated": total > len(self.cache), "record_limit": settings.max_records,
                         "sampling": "earliest records per source", "per_source_limit": per_source}
        return self.cache

    def beacons(self):
        groups = defaultdict(list)
        for event in self.events():
            n = event["normalized"]
            if event["source"] == "zeek_conn":
                groups[(n.get("source_ip"), n.get("dest_ip"), n.get("dest_port"), n.get("protocol"))].append(event)
        results = []
        for (source_ip, dest_ip, port, protocol), events in groups.items():
            self.checkpoint()
            events = sorted(events, key=lambda event: event["timestamp"])
            from datetime import datetime
            times = [datetime.fromisoformat(e["timestamp"]).timestamp() for e in events]
            intervals = [b - a for a, b in zip(times, times[1:])]
            avg = mean(intervals) if intervals else 0
            cv = pstdev(intervals) / avg if avg > 0 else None
            periodic = len(events) >= settings.beacon_min_connections and cv is not None and cv <= settings.beacon_max_cv
            results.append({"source_ip": source_ip, "dest_ip": dest_ip, "dest_port": port, "protocol": protocol,
                            "count": len(events), "mean_interval_seconds": avg,
                            "median_interval_seconds": median(intervals) if intervals else None,
                            "jitter_cv": cv, "span_seconds": times[-1] - times[0],
                            "periodic": periodic, "benign_context": dest_ip in [str(ip) for ip in self.request.benign_destinations],
                            "evidence_ids": [e["evidence_id"] for e in events]})
        return results
