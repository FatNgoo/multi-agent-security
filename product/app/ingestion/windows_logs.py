"""Stream EVTX and flattened Windows JSON events without executing event contents."""
import json
from datetime import datetime, timezone

from defusedxml import ElementTree as ET
from evtx import PyEvtxParser

from app.ingestion.normalize import normalize_sysmon
from app.ingestion.sysmon_xml_parser import _child, _field_text, _tag_name


def is_windows_json(row):
    return isinstance(row, dict) and all(key in row for key in ("EventID", "Hostname", "SourceName"))


def windows_row(index, provider, eid, host, ts, fields, raw):
    if not isinstance(host, str) or not host.strip() or len(host) > 128 or not provider:
        raise ValueError("missing or invalid computer/provider")
    eid = int(eid)
    if not 0 <= eid <= 65535 or ts.tzinfo is None:
        raise ValueError("invalid Windows EventID or event time")
    source = "sysmon" if provider.casefold() == "microsoft-windows-sysmon" else "windows_event"
    normalized = normalize_sysmon(fields) if source == "sysmon" else {}
    details = [str(fields[k]) for k in ("Image", "TargetObject", "TargetFilename", "DestinationIp") if fields.get(k)]
    desc = f"{provider} · ID {eid}" + (" · " + " · ".join(details) if details else "")
    return (index, ts.astimezone(timezone.utc), host, eid, desc[:2000], normalized, raw, source)


def evtx_rows(stream):
    if stream.read(8) != b"ElfFile\x00":
        raise ValueError("Chữ ký EVTX không hợp lệ.")
    stream.seek(42)
    chunks = int.from_bytes(stream.read(2), "little")
    stream.seek(0, 2)
    size = stream.tell()
    if size < 4096 + chunks * 65536:
        raise ValueError("Tệp EVTX thiếu header hoặc chunk chưa đầy đủ.")
    # Windows can preallocate a zero-filled tail after the last complete chunk.
    tail = (size - 4096) % 65536
    if tail:
        stream.seek(-tail, 2)
        if any(stream.read(tail)):
            raise ValueError("Chunk EVTX cuối tệp chưa đầy đủ.")
    stream.seek(0)
    try:
        parser = PyEvtxParser(stream, number_of_threads=1)
        for index, record in enumerate(parser.records(), 1):
            xml = record["data"]
            root = ET.fromstring(xml, forbid_dtd=True)
            system = _child(root, "System")
            provider_element = _child(system, "Provider") if system is not None else None
            if provider_element is None:
                raise ValueError(f"Event {index}: thiếu System/Provider")
            provider = provider_element.get("Name", "")
            created = _child(system, "TimeCreated")
            timestamp = created.get("SystemTime", "") if created is not None else ""
            host = _field_text(system, "Computer")
            eid = _field_text(system, "EventID")
            fields = {item.get("Name"): item.text or "" for item in root.iter()
                      if _tag_name(item.tag) == "Data" and item.get("Name")}
            raw = {"format": "windows_evtx", "provider": provider, "channel": _field_text(system, "Channel"),
                   "event_record_id": _field_text(system, "EventRecordID"), "header_record_id": record["event_record_id"],
                   "time_created": timestamp, "computer": host, "event_data": fields, "xml": xml}
            yield windows_row(index, provider, eid, host, datetime.fromisoformat(timestamp), fields, raw)
    except (ValueError, RuntimeError, OSError, OverflowError, ET.ParseError) as exc:
        raise ValueError(f"Không đọc được EVTX: {exc}") from exc


def reject_nonfinite(value):
    raise ValueError(f"invalid JSON number: {value}")


def otrf_rows(stream, stats):
    for index, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line.decode("utf-8-sig"), parse_constant=reject_nonfinite)
            if not is_windows_json(row):
                raise ValueError("expected EventID, Hostname, SourceName")
            # UtcTime is an explicitly UTC Sysmon payload time. @timestamp is the collector time.
            ts = None
            for field in ("UtcTime", "TimeCreated", "@timestamp"):
                if row.get(field):
                    ts = datetime.fromisoformat(row[field])
                    if field == "UtcTime" and ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts.tzinfo is not None:
                        break
            if ts is None:
                raise ValueError("missing event time")
            if ts.tzinfo is None:
                stats["missing_timezone"] += 1
                continue
            stats["clock_fields"][field] += 1
            yield windows_row(index, row["SourceName"], row["EventID"], row["Hostname"], ts, row, row)
        except (ValueError, TypeError, AttributeError, OverflowError) as exc:
            raise ValueError(f"Windows JSON, dòng {index}: {exc}") from exc
