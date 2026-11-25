"""Parse Windows Event Viewer Sysmon XML exports (single Event or Events root)."""
from datetime import datetime
from defusedxml import ElementTree as ET
from pydantic import ValidationError
from app.ingestion.sysmon_parser import SysmonRecord

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _tag_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element, name: str):
    return next((e for e in element if _tag_name(e.tag) == name), None)


def _field_text(parent, name: str):
    element = _child(parent, name) if parent is not None else None
    return (element.text or "").strip() if element is not None else ""


def parse_sysmon_xml(data: bytes) -> list[tuple[int, SysmonRecord, dict]]:
    """Return (1-based position, normalized record, original structured fields)."""
    try:
        root = ET.fromstring(data, forbid_dtd=True)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError(f"Invalid Windows Event XML: {exc}") from exc

    root_name = _tag_name(root.tag)
    if root_name == "Event":
        events = [root]
    elif root_name == "Events":
        events = [element for element in root if _tag_name(element.tag) == "Event"]
    else:
        raise ValueError("Expected an Event or Events XML root")
    if not events:
        raise ValueError("XML contains no Event records")

    results = []
    for position, event in enumerate(events, start=1):
        system = _child(event, "System")
        if system is None:
            raise ValueError(f"Event {position}: missing System section")
        provider = _child(system, "Provider")
        provider_name = provider.attrib.get("Name", "") if provider is not None else ""
        if "sysmon" not in provider_name.lower():
            raise ValueError(f"Event {position}: Provider is not Sysmon ({provider_name or 'missing'})")
        event_id = _field_text(system, "EventID")
        host = _field_text(system, "Computer")
        created = _child(system, "TimeCreated")
        system_time = created.attrib.get("SystemTime", "") if created is not None else ""
        time_value = system_time
        # TimeCreated uses UTC Z on Windows, with up to 7 fractional digits.
        if time_value.endswith("Z"):
            time_value = time_value[:-1] + "+00:00"
        if not time_value:
            raise ValueError(f"Event {position}: missing TimeCreated SystemTime")
        try:
            timestamp = datetime.fromisoformat(time_value)
        except ValueError as exc:
            raise ValueError(f"Event {position}: invalid timestamp") from exc

        eventdata = _child(event, "EventData")
        fields = {}
        if eventdata is not None:
            for element in eventdata:
                if _tag_name(element.tag) == "Data":
                    key = element.attrib.get("Name", "")
                    if key:
                        fields[key] = element.text or ""

        # Short, explanatory summary, without inventing any malicious label.
        important = ("Image", "TargetObject", "Details", "CommandLine", "ParentImage", "DestinationIp")
        summary = "; ".join(f"{k}={fields[k]}" for k in important if fields.get(k))
        description = (f"Sysmon Event ID {event_id}" + (f": {summary}" if summary else ""))[:2000]
        try:
            record = SysmonRecord.model_validate({
                "timestamp": timestamp, "host": host, "event_id": int(event_id),
                "description": description,
            })
        except (ValueError, ValidationError) as exc:
            raise ValueError(f"Event {position}: incomplete or invalid Sysmon fields: {exc}") from exc
        raw = {
            "format": "windows_event_xml", "provider": provider_name,
            "event_id": record.event_id, "computer": host,
            "event_record_id": _field_text(system, "EventRecordID") or None,
            "channel": _field_text(system, "Channel") or None,
            "time_created": system_time, "event_data": fields,
        }
        results.append((position, record, raw))
    return results
