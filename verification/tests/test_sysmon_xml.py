"""XML parser unit tests, independent of LLM and Docker."""
from pathlib import Path
import pytest
from app.ingestion.sysmon_xml_parser import parse_sysmon_xml

FIXTURE = Path(__file__).resolve().parents[1] / "logs/samples/sysmon-event-viewer.xml"


def test_event_viewer_xml_parse_and_normalize():
    rows = parse_sysmon_xml(FIXTURE.read_bytes())
    assert len(rows) == 2
    assert rows[0][1].host == "WIN-LAB-01"
    assert rows[0][1].event_id == 1
    assert rows[1][1].event_id == 13
    assert rows[0][1].timestamp.isoformat().endswith("+00:00")
    assert "Run\\Demo" in rows[1][2]["event_data"]["TargetObject"]
    assert "Registry" not in rows[1][1].description or rows[1][1].event_id == 13


def test_single_event_root():
    data = b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-10-15T10:00:00Z"/><Computer>HOST</Computer></System><EventData><Data Name="DestinationIp">192.0.2.1</Data></EventData></Event>'
    rows = parse_sysmon_xml(data)
    assert len(rows) == 1
    assert rows[0][1].event_id == 3
    assert rows[0][2]["event_data"]["DestinationIp"] == "192.0.2.1"


def test_reject_non_sysmon_and_external_entity():
    bad = b'<Event><System><Provider Name="Other-Provider"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-15T10:00:00Z"/><Computer>HOST</Computer></System></Event>'
    with pytest.raises(ValueError, match="not Sysmon"):
        parse_sysmon_xml(bad)
    with pytest.raises(ValueError, match="Invalid Windows Event XML"):
        parse_sysmon_xml(b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event>&xxe;</Event>')


def test_reject_missing_timestamp():
    bad = b'<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Computer>HOST</Computer></System></Event>'
    with pytest.raises(ValueError, match="TimeCreated"):
        parse_sysmon_xml(bad)
