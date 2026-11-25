import ntpath
import re
from uuid import uuid4


def finding(rule, title, agent, evidence_ids, technique=None, confidence="medium", classification="observed", **extra):
    return {"id": str(uuid4()), "rule_id": rule, "title": title, "agent": agent,
            "evidence_ids": evidence_ids, "technique_ids": [technique] if technique else [],
            "confidence": confidence, "classification": classification,
            "limitations": [], **extra}


def service_change(command):
    # A service can itself be named "config". Only the operation identifies a change.
    tokens = [word.strip('"') for word in re.findall(r'"[^"]*"|\S+', command)]
    if tokens and ntpath.basename(tokens[0]) in {"sc", "sc.exe"}:
        tokens.pop(0)
    if tokens and tokens[0].startswith("\\\\"):
        tokens.pop(0)
    return bool(tokens and tokens[0] in {"create", "config"})


def persistence_findings(events):
    findings = []
    for event in events:
        if event["source"] != "sysmon":
            continue
        n = event["normalized"]
        target = str(n.get("target_object") or "").lower()
        command = str(n.get("command_line") or "").lower()
        image = str(n.get("image") or "").lower()
        rule, title, technique = None, None, None
        raw = event.get("raw") or {}
        event_type = (raw.get("event_data") or {}).get("EventType") or raw.get("EventType") or raw.get("event_type")
        registry = event["event_id"] in {12, 13, 14}
        registry_write = registry and str(event_type).casefold() not in {"deletekey", "deletevalue"}
        if registry_write and re.search(r"\\currentversion\\run(?:once|onceex)?(?:\\|$)", target):
            rule, title, technique = "run_key", "Registry autorun configuration observed", "T1547.001"
        elif event["event_id"] == 11 and "\\start menu\\programs\\startup\\" in target:
            rule, title, technique = "startup", "Startup folder modification observed", "T1547.001"
        elif ((registry_write and "\\taskcache\\" in target) or
              (event["event_id"] == 1 and ntpath.basename(image) == "schtasks.exe" and re.search(r"(?:^|\s)/create(?:\s|$)", command))):
            rule, title, technique = "scheduled_task", "Scheduled task creation indicator", "T1053.005"
        elif ((registry_write and "\\system\\currentcontrolset\\services\\" in target and target.endswith("\\imagepath")) or
              (event["event_id"] == 1 and ntpath.basename(image) == "sc.exe" and service_change(command))):
            rule, title, technique = "service", "Windows service configuration indicator", "T1543.003"
        elif registry:
            rule, title = "registry_change", "Registry change requiring context"
        if rule:
            findings.append(finding(rule, title, "persistence", [event["evidence_id"]], technique,
                                    limitations=["Administrative software can produce this activity. Validate ownership and change records."]))
    return findings


def c2_findings(events, statistics):
    findings = []
    by_id = {e["evidence_id"]: e for e in events}
    for stat in statistics:
        if not stat["periodic"]:
            continue
        sample = by_id[stat["evidence_ids"][0]]["normalized"]
        service = str(sample.get("service") or "").lower()
        technique = "T1071.001" if any(s in service.split(",") for s in ("http", "ssl", "https")) else None
        findings.append(finding(
            "periodic_connection", "Periodic network connections", "c2", stat["evidence_ids"], technique,
            confidence="low", classification="benign_possible" if stat["benign_context"] else "hypothesis",
            statistics=stat, limitations=["Periodicity also occurs in software updates and monitoring.",
                                         "Destination reputation and payload purpose are unknown."]))
    for event in events:
        n = event["normalized"]
        query = n.get("query")
        if event["source"] == "zeek_dns" and isinstance(query, str) and any(len(label) >= 40 for label in query.split(".")):
            findings.append(finding("long_dns_label", "Long DNS label requiring investigation", "c2",
                                    [event["evidence_id"]], "T1071.004", confidence="low", classification="hypothesis",
                                    limitations=["Long DNS labels are also used by legitimate services. Payload content is unverified."]))
    return findings
