import re
from uuid import uuid4


def finding(rule, title, agent, evidence_ids, technique=None, confidence="medium", classification="observed", **extra):
    return {"id": str(uuid4()), "rule_id": rule, "title": title, "agent": agent,
            "evidence_ids": evidence_ids, "technique_ids": [technique] if technique else [],
            "confidence": confidence, "classification": classification,
            "limitations": [], **extra}


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
        if event["event_id"] in {12, 13, 14} and re.search(r"\\currentversion\\run(?:once|onceex)?(?:\\|$)", target):
            rule, title, technique = "run_key", "Registry autorun configuration observed", "T1547.001"
        elif "\\start menu\\programs\\startup\\" in target:
            rule, title, technique = "startup", "Startup folder modification observed", "T1547.001"
        elif ("\\taskcache\\" in target or
              (event["event_id"] == 1 and "schtasks" in image and re.search(r"(?:^|\s)/create(?:\s|$)", command))):
            rule, title, technique = "scheduled_task", "Scheduled task creation indicator", "T1053.005"
        elif (("\\system\\currentcontrolset\\services\\" in target and target.endswith("\\imagepath")) or
              (event["event_id"] == 1 and image.endswith("\\sc.exe") and re.search(r"\b(create|config)\b", command))):
            rule, title, technique = "service", "Windows service configuration indicator", "T1543.003"
        elif event["event_id"] in {12, 13, 14}:
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
