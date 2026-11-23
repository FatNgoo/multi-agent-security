from datetime import datetime


def correlate(events, findings, request, checkpoint=lambda: None):
    """Tuple matches support association, not malware attribution or causation."""
    by_id = {event["evidence_id"]: event for event in events}
    networks = [e for e in events if e["source"] == "sysmon" and e["event_id"] == 3]
    flows = [e for e in events if e["source"] == "zeek_conn"]
    relationships = []
    for persistence in [f for f in findings if f["agent"] == "persistence" and f["rule_id"] != "registry_change"]:
        anchor = by_id[persistence["evidence_ids"][0]]
        guid = anchor["normalized"].get("process_guid")
        matching = [e for e in networks if guid and e["host"] == anchor["host"]
                    and e["normalized"].get("process_guid") == guid]
        for flow in flows:
            checkpoint()
            if len(relationships) >= 500:
                return relationships
            fn = flow["normalized"]
            linked = None
            for network in matching:
                nn = network["normalized"]
                keys = ("source_ip", "source_port", "dest_ip", "dest_port", "protocol")
                if all(nn.get(key) is not None and nn.get(key) == fn.get(key) for key in keys):
                    skew = abs((datetime.fromisoformat(network["timestamp"]) - datetime.fromisoformat(flow["timestamp"])).total_seconds())
                    if skew <= 2:
                        linked = network
                        break
            if linked:
                relationships.append({"type": "supported_correlation", "confidence": "high",
                                      "finding_id": persistence["id"],
                                      "evidence_ids": [anchor["evidence_id"], linked["evidence_id"], flow["evidence_id"]],
                                      "join_keys": ["host", "ProcessGuid", "5-tuple", "time within 2s"],
                                      "reason": "The modifying process has an endpoint connection matching this Zeek flow.",
                                      "limitations": ["NAT and clock differences require review.",
                                                      "Execution of the autorun target and causality remain unverified."]})
                continue
            flow_time = datetime.fromisoformat(flow["timestamp"])
            mapped = any(m.host == anchor["host"] and str(m.ip) == fn.get("source_ip")
                         and m.start_time <= flow_time <= m.end_time for m in request.host_mappings)
            delta = abs((datetime.fromisoformat(anchor["timestamp"]) - flow_time).total_seconds())
            if mapped and delta <= 300:
                relationships.append({"type": "hypothesis", "confidence": "low", "finding_id": persistence["id"],
                                      "evidence_ids": [anchor["evidence_id"], flow["evidence_id"]],
                                      "join_keys": ["user supplied host-IP mapping", "time within 300s"],
                                      "reason": "Temporal proximity on a mapped host warrants review.",
                                      "limitations": ["No process-to-flow mapping established."]})
    return relationships
