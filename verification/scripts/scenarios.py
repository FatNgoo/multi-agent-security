"""Synthetic labeled cases, never forensic evidence from an actual incident."""
import json
from datetime import datetime, timezone

START = datetime(2026, 10, 14, 8, tzinfo=timezone.utc)


def scenario(name="combined"):
    guid = "{SIMULATED-PROCESS-01}"
    sysmon = [
        {"timestamp": START.isoformat(), "host": "WIN-LAB-01", "event_id": 1,
         "description": "SYNTHETIC lab process creation", "process_guid": guid,
         "image": r"C:\Lab\simulated-agent.exe", "parent_process_guid": "{SIMULATED-PARENT}",
         "parent_image": r"C:\Windows\explorer.exe"},
        {"timestamp": START.isoformat(), "host": "WIN-LAB-01", "event_id": 13,
         "description": "SYNTHETIC lab Run Key configuration", "process_guid": guid,
         "target_object": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LabDemo",
         "details": r"C:\Lab\simulated-agent.exe"},
    ]
    connections = []
    for index in range(8):
        ts = START.timestamp() + 60 * (index + 1)
        port = 51000 + index
        connection = {"ts": ts, "uid": f"SYNTHETIC{index}", "id.orig_h": "192.0.2.10", "id.orig_p": port,
                      "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                      "duration": 0.2, "orig_bytes": 100, "resp_bytes": 180, "conn_state": "SF"}
        connections.append(connection)
        sysmon.append({"timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(), "host": "WIN-LAB-01", "event_id": 3,
                       "description": "SYNTHETIC lab network connection", "process_guid": guid,
                       "source_ip": "192.0.2.10", "source_port": port,
                       "dest_ip": "198.51.100.20", "dest_port": 443, "protocol": "tcp"})
    if name == "ambiguous":
        sysmon = [e for e in sysmon if e["event_id"] != 3]
    elif name == "benign":
        sysmon = [sysmon[0]]
    elif name == "negative":
        sysmon = [sysmon[0]]
        for index, conn in enumerate(connections):
            conn["ts"] += index * index * 17
    dns = [{"ts": START.timestamp() + 60, "uid": "SYNTHETIC0", "id.orig_h": "192.0.2.10", "id.orig_p": 53000,
            "id.resp_h": "192.0.2.53", "id.resp_p": 53, "proto": "udp", "query": "lab-demo.example", "qtype_name": "A",
            "answers": ["198.51.100.20"]}]
    http = [{"ts": START.timestamp() + 60, "uid": "SYNTHETIC0", "id.orig_h": "192.0.2.10", "id.orig_p": 51000,
             "id.resp_h": "198.51.100.20", "id.resp_p": 443, "host": "lab-demo.example", "method": "GET",
             "uri": "/simulated-health", "status_code": 200, "user_agent": "SYNTHETIC lab"}]
    return {"sysmon": sysmon, "zeek_conn": connections, "zeek_dns": dns, "zeek_http": http}


def jsonl(records):
    return ("\n".join(json.dumps(record) for record in records) + "\n").encode()


def conn_tsv(records):
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes"]
    types = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count"]
    lines = [r"#separator \x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn",
             "#fields\t" + "\t".join(fields), "#types\t" + "\t".join(types)]
    lines += ["\t".join(str(record.get(field, "-")) for field in fields) for record in records]
    return ("\n".join(lines) + "\n").encode()
