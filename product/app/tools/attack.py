"""Small versioned, curated ATT&CK retrieval corpus. Refresh through source review."""
import re

CORPUS_VERSION = "curated-2026-11-12"
_RECORDS = [
    ("T1547.001", "Registry Run Keys / Startup Folder", "2.1",
     "Run keys and startup folder entries can cause a program to execute at logon.",
     "registry run runonce startup persistence autorun"),
    ("T1053.005", "Scheduled Task", "1.8",
     "Windows Task Scheduler can provide recurring execution or execution at startup.",
     "scheduled task schtasks taskcache persistence execution"),
    ("T1543.003", "Windows Service", "1.6",
     "Creating or modifying Windows services can establish startup execution.",
     "windows service services imagepath sc.exe persistence"),
    ("T1071.001", "Web Protocols", "1.5",
     "Adversaries can carry command-and-control traffic over application web protocols.",
     "http https web protocol command control c2 beacon"),
    ("T1071.004", "DNS", "1.4",
     "Adversaries can use DNS messages to carry command-and-control communication.",
     "dns query command control c2 tunneling beacon"),
]


def lookup(query: str) -> list[dict]:
    tokens = set(re.findall(r"[a-z0-9.]+", query.lower()))
    matches = []
    for technique_id, name, version, summary, keywords in _RECORDS:
        score = len(tokens & set(re.findall(r"[a-z0-9.]+", f"{technique_id} {name} {keywords}".lower())))
        if score:
            base, sub = technique_id.split(".")
            matches.append({"technique_id": technique_id, "name": name, "technique_version": version,
                            "summary": summary, "source": f"https://attack.mitre.org/techniques/{base}/{sub}/",
                            "reviewed_at": "2026-11-12", "corpus_version": CORPUS_VERSION,
                            "mapping_status": "candidate", "retrieval_score": score})
    return sorted(matches, key=lambda item: (-item["retrieval_score"], item["technique_id"]))[:5]
