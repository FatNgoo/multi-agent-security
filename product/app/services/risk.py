SEVERITY_ORDER = {"unknown": -1, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RUBRIC_VERSION = "triage-1.0"


def assess(findings, relationships, request):
    suspicious_network = {ref for f in findings if f["agent"] == "c2" and f["classification"] == "hypothesis"
                          for ref in f["evidence_ids"]}
    for finding in findings:
        rule = finding["rule_id"]
        severity = "medium"
        reason = "Persistence or network indicator requires analyst validation."
        if rule == "registry_change":
            severity, reason = "informational", "Registry change without a recognized persistence location."
        elif rule == "long_dns_label":
            severity, reason = "low", "DNS shape anomaly with unknown payload purpose."
        elif finding["classification"] == "benign_possible":
            severity, reason = "low", "User supplied benign destination context lowers triage priority."
        related = [r for r in relationships if r["type"] == "supported_correlation" and
                   set(r["evidence_ids"]) & suspicious_network and
                   (r["finding_id"] == finding["id"] or set(r["evidence_ids"]) & set(finding["evidence_ids"]))]
        if related and rule != "registry_change" and finding["classification"] != "benign_possible":
            severity, reason = "high", "Cross-source process/network association strengthens investigation priority."
        if request.asset_criticality == "high" and severity == "medium" and rule in {"run_key", "startup", "scheduled_task", "service"}:
            severity, reason = "high", "Analyst-supplied high asset criticality increases the urgency of reviewing this persistence indicator."
        if request.asset_criticality == "high" and severity == "high":
            reason += " The analyst identified this asset as high criticality."
        finding.update(severity=severity, severity_reason=reason, rubric_version=RUBRIC_VERSION)
    overall = max((f["severity"] for f in findings), key=lambda value: SEVERITY_ORDER[value], default="unknown")
    return {"severity": overall, "rubric_version": RUBRIC_VERSION,
            "reason": "Highest finding triage level; inspect individual evidence and confidence.",
            "asset_criticality": request.asset_criticality,
            "limitations": ["This rubric is a versioned research triage heuristic.",
                            "Critical severity requires an explicit analyst review of impact."]}
