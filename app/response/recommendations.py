from uuid import uuid4


def recommend(findings):
    for finding in findings:
        persistence = finding["agent"] == "persistence"
        actions = [
            ("verify", "Validate the change owner, software signature and baseline" if persistence else
             "Check destination ownership and compare with updater/monitoring baselines",
             "Apply before changing endpoint or network configuration.", "Read-only analyst review.",
             "Record the owner, baseline comparison and supporting evidence."),
            ("preserve", "Preserve original logs and relevant configuration with hashes",
             "Apply before remediation.", "Evidence storage may contain sensitive data.",
             "Verify hashes, timestamps and evidence chain."),
            ("contain", "Consider isolating the host and restricting confirmed suspicious destinations",
             "Apply after analyst confirmation of active malicious behavior and operational approval.",
             "Isolation may disrupt business services.", "Verify approved restrictions and retain management access."),
            ("remediate", "Export and remove confirmed unauthorized autorun/task/service configuration" if persistence else
             "Remove the confirmed offending process and associated persistence after forensic collection",
             "Apply only to artifacts validated as unauthorized.", "Changes can interrupt legitimate applications.",
             "Verify configuration and re-scan the affected host."),
            ("recover", "Restore approved configuration and monitor for recurrence",
             "Apply after containment and remediation review.", "Coordinate recovery with the asset owner.",
             "Collect fresh Sysmon/Zeek telemetry and verify the suspicious sequence has ceased."),
        ]
        if finding["severity"] in {"informational", "low", "unknown"}:
            actions = actions[:2] + [("monitor", "Monitor the approved activity and revisit the finding if new evidence appears",
                                      "Apply while the finding remains low priority or has a plausible benign explanation.",
                                      "Use an observation window appropriate to the asset.",
                                      "Compare fresh telemetry with the documented baseline.")]
        finding["recommendations"] = [
            {"id": str(uuid4()), "phase": phase, "action": action, "condition": condition,
             "operational_impact": impact, "verification": verification, "status": "pending",
             "priority": index + 1, "evidence_ids": finding["evidence_ids"],
             "source": "Local analyst playbook v1.0", "technique_ids": finding["technique_ids"]}
            for index, (phase, action, condition, impact, verification) in enumerate(actions)
        ]
