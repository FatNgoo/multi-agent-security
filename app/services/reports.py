def markdown_report(result):
    lines = ["# Investigation report", "", result["summary"], "",
             f"Investigation `{result['investigation_id']}`", "",
             f"Severity **{result['risk']['severity']}**", "",
             f"Mode `{result['mode']}` / strategy `{result['strategy']}`", "",
             "## Scope", "", f"Datasets: {', '.join(result['dataset_ids'])}",
             f"UTC range: {result['scope']['start_time']} to {result['scope']['end_time']}",
             "", "## Coverage and limitations", "", str(result["coverage"])]
    lines += [f"- {warning}" for warning in result["warnings"]]
    for finding in result["findings"]:
        lines += ["", f"## {finding['title']}", "",
                  f"Severity {finding['severity']}, confidence {finding['confidence']}, classification {finding['classification']}",
                  "", finding["severity_reason"], "", "Evidence: " + ", ".join(finding["evidence_ids"])]
        lines += [f"- Limitation: {item}" for item in finding["limitations"]]
        lines += [f"- ATT&CK candidate [{item['technique_id']}]({item['source']})" for item in finding["attack"]]
        lines += ["", "### Response recommendations", ""]
        for action in finding["recommendations"]:
            lines += [f"- **{action['phase']}** {action['action']} ({action['status']})",
                      f"  Condition: {action['condition']}", f"  Impact: {action['operational_impact']}",
                      f"  Verify: {action['verification']}"]
    lines += ["", "## Relationships", ""]
    for relationship in result["relationships"]:
        lines += [f"- {relationship['type']}, {relationship['confidence']}: {relationship['reason']}",
                  "  Evidence: " + ", ".join(relationship["evidence_ids"])]
    lines += ["", "## Timeline", ""]
    lines += [f"- {event['timestamp']} [{event['source']}] {event['description']} ({event['evidence_id']})" for event in result["timeline"]]
    lines += ["", "## Runtime and alert timing", "", str(result["timings"])]
    return "\n".join(lines)
