def markdown_report(result):
    lines = ["# Investigation report", "", result["summary"], "",
             f"Investigation `{result['investigation_id']}`", "",
             f"Severity **{result['risk']['severity']}**", "",
             f"Mode `{result['mode']}` / strategy `{result['strategy']}`", "",
             "## Scope", "", f"Datasets: {', '.join(result['dataset_ids'])}",
             f"UTC range: {result['scope']['start_time']} to {result['scope']['end_time']}",
             "", "## Coverage and limitations", "", str(result["coverage"])]
    lines += [f"- {warning}" for warning in result["warnings"]]
    plan = result.get("response_plan")
    if plan:
        lines += ["", "## Response recommendations — Biện pháp đề xuất tổng hợp", "",
                  f"Nguồn: {plan['source']} / {plan.get('provider') or 'offline'}; trạng thái: {plan['status']}",
                  "", plan["summary"]]
        if plan.get("error"):
            lines += ["", f"AI chưa hoàn tất: {plan['error']}. Hiển thị playbook thay thế."]
        for index, step in enumerate(plan["steps"], 1):
            lines += ["", f"### {index}. {step['title']}", "", step["action"],
                      "", f"Điều kiện và ảnh hưởng: {step['condition']}",
                      f"Kiểm tra kết quả: {step['verification']}", "Evidence: " + ", ".join(step["evidence_ids"])]
        lines += [f"- Giới hạn: {line}" for line in plan.get("limitations", [])]
    for finding in result["findings"]:
        lines += ["", f"## {finding['title']}", "",
                  f"Severity {finding['severity']}, confidence {finding['confidence']}, classification {finding['classification']}",
                  "", finding["severity_reason"], "", "Evidence: " + ", ".join(finding["evidence_ids"])]
        lines += [f"- Limitation: {item}" for item in finding["limitations"]]
        lines += [f"- ATT&CK candidate [{item['technique_id']}]({item['source']})" for item in finding["attack"]]
        if not plan:
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
