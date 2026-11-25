import pytest
from fastapi.testclient import TestClient

from app.agents.specialists import prioritized_events
from app.main import app
from scripts.evaluate import run_case
from scripts.scenarios import LAB_CASES


@pytest.mark.parametrize("case", LAB_CASES)
def test_labeled_log_case(case):
    with TestClient(app) as client:
        result = run_case(client, case, "multi_agent", "offline")
    assert result["rule_set_exact"], result["rules_observed"]
    assert result["severity_match"] and result["relationship_match"]
    assert result["response_refs_ok"]
    assert result["disruptive_playbook"] == (LAB_CASES[case]["severity"] == "high")
    assert result["evidence_completeness"] in (None, 1)


def test_specialist_context_keeps_join_records_after_a_long_quiet_prefix():
    records = [{"source": "sysmon", "evidence_id": str(i)} for i in range(50)]
    context = {"findings": [{"evidence_ids": ["47"]}], "relationships": [{"evidence_ids": ["47", "48", "49"]}]}
    visible = prioritized_events(records, context, "correlation")[:3]
    assert [event["evidence_id"] for event in visible] == ["47", "48", "49"]
