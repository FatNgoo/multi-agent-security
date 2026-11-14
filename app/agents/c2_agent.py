"""Investigate C2 indicators using shared endpoint and network tools."""
from app.agents.specialists import interpret
from app.analysis.findings import c2_findings
from app.schemas.investigation_state import InvestigationState


def run_c2_agent(state: InvestigationState) -> dict:
    tools = state["tools"]
    events = tools.run("c2", "query_events")
    statistics = tools.run("c2", "beacon_statistics")
    assessments = list(state["assessments"])
    if tools.request.strategy == "single_agent":
        assessments.append(interpret("single_agent", tools, state["mode"]))
    elif tools.request.strategy == "multi_agent" and any(event["source"].startswith("zeek") for event in events):
        assessments.append(interpret(
            "c2", tools, state["mode"], {"persistence_findings": state["findings"]},
        ))
    return {
        "findings": state["findings"] + c2_findings(events, statistics),
        "assessments": assessments,
    }
