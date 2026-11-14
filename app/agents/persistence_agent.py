"""Persistence investigation and the original Python compatibility entry point."""
from app.agents.specialists import interpret
from app.analysis.findings import persistence_findings
from app.core.config import settings
from app.schemas.investigation import InvestigationRequest
from app.schemas.investigation_state import InvestigationState
from app.tools.shared import SharedTools


def investigate_persistence(state: InvestigationState) -> dict:
    tools = state["tools"]
    events = tools.run("persistence", "query_events")
    process_tree = tools.run("persistence", "process_tree")
    assessments = []
    if tools.request.strategy == "single_agent" and "c2" not in state["plan"]:
        assessments = [interpret("single_agent", tools, state["mode"])]
    elif tools.request.strategy == "multi_agent" and any(event["source"] == "sysmon" for event in events):
        assessments = [interpret("persistence", tools, state["mode"])]
    return {
        "findings": persistence_findings(events),
        "assessments": assessments,
        "process_tree": process_tree,
    }


def run_persistence_agent(host: str, start_time: str, end_time: str, dataset_id: str) -> dict:
    request = InvestigationRequest(host=host, start_time=start_time, end_time=end_time, dataset_id=dataset_id)
    tools = SharedTools(request)
    events = tools.run("persistence", "query_events", source="sysmon")
    assessment = interpret("persistence", tools, settings.agent_mode)
    registry = sum(event["event_id"] in {12, 13, 14} for event in events)
    summary = f"Found {len(events)} Sysmon events; {registry} registry events. Validate context and evidence before concluding."
    if assessment.get("assessment"):
        summary = assessment["assessment"]["text"]
    return {"summary": summary, "events": events, "mode": settings.agent_mode,
            "trace": [f"{trace['tool']}: {trace['result_count']} records" for trace in tools.trace],
            "findings": persistence_findings(events), "coverage": tools.coverage, "assessment": assessment}
