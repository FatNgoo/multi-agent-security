"""Select investigation stages from the sources inside the requested scope."""
from app.schemas.investigation_state import InvestigationState


def run_supervisor(state: InvestigationState) -> dict:
    tools = state["tools"]
    events = tools.run("supervisor", "query_events")
    sources = {event["source"] for event in events}
    route = "persistence" if sources <= {"sysmon"} else "persistence+c2+correlation"
    if not sources:
        route = "insufficient_evidence"
    plan = []
    if "sysmon" in sources:
        plan.append("persistence")
    if any(source.startswith("zeek") for source in sources):
        plan.append("c2")
    if "persistence" in plan and "c2" in plan:
        plan.append("correlation")
    return {
        "route": route,
        "findings": [],
        "assessments": [],
        "relationships": [],
        "process_tree": [],
        "plan": plan + ["verification", "report"],
    }
