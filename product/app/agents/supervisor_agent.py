"""Select investigation stages from the sources inside the requested scope."""
from app.schemas.investigation_state import InvestigationState


def run_supervisor(state: InvestigationState) -> dict:
    tools = state["tools"]
    events = tools.run("supervisor", "query_events")
    # Keep one provider call for the final response advisor within the existing total budget.
    tools.reserved_llm_calls = 1 if state["mode"] != "offline" else 0
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
        "plan": plan + ["verification", "response", "report"],
    }
