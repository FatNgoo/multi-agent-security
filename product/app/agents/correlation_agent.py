"""Correlate specialist findings and request a bounded cross-source assessment."""
from app.agents.specialists import interpret
from app.tools.correlation import correlate
from app.schemas.investigation_state import InvestigationState


def run_correlation_agent(state: InvestigationState) -> dict:
    tools = state["tools"]
    tools.checkpoint()
    tools.progress("correlation")
    relationships = correlate(tools.events(), state["findings"], tools.request, tools.checkpoint)
    assessments = list(state["assessments"])
    if tools.request.strategy == "multi_agent" and relationships:
        assessments.append(interpret(
            "correlation", tools, state["mode"],
            {
                "findings": state["findings"],
                "relationships": relationships,
                "specialist_assessments": assessments,
            },
        ))
    return {"relationships": relationships, "assessments": assessments}
