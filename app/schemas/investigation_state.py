"""State shared by the investigation agents and the LangGraph workflow."""
from typing import Any, TypedDict


class InvestigationState(TypedDict, total=False):
    tools: Any
    mode: str
    findings: list
    assessments: list
    relationships: list
    risk: dict
    route: str
    plan: list
    detected_at: str | None
    process_tree: list
