from typing import Any, TypedDict
from langgraph.graph import StateGraph, START, END
from app.agents.persistence_agent import run_persistence_agent


class InvestigationState(TypedDict, total=False):
    host: str
    dataset_id: str
    start_time: str
    end_time: str
    route: str
    agent_result: dict[str, Any]


def supervisor(state: InvestigationState) -> dict:
    # v0.1: deterministic routing to the only implemented specialist.
    # Future versions add C2 and correlation routes here.
    return {"route": "persistence"}


def persistence(state: InvestigationState) -> dict:
    return {"agent_result": run_persistence_agent(
        state["host"], state["start_time"], state["end_time"], state["dataset_id"]
    )}


def route_agent(state: InvestigationState) -> str:
    return state["route"]


def build_graph():
    graph = StateGraph(InvestigationState)
    graph.add_node("supervisor", supervisor)
    graph.add_node("persistence", persistence)
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", route_agent, {"persistence": "persistence"})
    graph.add_edge("persistence", END)
    return graph.compile()


investigation_graph = build_graph()
