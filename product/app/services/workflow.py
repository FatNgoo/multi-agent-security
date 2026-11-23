"""Compose investigation agents, verification and reporting with LangGraph."""
from langgraph.graph import StateGraph, START, END
from app.agents.supervisor_agent import run_supervisor as supervisor
from app.agents.persistence_agent import investigate_persistence as persistence
from app.agents.c2_agent import run_c2_agent as c2
from app.agents.correlation_agent import run_correlation_agent as correlation
from app.services.risk import assess
from app.common import iso, utcnow
from app.tools.attack import lookup
from app.services.recommendations import recommend
from app.agents.response_agent import propose_response
from app.schemas.investigation_state import InvestigationState


def verify(state):
    tools = state["tools"]
    tools.checkpoint()
    tools.progress("verification")
    known = {e["evidence_id"] for e in tools.events()}
    for item in state["findings"] + state["relationships"]:
        if not item["evidence_ids"] or not set(item["evidence_ids"]) <= known:
            raise ValueError("Evidence validation failed")
    risk = assess(state["findings"], state["relationships"], tools.request)
    return {"risk": risk, "detected_at": iso(utcnow()) if state["findings"] else None}


def response(state):
    tools = state["tools"]
    tools.checkpoint()
    tools.progress("response")
    recommend(state["findings"])
    plan = propose_response(state["findings"], state["relationships"], state["risk"], tools, state["mode"])
    assessment = {"agent": "response", "status": plan["status"], "error": plan.get("error"),
                  "error_code": plan.get("error_code"), "error_message": plan.get("error_message"),
                  "assessment": {"text": plan["summary"], "limitations": plan.get("limitations", []),
                                 "evidence_ids": list(dict.fromkeys(ref for step in plan["steps"] for ref in step["evidence_ids"]))}
                  if plan["source"] == "ai" else None}
    return {"response_plan": plan, "assessments": state["assessments"] + [assessment]}


def report(state):
    tools = state["tools"]
    tools.checkpoint()
    tools.progress("report")
    for item in state["findings"]:
        item["attack"] = [record for technique in item["technique_ids"]
                          for record in lookup(technique) if record["technique_id"] == technique]
    return {}


def build_graph():
    graph = StateGraph(InvestigationState)
    nodes = {"supervisor": supervisor, "persistence": persistence, "c2": c2,
             "correlation": correlation, "verification": verify, "response": response, "report": report}
    for name, action in nodes.items():
        graph.add_node(name, action)
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", lambda state: state["plan"][0])
    graph.add_conditional_edges("persistence", lambda state: "c2" if "c2" in state["plan"] else "verification")
    graph.add_conditional_edges("c2", lambda state: "correlation" if "correlation" in state["plan"] else "verification")
    graph.add_edge("correlation", "verification")
    graph.add_edge("verification", "response")
    graph.add_edge("response", "report")
    graph.add_edge("report", END)
    return graph.compile()


investigation_graph = build_graph()
