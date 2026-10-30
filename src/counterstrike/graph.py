"""LangGraph wiring for the fleet.

    ingest -> extract --(nothing extracted)--> dispatch
                 |
                 v
             correlate --(no matches)--> dispatch
                 |
                 v
              score -> remediate -> dispatch -> END

Control flow is code; the LLM is only called inside `extract` and `remediate`.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

from langgraph.graph import END, START, StateGraph

from counterstrike.agents.correlate import correlate_agent
from counterstrike.agents.extract import extract_agent
from counterstrike.agents.ingest import ingest_agent
from counterstrike.agents.remediate import remediate_agent
from counterstrike.agents.score import score_agent
from counterstrike.dispatch import dispatch_agent
from counterstrike.llm import LLMPort
from counterstrike.models import FleetState


def build_graph(llm: LLMPort):
    g = StateGraph(FleetState)
    g.add_node("ingest", ingest_agent)
    g.add_node("extract", partial(extract_agent, llm=llm))
    g.add_node("correlate", correlate_agent)
    g.add_node("score", score_agent)
    g.add_node("remediate", partial(remediate_agent, llm=llm))
    g.add_node("dispatch", dispatch_agent)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "extract")
    g.add_conditional_edges(
        "extract",
        lambda s: "correlate" if s["extracted"] else "dispatch",
        ["correlate", "dispatch"],
    )
    g.add_conditional_edges(
        "correlate", lambda s: "score" if s["matches"] else "dispatch", ["score", "dispatch"]
    )
    g.add_edge("score", "remediate")
    g.add_edge("remediate", "dispatch")
    g.add_edge("dispatch", END)
    return g.compile()


def run(data_dir: str | Path, out_dir: str | Path, llm: LLMPort) -> FleetState:
    graph = build_graph(llm)
    return graph.invoke(
        {"data_dir": str(data_dir), "out_dir": str(out_dir), "needs_human": [], "trace": []}
    )
