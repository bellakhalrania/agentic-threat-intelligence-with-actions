"""
graph/workflow.py
Wires the seven agents into a single linear LangGraph pipeline:

START -> Collection -> Enrichment -> Mapping -> Correlation -> Prediction -> Response -> Reporting -> END

Response runs BEFORE Reporting so that response actions are available
to include in the generated report.
"""

from langgraph.graph import StateGraph, START, END
from graph.state import InvestigationState
from graph.nodes import (
    collection_node,
    enrichment_node,
    mapping_node,
    correlation_node,
    prediction_node,
    reporting_node,
    response_node,
)


def build_workflow():
    graph = StateGraph(InvestigationState)

    graph.add_node("collection", collection_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("mapping", mapping_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("prediction", prediction_node)
    graph.add_node("reporting", reporting_node)
    graph.add_node("response", response_node)

    graph.add_edge(START, "collection")
    graph.add_edge("collection", "enrichment")
    graph.add_edge("enrichment", "mapping")
    graph.add_edge("mapping", "correlation")
    graph.add_edge("correlation", "prediction")
    graph.add_edge("prediction", "response")
    graph.add_edge("response", "reporting")
    graph.add_edge("reporting", END)

    # Compile without checkpointer to avoid schema corruption issues
    return graph.compile(checkpointer=None)


# Singleton compiled graph used by main.py
threat_intel_workflow = build_workflow()
