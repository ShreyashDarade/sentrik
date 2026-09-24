"""LangGraph durable workflow for the assessment lifecycle.

This is a real LangGraph `StateGraph` whose nodes delegate to the AssessmentEngine's
phase wrappers (`node_*`). It provides durable checkpointing via LangGraph's own
checkpointer and conditional edges for cancellation/failure. It is used when
`SENTINEL_USE_LANGGRAPH=true` and langgraph is installed; otherwise the orchestrator
falls back to the inline engine (`AssessmentEngine.run`). Both paths share the exact
same phase implementations, so behavior is identical — LangGraph adds durable,
inspectable workflow orchestration on top.

Authorization is still enforced entirely by the deterministic layer beneath the phases;
the graph only sequences work.
"""

from __future__ import annotations

import logging
from typing import TypedDict

log = logging.getLogger("sentinel.graph")

try:  # optional dependency
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, StateGraph

    LANGGRAPH_AVAILABLE = True
except Exception:  # noqa: BLE001  pragma: no cover
    LANGGRAPH_AVAILABLE = False


class AssessmentGraphState(TypedDict, total=False):
    assessment_id: str
    status: str  # "running" | "cancelled" | "failed" | "completed"
    error: str
    last_phase: str


def build_assessment_graph(engine):
    """Compile a LangGraph workflow bound to a specific AssessmentEngine instance."""
    if not LANGGRAPH_AVAILABLE:
        raise RuntimeError("langgraph is not installed")

    async def _guard_cancel(state: AssessmentGraphState) -> bool:
        return await engine._cancelled()

    def _node(name: str, coro_method):
        async def _run(state: AssessmentGraphState) -> AssessmentGraphState:
            if state.get("status") not in (None, "running"):
                return state
            if await _guard_cancel(state):
                return {**state, "status": "cancelled", "last_phase": name}
            try:
                result = await coro_method()
                if name == "authorize" and result != "ok":
                    return {
                        **state,
                        "status": "failed",
                        "error": result,
                        "last_phase": name,
                    }
            except Exception as exc:
                log.exception("graph node %s failed", name)
                await engine.mark_failed(f"{type(exc).__name__}: {exc}")
                return {
                    **state,
                    "status": "failed",
                    "error": str(exc),
                    "last_phase": name,
                }
            return {**state, "status": "running", "last_phase": name}

        return _run

    graph = StateGraph(AssessmentGraphState)
    graph.add_node("authorize", _node("authorize", engine.node_authorize))
    graph.add_node("discover", _node("discover", engine.node_discover))
    graph.add_node("plan", _node("plan", engine.node_plan))
    graph.add_node("policy", _node("policy", engine.node_policy))
    graph.add_node("execute", _node("execute", engine.node_execute))
    graph.add_node("validate", _node("validate", engine.node_validate))
    graph.add_node("score", _node("score", engine.node_score))
    graph.add_node("report", _node("report", engine.node_report))

    graph.set_entry_point("authorize")

    def _route(next_node: str):
        def _r(state: AssessmentGraphState) -> str:
            if state.get("status") in ("cancelled", "failed"):
                return END
            return next_node

        return _r

    graph.add_conditional_edges(
        "authorize", _route("discover"), {"discover": "discover", END: END}
    )
    graph.add_conditional_edges("discover", _route("plan"), {"plan": "plan", END: END})
    graph.add_conditional_edges(
        "plan", _route("policy"), {"policy": "policy", END: END}
    )
    graph.add_conditional_edges(
        "policy", _route("execute"), {"execute": "execute", END: END}
    )
    graph.add_conditional_edges(
        "execute", _route("validate"), {"validate": "validate", END: END}
    )
    graph.add_conditional_edges(
        "validate", _route("score"), {"score": "score", END: END}
    )
    graph.add_conditional_edges(
        "score", _route("report"), {"report": "report", END: END}
    )
    graph.add_edge("report", END)

    return graph.compile(checkpointer=MemorySaver())


async def run_via_langgraph(assessment_id: str) -> None:
    """Run one assessment through the LangGraph workflow."""
    from app.orchestration.engine import AssessmentEngine

    engine = AssessmentEngine(assessment_id)
    compiled = build_assessment_graph(engine)
    config = {"configurable": {"thread_id": assessment_id}}
    final = await compiled.ainvoke(
        {"assessment_id": assessment_id, "status": "running"}, config
    )
    status = final.get("status")
    if status == "cancelled":
        await engine._finish_cancelled()
    # failed/completed already persisted by the nodes
