"""LangGraph durable workflow for the assessment lifecycle.

This is a real LangGraph `StateGraph` whose nodes delegate to the AssessmentEngine's
phase wrappers (`node_*`). It provides durable checkpointing via LangGraph's own
checkpointer and conditional edges for cancellation/failure. It is used when
`SENTINEL_USE_LANGGRAPH=true` and langgraph is installed; otherwise the orchestrator
falls back to the inline engine (`AssessmentEngine.run`). Both paths share the exact
same phase implementations, so behavior is identical — LangGraph adds durable,
inspectable workflow orchestration on top.

Durability semantics (B-03 / B-04 / B-07):

* Every node transition is persisted **before** the next node starts
  (``durability="sync"``), to SQLite (``AsyncSqliteSaver``) or Postgres
  (``AsyncPostgresSaver``) when the application database is Postgres and the
  ``langgraph-checkpoint-postgres`` package is installed.
* ``run_via_langgraph`` inspects the thread first: if the checkpointer holds pending
  nodes (a crash mid-run, or a run parked on an approval), it **continues** from that
  node with ``ainvoke(None | Command(resume=...))`` instead of restarting.
* The ``policy`` node calls ``interrupt()`` when steps are held for per-action approval
  (CP-03): the run parks with no live task and resumes once an operator decides.

Authorization is still enforced entirely by the deterministic layer beneath the phases;
the graph only sequences work.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import TypedDict

from app.core.config import get_settings

log = logging.getLogger("sentrik.graph")

try:  # optional dependency
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, StateGraph
    from langgraph.types import Command, interrupt

    LANGGRAPH_AVAILABLE = True
except Exception:  # noqa: BLE001  pragma: no cover
    LANGGRAPH_AVAILABLE = False

try:  # durable checkpointer (crash-recoverable run state); optional
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    SQLITE_CHECKPOINTER_AVAILABLE = True
except Exception:  # noqa: BLE001  pragma: no cover
    SQLITE_CHECKPOINTER_AVAILABLE = False

try:  # Postgres checkpointer for production deployments; optional
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    POSTGRES_CHECKPOINTER_AVAILABLE = True
except Exception:  # noqa: BLE001  pragma: no cover
    POSTGRES_CHECKPOINTER_AVAILABLE = False


def _checkpoint_db_path() -> str:
    """Resolve the SQLite file that backs the durable checkpointer.

    Uses ``langgraph_checkpoint_db`` when set; otherwise derives a sibling file next to
    the sqlite application database, else a local default.
    """
    settings = get_settings()
    configured = (settings.langgraph_checkpoint_db or "").strip()
    if configured:
        return configured
    url = settings.database_url or ""
    if url.startswith("sqlite") and "///" in url:
        db_file = url.split("///", 1)[1]
        if db_file and db_file != ":memory:":
            base, _ext = os.path.splitext(db_file)
            return f"{base}_checkpoints.db"
    return "./sentrik_checkpoints.db"


def checkpointer_kind() -> str:
    """Which checkpointer ``checkpointer_cm`` will yield: postgres | sqlite | memory."""
    url = get_settings().database_url or ""
    if url.startswith("postgresql") and POSTGRES_CHECKPOINTER_AVAILABLE:
        return "postgres"
    if SQLITE_CHECKPOINTER_AVAILABLE:
        return "sqlite"
    return "memory"


@asynccontextmanager
async def checkpointer_cm():
    """Yield a LangGraph checkpointer, durable whenever a durable backend is available.

    Postgres when the app DB is Postgres and ``langgraph-checkpoint-postgres`` is
    installed; otherwise ``AsyncSqliteSaver``; otherwise the in-memory saver (correct
    single-process orchestration, no crash recovery).
    """
    kind = checkpointer_kind()
    if kind == "postgres":  # pragma: no cover - needs a Postgres deployment
        url = get_settings().database_url.replace("+asyncpg", "").replace("+psycopg", "")
        async with AsyncPostgresSaver.from_conn_string(url) as saver:
            await saver.setup()
            yield saver
        return
    if kind == "sqlite":
        path = _checkpoint_db_path()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        async with AsyncSqliteSaver.from_conn_string(path) as saver:
            yield saver
        return
    yield MemorySaver()  # pragma: no cover - exercised only without the sqlite extra


class AssessmentGraphState(TypedDict, total=False):
    assessment_id: str
    status: str  # "running" | "cancelled" | "failed" | "completed"
    error: str
    last_phase: str
    awaiting_approval: list[str]


def build_assessment_graph(engine, checkpointer=None):
    """Compile a LangGraph workflow bound to a specific AssessmentEngine instance.

    ``checkpointer`` is the durable/in-memory saver the compiled graph persists state to;
    when omitted an in-memory ``MemorySaver`` is used (single-run, no crash recovery).
    """
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
                if name == "policy" and result:
                    # B-04: park the run until an operator approves/denies every held
                    # step. `interrupt` raises here; on resume this node re-runs from the
                    # top, recomputes the held set and only proceeds once it is empty.
                    held = list(result)
                    await engine.mark_parked(held)
                    interrupt({"awaiting_approval": held})
            except Exception as exc:
                if type(exc).__name__ == "GraphInterrupt":
                    raise
                log.exception("graph node %s failed", name)
                await engine.mark_failed(f"{type(exc).__name__}: {exc}")
                return {
                    **state,
                    "status": "failed",
                    "error": str(exc),
                    "last_phase": name,
                }
            return {
                **state,
                "status": "running",
                "last_phase": name,
                "awaiting_approval": [],
            }

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

    return graph.compile(checkpointer=checkpointer or MemorySaver())


def _config(assessment_id: str) -> dict:
    return {"configurable": {"thread_id": assessment_id}}


async def pending_nodes(assessment_id: str) -> list[str]:
    """Nodes the durable checkpointer still has to run for this assessment's thread
    (empty when the thread is unknown or finished). Used by the startup sweep to
    decide between *continue* and *restart* (B-03)."""
    if not LANGGRAPH_AVAILABLE:
        return []
    from app.orchestration.engine import AssessmentEngine

    async with checkpointer_cm() as checkpointer:
        compiled = build_assessment_graph(
            AssessmentEngine(assessment_id), checkpointer=checkpointer
        )
        snapshot = await compiled.aget_state(_config(assessment_id))
        return list(snapshot.next or ())


async def run_via_langgraph(assessment_id: str) -> dict:
    """Run one assessment through the LangGraph workflow, continuing a pending thread
    when one exists. Returns ``{"mode": fresh|resume, "parked": bool, "status": ...}``."""
    from app.agents.budget import reset_current_budget, set_current_budget
    from app.orchestration.engine import AssessmentEngine

    engine = AssessmentEngine(assessment_id)
    config = _config(assessment_id)
    # F-09: the durable-workflow path drives phases directly (not via engine.run), so the
    # LLM token/cost ledger must be installed here too.
    budget_token = set_current_budget(engine.llm_budget)
    outcome: dict = {"mode": "fresh", "parked": False, "status": ""}
    try:
        async with checkpointer_cm() as checkpointer:
            compiled = build_assessment_graph(engine, checkpointer=checkpointer)
            snapshot = await compiled.aget_state(config)
            if snapshot.next:
                # B-03/B-04: continue from the pending node. A parked approval interrupt
                # is answered with a Command; a plain crash checkpoint is continued as-is.
                interrupted = any(getattr(t, "interrupts", ()) for t in snapshot.tasks)
                payload = Command(resume={"resolved": True}) if interrupted else None
                outcome["mode"] = "resume"
                log.info(
                    "continuing assessment %s from %s", assessment_id, snapshot.next
                )
            else:
                payload = {"assessment_id": assessment_id, "status": "running"}
            final = await compiled.ainvoke(payload, config, durability="sync")
        if "__interrupt__" in final:
            outcome["parked"] = True
            outcome["status"] = "parked"
            return outcome
        status = final.get("status")
        outcome["status"] = status or ""
        if status == "cancelled":
            await engine._finish_cancelled()
        # failed/completed already persisted by the nodes
        return outcome
    finally:
        reset_current_budget(budget_token)
        await engine._persist_llm_budget()
