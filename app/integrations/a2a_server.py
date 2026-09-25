"""A2A (Agent2Agent, v1.0.0) binding for Sentrik (F-05).

Exposes Sentrik as an A2A agent so *other* agents can task it over the network:

* agent card at ``/.well-known/agent-card.json`` (public discovery, declares the
  ``X-API-Key`` security scheme and one skill per authorized check class),
* JSON-RPC binding at ``/a2a`` — ``message/send``, ``tasks/get``, ``tasks/list``,
  ``tasks/cancel`` — served by the official ``a2a-sdk`` request handler,
* a durable, **owner-scoped** task store in the application database (owner = org id),
  so one tenant can never read or cancel another tenant's tasks.

A task *is* an assessment. The caller sends a data part::

    {"target_id": "...", "authorization_id": "...",
     "requested_check_classes": ["sqli", ...],            # optional
     "artifacts": [{"kind": "openapi", "content": "..."}]}  # optional

Everything an A2A caller can do is exactly what the same API key can do over REST:
the message is data, never instructions — it cannot widen the authorization record,
and every request still goes through the deterministic scope guard.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app import __version__
from app.checks.base import registry as check_registry
from app.core.config import get_settings
from app.core.db import get_engine, get_sessionmaker
from app.core.enums import AssessmentState
from app.models import Assessment
from app.services.assessment_service import (
    AssessmentCreateError,
    build_report,
    create_assessment,
)
from app.services.audit import write_audit

log = logging.getLogger("sentrik.a2a")

# Google's A2A SDK (a2a-sdk) is a required dependency: the A2A binding is part of the
# product surface, not an optional extra.
from a2a.helpers import get_data_parts, new_data_part, new_task, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import DatabaseTaskStore, TaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    APIKeySecurityScheme,
    SecurityRequirement,
    SecurityScheme,
    StringList,
)
from a2a.types import TaskState as _TaskState

TERMINAL = {
    AssessmentState.COMPLETED.value,
    AssessmentState.FAILED.value,
    AssessmentState.CANCELLED.value,
}

_SKILL_DESCRIPTIONS = {
    "sqli": "SQL injection (error-based + boolean differential), independently re-proved",
    "xss": "Reflected cross-site scripting with unique-marker, context-aware detection",
    "bola": "Broken object-level authorization across two test accounts",
    "open_redirect": "Open redirect via attacker-controlled Location",
    "security_headers": "Missing browser security headers",
    "info_disclosure": "Technology / version disclosure headers",
    "business_logic": "Server-side numeric range validation on quantity/amount parameters",
}


def build_agent_card() -> AgentCard:
    settings = get_settings()
    base = settings.public_base_url.rstrip("/")
    skills = [
        AgentSkill(
            id="assessment",
            name="Authorized application security assessment",
            description=(
                "Run the full lifecycle (discovery → planning → policy → execution → "
                "independent validation → scoring → report) against a target the "
                "caller's organization owns and has authorized. Data part: "
                "{target_id, authorization_id, requested_check_classes?, artifacts?}."
            ),
            tags=["security-testing", "appsec", "dast", "authorized-only"],
            examples=[
                json.dumps(
                    {
                        "target_id": "<target id>",
                        "authorization_id": "<verified authorization id>",
                        "requested_check_classes": ["sqli", "xss"],
                    }
                )
            ],
            input_modes=["application/json", "text/plain"],
            output_modes=["application/json"],
        )
    ]
    for cls in check_registry.classes():
        skills.append(
            AgentSkill(
                id=f"check.{cls}",
                name=f"{cls} check",
                description=_SKILL_DESCRIPTIONS.get(cls, f"{cls} security check"),
                tags=["security-check", cls],
                input_modes=["application/json"],
                output_modes=["application/json"],
            )
        )
    card = AgentCard(
        name="Sentrik",
        description=(
            "Authorized, autonomous application & API security testing. Authorization is "
            "enforced outside the LLM: every request is bound to a verified authorization "
            "record of the calling organization."
        ),
        version=__version__,
        documentation_url=f"{base}/docs",
        supported_interfaces=[
            AgentInterface(
                url=f"{base}/a2a", protocol_binding="JSONRPC", protocol_version="1.0"
            )
        ],
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        security_schemes={
            "apiKey": SecurityScheme(
                api_key_security_scheme=APIKeySecurityScheme(
                    description="Sentrik API key (same as the REST API)",
                    location="header",
                    name="X-API-Key",
                )
            )
        },
        security_requirements=[SecurityRequirement(schemes={"apiKey": StringList(list=[])})],
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json"],
        skills=skills,
    )
    return card


def _parse_request(context: RequestContext) -> dict[str, Any]:
    """Merge data parts (dicts) and a ``key=value`` text form into one request dict."""
    req: dict[str, Any] = {}
    if context.message is not None:
        for part in get_data_parts(context.message.parts):
            if isinstance(part, dict):
                req.update(part)
    text = context.get_user_input().strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                req.update(obj)
        except ValueError:
            pass
    else:
        for token in text.split():
            if "=" in token:
                k, v = token.split("=", 1)
                req.setdefault(k.strip(), v.strip())
    return req


class SentrikAgentExecutor(AgentExecutor):
    """Turns an A2A message into a tenant-scoped assessment and reports its outcome."""

    def __init__(self, *, wait_seconds: int | None = None):
        self.wait_seconds = wait_seconds

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.current_task is None:
            # A new conversation: the SDK requires the Task itself to be the first event.
            await event_queue.enqueue_event(
                new_task(
                    context.task_id,
                    context.context_id,
                    _TaskState.TASK_STATE_SUBMITTED,
                    history=[context.message] if context.message is not None else None,
                )
            )
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        user = context.call_context.user if context.call_context else None
        if user is None or not user.is_authenticated or not user.user_name:
            await updater.requires_auth(
                updater.new_agent_message(
                    [new_text_part("authenticate with the X-API-Key header (see agent card)")]
                )
            )
            return
        org_id = user.user_name
        req = _parse_request(context)
        target_id = str(req.get("target_id") or "")
        authorization_id = str(req.get("authorization_id") or "")
        if not target_id or not authorization_id:
            await updater.requires_input(
                updater.new_agent_message(
                    [
                        new_text_part(
                            "send a data part {target_id, authorization_id, "
                            "requested_check_classes?, artifacts?}"
                        )
                    ]
                )
            )
            return
        classes = req.get("requested_check_classes") or []
        artifacts = req.get("artifacts") or []
        if not isinstance(classes, list) or not isinstance(artifacts, list):
            await updater.reject(
                updater.new_agent_message(
                    [new_text_part("requested_check_classes and artifacts must be lists")]
                )
            )
            return

        sm = get_sessionmaker()
        try:
            async with sm() as session:
                a = await create_assessment(
                    session,
                    org_id=org_id,
                    target_id=target_id,
                    authorization_id=authorization_id,
                    requested_check_classes=[str(c) for c in classes],
                    artifacts=[x for x in artifacts if isinstance(x, dict)],
                    audit_data={"via": "a2a", "task_id": context.task_id},
                )
                await session.commit()
                assessment_id = a.id
        except AssessmentCreateError as exc:
            await updater.reject(
                updater.new_agent_message([new_text_part(f"{exc.status_code}: {exc.detail}")])
            )
            return

        await updater.update_status(
            _TaskState.TASK_STATE_WORKING,
            updater.new_agent_message(
                [new_data_part({"assessment_id": assessment_id, "state": "created"})]
            ),
            metadata={"assessment_id": assessment_id},
        )
        from app.orchestration import engine as orchestrator

        orchestrator.start_assessment(assessment_id)
        state = await self._wait(assessment_id)
        async with sm() as session:
            a = await session.get(Assessment, assessment_id)
            payload = await build_report(session, a) if a else {}
        if state == AssessmentState.COMPLETED.value:
            await updater.add_artifact(
                [new_data_part(payload)], name="sentrik-report", metadata={"assessment_id": assessment_id}
            )
            await updater.complete(
                updater.new_agent_message(
                    [
                        new_data_part(
                            {
                                "assessment_id": assessment_id,
                                "state": state,
                                "completion_reason": (a.completion_reason if a else ""),
                                "findings": len(payload.get("findings", [])),
                            }
                        )
                    ]
                )
            )
        elif state == AssessmentState.CANCELLED.value:
            await updater.cancel(
                updater.new_agent_message(
                    [new_data_part({"assessment_id": assessment_id, "state": state})]
                )
            )
        elif state in TERMINAL:
            await updater.failed(
                updater.new_agent_message(
                    [
                        new_data_part(
                            {
                                "assessment_id": assessment_id,
                                "state": state,
                                "error": (a.error if a else ""),
                            }
                        )
                    ]
                )
            )
        else:  # still running past the wait budget: leave WORKING, poll with tasks/get
            await updater.update_status(
                _TaskState.TASK_STATE_WORKING,
                updater.new_agent_message(
                    [new_data_part({"assessment_id": assessment_id, "state": state})]
                ),
                metadata={"assessment_id": assessment_id},
            )

    async def _wait(self, assessment_id: str) -> str:
        wait = self.wait_seconds
        if wait is None:
            wait = get_settings().a2a_task_wait_seconds
        deadline = asyncio.get_event_loop().time() + max(1, int(wait))
        sm = get_sessionmaker()
        state = ""
        while asyncio.get_event_loop().time() < deadline:
            async with sm() as session:
                a = await session.get(Assessment, assessment_id)
                state = a.state if a else AssessmentState.FAILED.value
            if state in TERMINAL:
                return state
            await asyncio.sleep(0.25)
        return state

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        task = context.current_task
        assessment_id = ""
        if task is not None and task.metadata:
            try:
                assessment_id = str(dict(task.metadata).get("assessment_id") or "")
            except Exception:  # noqa: BLE001
                assessment_id = ""
        user = context.call_context.user if context.call_context else None
        org_id = user.user_name if user and user.is_authenticated else ""
        if assessment_id and org_id:
            sm = get_sessionmaker()
            async with sm() as session:
                a = await session.get(Assessment, assessment_id)
                if a and a.org_id == org_id and a.state not in TERMINAL:
                    a.cancel_requested = True
                    await write_audit(
                        session,
                        org_id=org_id,
                        assessment_id=assessment_id,
                        event="assessment.cancel_requested",
                        data={"via": "a2a", "task_id": context.task_id},
                    )
                    from app.orchestration import engine as orchestrator

                    if not orchestrator.is_running(assessment_id):
                        a.state = AssessmentState.CANCELLED.value
                    await session.commit()
        await updater.cancel(
            updater.new_agent_message(
                [new_data_part({"assessment_id": assessment_id, "state": "cancel_requested"})]
            )
        )


class LazyDatabaseTaskStore(TaskStore):
    """Owner-scoped durable task store bound to the *current* application engine.

    The engine is created lazily (and re-created by tests), so the SDK store is built on
    first use instead of at import time.
    """

    def __init__(self, table_name: str = "a2a_tasks"):
        self._table = table_name
        self._store: DatabaseTaskStore | None = None
        self._engine = None

    def _delegate(self) -> DatabaseTaskStore:
        engine = get_engine()
        if self._store is None or engine is not self._engine:
            self._engine = engine
            self._store = DatabaseTaskStore(engine, create_table=True, table_name=self._table)
        return self._store

    async def save(self, task, context: ServerCallContext) -> None:
        await self._delegate().save(task, context)

    async def get(self, task_id: str, context: ServerCallContext):
        return await self._delegate().get(task_id, context)

    async def delete(self, task_id: str, context: ServerCallContext) -> None:
        await self._delegate().delete(task_id, context)

    async def list(self, *args, **kwargs):
        return await self._delegate().list(*args, **kwargs)


def build_a2a_routes(*, rpc_path: str = "/a2a") -> tuple[list, list, AgentCard]:
    """Agent-card routes and JSON-RPC routes for mounting into FastAPI."""
    card = build_agent_card()
    handler = DefaultRequestHandler(
        agent_executor=SentrikAgentExecutor(),
        task_store=LazyDatabaseTaskStore(),
        agent_card=card,
    )
    return create_agent_card_routes(card), create_jsonrpc_routes(handler, rpc_path), card
