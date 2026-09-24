"""Conversational interface + agent-skill registry.

The chat endpoint is a documented connector: it maps natural-language intents to
concrete platform actions (list targets, start assessment, get status, summarize
findings) and returns both a reply and the structured `actions` taken, so the same
capabilities are reachable conversationally or via typed APIs. Intent parsing is
deterministic (keyword+context); an LLM brain can enrich phrasing but never performs
a privileged action the typed API would not allow.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.registry import parse_skill_md, register_manifest, seed_builtin_skills
from app.api.schemas import ChatReply, ChatRequest, SkillOut, SkillRegister
from app.core.auth import Principal, get_principal, require_role
from app.core.db import get_session
from app.core.enums import AssessmentState, Role
from app.models import AgentSkill, Assessment, ChatMessage, ChatSession, Finding, Target
from app.orchestration import engine as orchestrator

router = APIRouter(tags=["chat"], prefix="/v1")


@router.post("/chat", response_model=ChatReply)
async def chat(
    body: ChatRequest,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    # resolve or create a chat session
    chat_session = None
    if body.session_id:
        chat_session = await session.get(ChatSession, body.session_id)
        if chat_session and chat_session.org_id != principal.org_id:
            raise HTTPException(status_code=404, detail="chat session not found")
    if chat_session is None:
        chat_session = ChatSession(
            org_id=principal.org_id,
            assessment_id=body.assessment_id,
            title=body.message[:60],
        )
        session.add(chat_session)
        await session.flush()

    session.add(
        ChatMessage(session_id=chat_session.id, role="user", content=body.message)
    )

    reply, actions = await _handle_intent(
        session, principal, body.message, body.assessment_id
    )

    session.add(
        ChatMessage(
            session_id=chat_session.id, role="assistant", content=reply, actions=actions
        )
    )
    await session.commit()
    return ChatReply(session_id=chat_session.id, reply=reply, actions=actions)


async def _handle_intent(session, principal, message: str, assessment_id: str | None):
    text = message.lower().strip()
    actions: list[dict] = []

    # status intent
    if any(w in text for w in ("status", "progress", "how is", "where is")):
        aid = _extract_id(message) or assessment_id
        if aid:
            a = await session.get(Assessment, aid)
            if a and a.org_id == principal.org_id:
                findings = (
                    await session.execute(
                        select(func.count())
                        .select_from(Finding)
                        .where(Finding.assessment_id == aid)
                    )
                ).scalar() or 0
                actions.append({"type": "get_status", "assessment_id": aid})
                risk = (a.summary or {}).get("risk", {})
                return (
                    f"Assessment {aid} is in state '{a.state}' with {a.requests_made} "
                    f"requests made and {findings} findings so far. "
                    f"Risk grade: {risk.get('grade', 'n/a')}."
                ), actions
        return "Tell me which assessment (id) you'd like the status of.", actions

    # start intent
    if (
        text.startswith("start")
        or "run assessment" in text
        or "begin assessment" in text
    ):
        aid = _extract_id(message) or assessment_id
        if not aid:
            return "Which assessment id should I start?", actions
        a = await session.get(Assessment, aid)
        if not a or a.org_id != principal.org_id:
            return f"I couldn't find assessment {aid}.", actions
        if a.state not in (AssessmentState.CREATED.value, AssessmentState.FAILED.value):
            return f"Assessment {aid} is already {a.state}; cannot start.", actions
        if principal.role == Role.VIEWER:
            return (
                "You need at least the operator role to start an assessment.",
                actions,
            )
        orchestrator.start_assessment(aid)
        actions.append({"type": "start_assessment", "assessment_id": aid})
        return f"Started assessment {aid}. Ask me for its status any time.", actions

    # list targets
    if "target" in text and any(w in text for w in ("list", "show", "what")):
        rows = (
            (
                await session.execute(
                    select(Target).where(Target.org_id == principal.org_id)
                )
            )
            .scalars()
            .all()
        )
        actions.append({"type": "list_targets", "count": len(rows)})
        if not rows:
            return "You have no targets yet. Create one via POST /v1/targets.", actions
        listing = ", ".join(f"{t.name} ({t.id})" for t in rows[:10])
        return f"You have {len(rows)} target(s): {listing}.", actions

    # summarize findings
    if "finding" in text or "vulnerab" in text or "summar" in text:
        aid = _extract_id(message) or assessment_id
        if aid:
            findings = (
                (
                    await session.execute(
                        select(Finding).where(Finding.assessment_id == aid)
                    )
                )
                .scalars()
                .all()
            )
            actions.append({"type": "summarize_findings", "assessment_id": aid})
            if not findings:
                return f"No findings recorded for {aid} yet.", actions
            by_sev: dict[str, int] = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            top = sorted(findings, key=lambda x: x.risk_score, reverse=True)[:3]
            top_txt = "; ".join(f"{t.title} ({t.severity}, {t.status})" for t in top)
            return (
                f"{len(findings)} findings by severity {by_sev}. Top: {top_txt}."
            ), actions
        return "Which assessment's findings should I summarize?", actions

    # help / fallback
    return (
        "I can: list targets, start an assessment, report assessment status, and "
        "summarize findings. Try 'start assessment <id>' or 'status of <id>'. "
        "For onboarding, authorization, and discovery use the documented /v1 APIs."
    ), actions


def _extract_id(message: str) -> str | None:
    m = re.search(r"\b([0-9a-f]{32})\b", message)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# Agent-skill registry
# --------------------------------------------------------------------------- #
@router.get("/skills", response_model=list[SkillOut])
async def list_skills(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    # ensure built-in check skills are present (idempotent upsert)
    await seed_builtin_skills(session)
    await session.commit()
    # tenant view: shared built-ins (org_id NULL) + this org's own registered skills
    rows = (
        (
            await session.execute(
                select(AgentSkill).where(
                    (AgentSkill.org_id.is_(None))
                    | (AgentSkill.org_id == principal.org_id)
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        SkillOut(
            id=r.id,
            name=r.name,
            version=r.version,
            check_class=r.check_class,
            enabled=r.enabled,
            provenance=r.provenance,
            manifest=r.manifest or {},
        )
        for r in rows
    ]


@router.post("/skills", response_model=SkillOut, status_code=201)
async def register_skill(
    body: SkillRegister,
    principal: Principal = Depends(require_role(Role.ADMIN)),
    session: AsyncSession = Depends(get_session),
):
    await seed_builtin_skills(
        session
    )  # ensure builtins present alongside the new skill
    manifest = parse_skill_md(body.skill_md)
    row = await register_manifest(
        session, manifest, provenance="skill_md", org_id=principal.org_id
    )
    await session.commit()
    await session.refresh(row)
    out = SkillOut(
        id=row.id,
        name=row.name,
        version=row.version,
        check_class=row.check_class,
        enabled=row.enabled,
        provenance=row.provenance,
        manifest=row.manifest or {},
    )
    return out
