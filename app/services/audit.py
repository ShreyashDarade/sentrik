"""Audit trail helper — traceable agent decisions, tool calls, policy evaluations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


async def write_audit(
    session: AsyncSession,
    *,
    org_id: str,
    event: str,
    assessment_id: str | None = None,
    actor: str = "system",
    data: dict | None = None,
) -> AuditLog:
    row = AuditLog(
        org_id=org_id,
        assessment_id=assessment_id,
        actor=actor,
        event=event,
        data=data or {},
    )
    session.add(row)
    await session.flush()
    return row


async def list_audit(
    session: AsyncSession, *, org_id: str, assessment_id: str, limit: int = 500
):
    stmt = (
        select(AuditLog)
        .where(AuditLog.org_id == org_id, AuditLog.assessment_id == assessment_id)
        .order_by(AuditLog.created_at.asc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())
