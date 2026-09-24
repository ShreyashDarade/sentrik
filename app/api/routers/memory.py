"""Durable, tenant-isolated project memory API (AG-MEM).

Stores small facts an assessment can carry forward (learned auth flows, known false
positives, stable object ids). Every read/write is org-scoped; one tenant can never
see another's memory.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Principal, get_principal, require_role
from app.core.db import get_session
from app.core.enums import Role
from app.models import ProjectMemory
from app.services.audit import write_audit

router = APIRouter(tags=["memory"], prefix="/v1")


@router.get("/memory")
async def list_memory(
    target_id: str | None = Query(default=None),
    key: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(ProjectMemory).where(ProjectMemory.org_id == principal.org_id)
    if target_id:
        stmt = stmt.where(ProjectMemory.target_id == target_id)
    if key:
        stmt = stmt.where(ProjectMemory.key == key)
    stmt = stmt.order_by(ProjectMemory.updated_at.desc()).limit(limit).offset(offset)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "items": [
            {
                "id": r.id,
                "target_id": r.target_id,
                "key": r.key,
                "value": r.value,
                "kind": r.kind,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rows
        ],
        "limit": limit,
        "offset": offset,
    }


@router.put("/memory")
async def upsert_memory(
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    key = body.get("key")
    if not key:
        raise HTTPException(status_code=422, detail="'key' is required")
    target_id = body.get("target_id")
    existing = (
        await session.execute(
            select(ProjectMemory).where(
                ProjectMemory.org_id == principal.org_id,
                ProjectMemory.target_id == target_id,
                ProjectMemory.key == key,
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.value = body.get("value", existing.value)
        existing.kind = body.get("kind", existing.kind)
        row = existing
    else:
        row = ProjectMemory(
            org_id=principal.org_id,
            target_id=target_id,
            key=key,
            value=body.get("value", {}),
            kind=body.get("kind", "note"),
        )
        session.add(row)
    await write_audit(
        session,
        org_id=principal.org_id,
        event="memory.upsert",
        data={"key": key, "target_id": target_id},
    )
    await session.commit()
    await session.refresh(row)
    return {
        "id": row.id,
        "key": row.key,
        "target_id": row.target_id,
        "value": row.value,
        "kind": row.kind,
    }


@router.delete("/memory/{memory_id}", status_code=204)
async def delete_memory(
    memory_id: str,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    row = await session.get(ProjectMemory, memory_id)
    if not row or row.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="not found")
    await session.delete(row)
    await session.commit()
