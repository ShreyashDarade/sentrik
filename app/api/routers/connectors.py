"""Connector APIs: ingest discovery inputs from a spec URL or a repository raw file,
and a CI/CD webhook that triggers change-based retesting.

Fetching a spec is metadata retrieval (not target attack traffic), but it is still
SSRF-guarded: the fetch destination is classified by NetGuard and private/loopback/
metadata endpoints are refused. A connector produces a real assessment (with the
fetched artifact) bound to a verified authorization record.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Principal, require_role
from app.core.db import get_session
from app.core.enums import AssessmentState, Role, VerificationStatus
from app.models import Assessment, AuthorizationRecord, DiscoveryArtifact, Target
from app.orchestration import engine as orchestrator
from app.security.netguard import NetGuardError, parse_url, resolve_host
from app.services.audit import write_audit

router = APIRouter(tags=["connectors"], prefix="/v1")


async def _guarded_fetch(url: str) -> str:
    """Fetch a spec/artifact over HTTP(S), refusing SSRF-prone destinations."""
    try:
        _scheme, host, port, _path = parse_url(url)
        info = resolve_host(host, port, allow_dns=True)
    except NetGuardError as exc:
        raise HTTPException(status_code=422, detail=f"invalid/unsafe URL: {exc}")
    if info.is_hard_blocked or info.is_private or info.is_loopback:
        raise HTTPException(
            status_code=422,
            detail="connector fetch destination is private/loopback/metadata (refused)",
        )
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            resp = await client.get(url)
        if resp.status_code >= 400:
            raise HTTPException(
                status_code=422,
                detail=f"connector fetch failed: HTTP {resp.status_code}",
            )
        return resp.text
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=422, detail=f"connector fetch error: {exc}")


async def _get_target(session, principal, target_id) -> Target:
    row = await session.get(Target, target_id)
    if not row or row.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="target not found")
    return row


async def _verified_authz(
    session, principal, target_id, authorization_id
) -> AuthorizationRecord:
    rec = await session.get(AuthorizationRecord, authorization_id)
    if not rec or rec.org_id != principal.org_id or rec.target_id != target_id:
        raise HTTPException(
            status_code=404, detail="authorization not found for target"
        )
    if rec.status != VerificationStatus.VERIFIED.value:
        raise HTTPException(status_code=403, detail="authorization not verified")
    return rec


async def _create_assessment_with_artifact(
    session: AsyncSession,
    principal: Principal,
    target_id: str,
    authorization_id: str,
    kind: str,
    content: str,
    filename: str,
    requested: list[str],
    start: bool,
) -> Assessment:
    assessment = Assessment(
        org_id=principal.org_id,
        target_id=target_id,
        authorization_id=authorization_id,
        state=AssessmentState.CREATED.value,
        requested_check_classes=requested or [],
    )
    session.add(assessment)
    await session.flush()
    session.add(
        DiscoveryArtifact(
            org_id=principal.org_id,
            assessment_id=assessment.id,
            kind=kind,
            filename=filename,
            content=content,
        )
    )
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment.id,
        event="connector.ingested",
        data={"kind": kind, "filename": filename},
    )
    await session.commit()
    await session.refresh(assessment)
    if start:
        orchestrator.start_assessment(assessment.id)
    return assessment


@router.post("/targets/{target_id}/connectors/spec-url", status_code=201)
async def connect_spec_url(
    target_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Ingest an OpenAPI/GraphQL/Postman spec from a URL and create an assessment.

    body: {url, authorization_id, kind?=openapi, requested_check_classes?=[], start?=false}
    """
    url = body.get("url")
    authz = body.get("authorization_id")
    if not url or not authz:
        raise HTTPException(
            status_code=422, detail="url and authorization_id are required"
        )
    kind = body.get("kind", "openapi")
    await _get_target(session, principal, target_id)
    await _verified_authz(session, principal, target_id, authz)
    content = await _guarded_fetch(url)
    a = await _create_assessment_with_artifact(
        session,
        principal,
        target_id,
        authz,
        kind,
        content,
        url,
        body.get("requested_check_classes", []),
        bool(body.get("start", False)),
    )
    return {"assessment_id": a.id, "state": a.state, "source": url, "kind": kind}


@router.post("/targets/{target_id}/connectors/repo", status_code=201)
async def connect_repo(
    target_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Ingest an API spec from a repository raw-file URL (e.g. raw.githubusercontent.com).

    body: {raw_spec_url, authorization_id, kind?=openapi, requested_check_classes?=[], start?}
    """
    url = body.get("raw_spec_url")
    authz = body.get("authorization_id")
    if not url or not authz:
        raise HTTPException(
            status_code=422, detail="raw_spec_url and authorization_id are required"
        )
    await _get_target(session, principal, target_id)
    await _verified_authz(session, principal, target_id, authz)
    content = await _guarded_fetch(url)
    a = await _create_assessment_with_artifact(
        session,
        principal,
        target_id,
        authz,
        body.get("kind", "openapi"),
        content,
        url,
        body.get("requested_check_classes", []),
        bool(body.get("start", False)),
    )
    return {"assessment_id": a.id, "state": a.state, "source": url, "connector": "repo"}


@router.post("/webhooks/ci/{target_id}", status_code=202)
async def ci_webhook(
    target_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """CI/CD change-trigger: retest the most recent assessment for the target (BE-11).

    body: {authorization_id?, event?, requested_check_classes?, start?=true}
    """
    await _get_target(session, principal, target_id)
    prev = (
        (
            await session.execute(
                select(Assessment)
                .where(
                    Assessment.target_id == target_id,
                    Assessment.org_id == principal.org_id,
                )
                .order_by(Assessment.created_at.desc())
            )
        )
        .scalars()
        .first()
    )
    if prev is None:
        raise HTTPException(
            status_code=404, detail="no prior assessment to retest for this target"
        )
    authz = body.get("authorization_id", prev.authorization_id)
    await _verified_authz(session, principal, target_id, authz)

    new = Assessment(
        org_id=principal.org_id,
        target_id=target_id,
        authorization_id=authz,
        state=AssessmentState.CREATED.value,
        is_retest=True,
        previous_assessment_id=prev.id,
        requested_check_classes=body.get(
            "requested_check_classes", prev.requested_check_classes
        ),
    )
    session.add(new)
    await session.flush()
    # carry forward artifacts
    for art in (
        (
            await session.execute(
                select(DiscoveryArtifact).where(
                    DiscoveryArtifact.assessment_id == prev.id
                )
            )
        )
        .scalars()
        .all()
    ):
        session.add(
            DiscoveryArtifact(
                org_id=principal.org_id,
                assessment_id=new.id,
                kind=art.kind,
                filename=art.filename,
                content=art.content,
                endpoint_url=art.endpoint_url,
            )
        )
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=new.id,
        event="connector.ci_triggered",
        data={"event": body.get("event", "ci"), "previous": prev.id},
    )
    await session.commit()
    if body.get("start", True):
        orchestrator.start_assessment(new.id)
    return {
        "assessment_id": new.id,
        "is_retest": True,
        "previous_assessment_id": prev.id,
        "triggered_by": body.get("event", "ci"),
    }
