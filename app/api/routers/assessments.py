"""Assessment lifecycle API: create, run, monitor, cancel, findings, report, retest."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    ArtifactOut,
    AssessmentCreate,
    AssessmentOut,
    AssessmentProgress,
    EndpointOut,
    EvidenceOut,
    FindingOut,
    PlanStepOut,
    RetestCreate,
    StepDecision,
)
from app.core.auth import Principal, get_principal, require_role
from app.core.db import get_session, get_sessionmaker
from app.core.enums import AssessmentState, FindingStatus, Role
from app.models import (
    Assessment,
    AuthorizationRecord,
    Coverage,
    DiscoveryArtifact,
    Endpoint,
    Evidence,
    Finding,
    PlanStep,
    ProjectMemory,
    RegressionTest,
    Target,
)
from app.orchestration import engine as orchestrator
from app.security.http_client import GuardedHttpClient
from app.security.scope import ScopeGuard
from app.services import reporting
from app.services.assessment_service import (
    AssessmentCreateError,
    build_report,
    finding_dict,
)
from app.services.assessment_service import create_assessment as create_assessment_record
from app.services.audit import list_audit, write_audit
from app.services.regression import build_regression_definition, run_regression

router = APIRouter(tags=["assessments"], prefix="/v1")


# --------------------------------------------------------------------------- #
# create / start / monitor / cancel
# --------------------------------------------------------------------------- #
@router.post("/assessments", response_model=AssessmentOut, status_code=201)
async def create_assessment(
    body: AssessmentCreate,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    try:
        assessment = await create_assessment_record(
            session,
            org_id=principal.org_id,
            target_id=body.target_id,
            authorization_id=body.authorization_id,
            requested_check_classes=body.requested_check_classes,
            artifacts=[art.model_dump() for art in body.artifacts],
        )
    except AssessmentCreateError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    await session.commit()
    await session.refresh(assessment)
    return _assessment_out(assessment)


@router.post("/assessments/{assessment_id}/start", response_model=AssessmentOut)
async def start_assessment(
    assessment_id: str,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    if a.state not in (AssessmentState.CREATED.value, AssessmentState.FAILED.value):
        raise HTTPException(
            status_code=409, detail=f"cannot start from state {a.state}"
        )
    a.cancel_requested = False
    a.error = ""
    await session.commit()
    orchestrator.start_assessment(assessment_id)
    await session.refresh(a)
    return _assessment_out(a)


@router.get("/assessments", response_model=list[AssessmentOut])
async def list_assessments(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    rows = (
        (
            await session.execute(
                select(Assessment)
                .where(Assessment.org_id == principal.org_id)
                .order_by(Assessment.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return [_assessment_out(r) for r in rows]


@router.get("/assessments/{assessment_id}", response_model=AssessmentOut)
async def get_assessment(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    return _assessment_out(a)


@router.get("/assessments/{assessment_id}/progress", response_model=AssessmentProgress)
async def progress(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    endpoints = (
        await session.execute(
            select(func.count())
            .select_from(Endpoint)
            .where(Endpoint.assessment_id == assessment_id)
        )
    ).scalar() or 0
    steps = (
        await session.execute(
            select(func.count())
            .select_from(PlanStep)
            .where(PlanStep.assessment_id == assessment_id)
        )
    ).scalar() or 0
    findings = (
        (
            await session.execute(
                select(Finding).where(Finding.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )
    by_status: dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
    return AssessmentProgress(
        id=a.id,
        state=a.state,
        requests_made=a.requests_made,
        endpoints=endpoints,
        plan_steps=steps,
        findings=len(findings),
        findings_by_status=by_status,
        risk=(a.summary or {}).get("risk", {}),
        agents_instantiated=(a.summary or {}).get("agents_instantiated", 0),
    )


@router.get("/assessments/{assessment_id}/stream")
async def stream_progress(
    assessment_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    """Server-Sent Events stream of live assessment progress (BE-04).

    Emits a JSON `progress` event whenever the state/findings/requests change, and a
    final `done` event at a terminal state. Closes when the client disconnects.
    """
    await _get_assessment(session, principal, assessment_id)
    org_id = principal.org_id
    terminal = {
        AssessmentState.COMPLETED.value,
        AssessmentState.FAILED.value,
        AssessmentState.CANCELLED.value,
    }

    async def gen():
        last = None
        deadline = asyncio.get_event_loop().time() + 300  # hard cap 5 min
        while asyncio.get_event_loop().time() < deadline:
            if await request.is_disconnected():
                break
            async with get_sessionmaker()() as s:
                a = await s.get(Assessment, assessment_id)
                if a is None or a.org_id != org_id:
                    break
                fcount = (
                    await s.execute(
                        select(func.count())
                        .select_from(Finding)
                        .where(Finding.assessment_id == assessment_id)
                    )
                ).scalar() or 0
                snapshot = {
                    "state": a.state,
                    "requests_made": a.requests_made,
                    "findings": fcount,
                    "risk": (a.summary or {}).get("risk", {}).get("grade"),
                }
            if snapshot != last:
                yield f"event: progress\ndata: {json.dumps(snapshot)}\n\n"
                last = snapshot
            if snapshot["state"] in terminal:
                yield f"event: done\ndata: {json.dumps(snapshot)}\n\n"
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/assessments/{assessment_id}/findings/{finding_id}/triage")
async def triage_finding(
    assessment_id: str,
    finding_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """False-positive investigation & correction workflow (EX-11).

    An operator can set a finding's status to `rejected` (false positive), `confirmed`
    (accept), or `suspected` (reopen a previously rejected finding for re-validation).
    A rejection is recorded as a known-FP in project memory so future assessments of the
    same target can be informed. The change is audited.
    """
    a = await _get_assessment(session, principal, assessment_id)
    finding = await session.get(Finding, finding_id)
    if not finding or finding.assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="finding not found")
    new_status = str(body.get("status", "")).lower()
    allowed = {
        FindingStatus.REJECTED.value,
        FindingStatus.CONFIRMED.value,
        FindingStatus.SUSPECTED.value,
    }
    if new_status not in allowed:
        raise HTTPException(
            status_code=422, detail=f"status must be one of {sorted(allowed)}"
        )
    reason = str(body.get("reason", ""))[:1000]
    old_status = finding.status
    finding.status = new_status
    # record a rejection as a known false-positive in tenant project memory
    if new_status == FindingStatus.REJECTED.value:
        session.add(
            ProjectMemory(
                org_id=principal.org_id,
                target_id=a.target_id,
                key=f"known_fp:{finding.dedup_key}",
                value={
                    "finding_id": finding.id,
                    "title": finding.title,
                    "reason": reason,
                },
                kind="false_positive",
            )
        )
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        actor=principal.user_id,
        event="finding.triaged",
        data={
            "finding_id": finding.id,
            "from": old_status,
            "to": new_status,
            "reason": reason,
        },
    )
    await session.commit()
    return {"finding_id": finding.id, "status": new_status, "previous": old_status}


@router.post("/assessments/{assessment_id}/traffic", status_code=201)
async def ingest_traffic(
    assessment_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Authorized live network-traffic observation (BE-03).

    Accepts observed request exchanges (e.g. from a proxy the operator runs) and adds the
    in-scope ones to the endpoint inventory with TRAFFIC provenance. Out-of-scope hosts
    are refused deny-by-default. Body: {entries: [{method, url, params?:[{name}], auth?}]}.
    """
    from urllib.parse import urlsplit

    from app.core.enums import Provenance
    from app.discovery.normalize import DiscoveredEndpoint, endpoint_fingerprint
    from app.security.scope import ScopeGuard

    a = await _get_assessment(session, principal, assessment_id)
    record = await session.get(AuthorizationRecord, a.authorization_id)
    guard = ScopeGuard(record)
    entries = body.get("entries", [])
    if not isinstance(entries, list) or not entries:
        raise HTTPException(
            status_code=422, detail="'entries' must be a non-empty list"
        )

    existing = {
        fp
        for (fp,) in (
            await session.execute(
                select(Endpoint.fingerprint).where(
                    Endpoint.assessment_id == assessment_id
                )
            )
        ).all()
    }
    added, skipped_scope, skipped_dup = 0, 0, 0
    for entry in entries[:2000]:
        url = str(entry.get("url", ""))
        method = str(entry.get("method", "GET")).upper()
        if not url:
            continue
        host = (urlsplit(url).hostname or "").lower()
        if not guard.evaluate_new_asset(host).allowed:
            skipped_scope += 1
            continue
        de = DiscoveredEndpoint(
            method=method,
            url=url,
            provenance=Provenance.TRAFFIC,
            parameters=[
                {
                    "name": p.get("name", ""),
                    "in": p.get("in", "query"),
                    "type": "string",
                    "required": False,
                }
                for p in (entry.get("params") or [])
                if isinstance(p, dict) and p.get("name")
            ],
            auth_required=bool(entry.get("auth")),
        )
        fp = endpoint_fingerprint(method, url, de.path_template)
        if fp in existing:
            skipped_dup += 1
            continue
        existing.add(fp)
        session.add(
            Endpoint(
                org_id=principal.org_id,
                assessment_id=assessment_id,
                method=de.method,
                url=de.url,
                path_template=de.path_template,
                parameters=de.parameters,
                request_body_schema={},
                auth_required=de.auth_required,
                roles=[],
                api_version=de.api_version,
                provenance=Provenance.TRAFFIC.value,
                confidence=de.confidence,
                fingerprint=fp,
            )
        )
        added += 1
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="traffic.ingested",
        data={
            "added": added,
            "skipped_out_of_scope": skipped_scope,
            "skipped_dup": skipped_dup,
        },
    )
    await session.commit()
    return {
        "added": added,
        "skipped_out_of_scope": skipped_scope,
        "skipped_duplicate": skipped_dup,
    }


@router.post("/assessments/cancel-all")
async def cancel_all(
    principal: Principal = Depends(require_role(Role.ADMIN)),
    session: AsyncSession = Depends(get_session),
):
    """Emergency stop-all: request cancellation of every running assessment in the org
    (F-04). Honored at the next phase/step boundary of each run."""
    terminal = {
        AssessmentState.COMPLETED.value,
        AssessmentState.CANCELLED.value,
        AssessmentState.FAILED.value,
    }
    rows = (
        (
            await session.execute(
                select(Assessment).where(
                    Assessment.org_id == principal.org_id,
                    Assessment.state.notin_(list(terminal)),
                )
            )
        )
        .scalars()
        .all()
    )
    for a in rows:
        a.cancel_requested = True
    await write_audit(
        session,
        org_id=principal.org_id,
        event="assessment.cancel_all",
        data={"count": len(rows)},
    )
    await session.commit()
    return {"cancel_requested": len(rows), "assessment_ids": [a.id for a in rows]}


@router.post("/assessments/{assessment_id}/cancel", response_model=AssessmentOut)
async def cancel(
    assessment_id: str,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    if a.state in (
        AssessmentState.COMPLETED.value,
        AssessmentState.CANCELLED.value,
        AssessmentState.FAILED.value,
    ):
        raise HTTPException(status_code=409, detail=f"assessment already {a.state}")
    a.cancel_requested = True
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="assessment.cancel_requested",
        data={},
    )
    # A run with no live task (never started, or parked on an approval interrupt in
    # graph mode — B-04) has nothing to honour the flag, so finalize it right here.
    if not orchestrator.is_running(assessment_id):
        a.state = AssessmentState.CANCELLED.value
        a.finished_at = datetime.now(UTC)
        await write_audit(
            session,
            org_id=principal.org_id,
            assessment_id=assessment_id,
            event="assessment.cancelled",
            data={"while": "not_running"},
        )
    await session.commit()
    await session.refresh(a)
    return _assessment_out(a)


# --------------------------------------------------------------------------- #
# plan steps + per-action approval (CP-03)
# --------------------------------------------------------------------------- #
def _step_out(s: PlanStep) -> PlanStepOut:
    return PlanStepOut(
        id=s.id,
        assessment_id=s.assessment_id,
        endpoint_id=s.endpoint_id,
        check_class=s.check_class,
        check_name=s.check_name,
        intensity=s.intensity,
        priority=s.priority,
        status=s.status,
        rationale=s.rationale or "",
        policy_decision=s.policy_decision or {},
    )


@router.get("/assessments/{assessment_id}/steps", response_model=list[PlanStepOut])
async def list_steps(
    assessment_id: str,
    status: str | None = Query(default=None),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    """List plan steps; filter with ``?status=awaiting_approval`` to see held actions."""
    await _get_assessment(session, principal, assessment_id)
    stmt = select(PlanStep).where(PlanStep.assessment_id == assessment_id)
    if status:
        stmt = stmt.where(PlanStep.status == status)
    rows = (await session.execute(stmt.order_by(PlanStep.priority))).scalars().all()
    return [_step_out(s) for s in rows]


async def _held_step(session, principal, assessment_id, step_id) -> PlanStep:
    await _get_assessment(session, principal, assessment_id)
    step = await session.get(PlanStep, step_id)
    if not step or step.assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="plan step not found")
    if step.status != "awaiting_approval":
        raise HTTPException(
            status_code=409, detail=f"step is {step.status}, not awaiting_approval"
        )
    return step


@router.post(
    "/assessments/{assessment_id}/steps/{step_id}/approve",
    response_model=PlanStepOut,
)
async def approve_step(
    assessment_id: str,
    step_id: str,
    body: StepDecision | None = None,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Approve one held state-changing/invasive step (CP-03).

    While the assessment is still running, the engine's bounded approval wait picks the
    step up. If the run has already finished, the step is executed now in the background
    under a fresh scope-guarded client (same authorization record, budgets and sandbox),
    followed by independent validation and re-scoring.
    """
    step = await _held_step(session, principal, assessment_id, step_id)
    a = await session.get(Assessment, assessment_id)
    step.status = "approved"
    step.policy_decision = {
        **(step.policy_decision or {}),
        "approved_by": principal.user_id,
        "approval_note": (body.note if body else ""),
    }
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        actor=principal.user_id,
        event="step.approved",
        data={"step_id": step_id, "check_name": step.check_name, "note": body.note if body else ""},
    )
    await session.commit()
    await session.refresh(step)
    if a.state in (
        AssessmentState.COMPLETED.value,
        AssessmentState.CANCELLED.value,
        AssessmentState.FAILED.value,
    ):
        orchestrator.start_approved_steps(assessment_id, [step_id])
    else:
        await _resume_if_parked(session, a)
    return _step_out(step)


async def _resume_if_parked(session: AsyncSession, a: Assessment) -> None:
    """B-04: a graph-mode run parked on approvals continues once nothing is held."""
    if orchestrator.is_running(a.id) or a.state != AssessmentState.POLICY_CHECK.value:
        return
    remaining = (
        await session.execute(
            select(func.count(PlanStep.id)).where(
                PlanStep.assessment_id == a.id,
                PlanStep.status == "awaiting_approval",
            )
        )
    ).scalar_one()
    if remaining == 0:
        orchestrator.start_assessment(a.id)


@router.post(
    "/assessments/{assessment_id}/steps/{step_id}/deny",
    response_model=PlanStepOut,
)
async def deny_step(
    assessment_id: str,
    step_id: str,
    body: StepDecision | None = None,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    step = await _held_step(session, principal, assessment_id, step_id)
    step.status = "denied"
    step.policy_decision = {
        **(step.policy_decision or {}),
        "denied_by": principal.user_id,
        "denial_note": (body.note if body else ""),
    }
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        actor=principal.user_id,
        event="step.denied",
        data={"step_id": step_id, "check_name": step.check_name},
    )
    await session.commit()
    await session.refresh(step)
    a = await session.get(Assessment, assessment_id)
    if a is not None:
        await _resume_if_parked(session, a)
    return _step_out(step)


# --------------------------------------------------------------------------- #
# artifacts / endpoints / findings / evidence / coverage
# --------------------------------------------------------------------------- #
@router.get("/assessments/{assessment_id}/artifacts", response_model=list[ArtifactOut])
async def list_artifacts(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_assessment(session, principal, assessment_id)
    rows = (
        (
            await session.execute(
                select(DiscoveryArtifact).where(
                    DiscoveryArtifact.assessment_id == assessment_id
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        ArtifactOut(
            id=r.id,
            kind=r.kind,
            filename=r.filename,
            parsed=r.parsed,
            warnings=r.warnings or [],
        )
        for r in rows
    ]


@router.get("/assessments/{assessment_id}/endpoints", response_model=list[EndpointOut])
async def list_endpoints(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_assessment(session, principal, assessment_id)
    rows = (
        (
            await session.execute(
                select(Endpoint).where(Endpoint.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )
    return [
        EndpointOut(
            id=r.id,
            method=r.method,
            url=r.url,
            path_template=r.path_template,
            parameters=r.parameters or [],
            auth_required=r.auth_required,
            api_version=r.api_version,
            provenance=r.provenance,
            confidence=r.confidence,
        )
        for r in rows
    ]


@router.get("/assessments/{assessment_id}/findings", response_model=list[FindingOut])
async def list_findings(
    assessment_id: str,
    status: str | None = Query(default=None),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    await _get_assessment(session, principal, assessment_id)
    stmt = select(Finding).where(Finding.assessment_id == assessment_id)
    if status:
        stmt = stmt.where(Finding.status == status)
    rows = (
        (
            await session.execute(
                stmt.order_by(Finding.risk_score.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return [_finding_out(r) for r in rows]


@router.get(
    "/assessments/{assessment_id}/findings/{finding_id}/evidence",
    response_model=list[EvidenceOut],
)
async def finding_evidence(
    assessment_id: str,
    finding_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_assessment(session, principal, assessment_id)
    rows = (
        (
            await session.execute(
                select(Evidence).where(
                    Evidence.assessment_id == assessment_id,
                    Evidence.finding_id == finding_id,
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        EvidenceOut(
            id=r.id,
            kind=r.kind,
            request=r.request,
            response=r.response,
            note=r.note,
            lineage=r.lineage,
        )
        for r in rows
    ]


@router.get("/assessments/{assessment_id}/coverage")
async def coverage(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_assessment(session, principal, assessment_id)
    rows = (
        (
            await session.execute(
                select(Coverage).where(Coverage.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )
    tested = sum(1 for r in rows if r.tested)
    return {
        "denominator": len(rows),
        "tested": tested,
        "untested": len(rows) - tested,
        "coverage_ratio": round(tested / len(rows), 3) if rows else 0.0,
        "note": "Untested endpoint/check pairs are UNKNOWN risk, not confirmed-safe.",
        "pairs": [
            {
                "endpoint_id": r.endpoint_id,
                "check_class": r.check_class,
                "tested": r.tested,
                "reason_untested": r.reason_untested,
            }
            for r in rows[:500]
        ],
    }


@router.get("/assessments/{assessment_id}/audit")
async def audit_trail(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_assessment(session, principal, assessment_id)
    rows = await list_audit(
        session, org_id=principal.org_id, assessment_id=assessment_id
    )
    return [
        {
            "event": r.event,
            "actor": r.actor,
            "data": r.data,
            "at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@router.get("/assessments/{assessment_id}/report")
async def report(
    assessment_id: str,
    fmt: str = Query(default="json"),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    payload = await build_report(session, a)
    if fmt == "markdown":
        return Response(
            content=reporting.render_markdown(payload), media_type="text/markdown"
        )
    if fmt == "pdf":
        from app.services.pdf_report import text_to_pdf

        pdf = text_to_pdf(reporting.render_markdown(payload))
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report-{a.id}.pdf"'
            },
        )
    return payload


@router.post("/assessments/{assessment_id}/report/export")
async def export_report(
    assessment_id: str,
    fmt: str = Query(default="pdf"),
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Render the report and store it via the configured object-storage backend
    (db/local/s3). Returns a persistable ObjectRef the caller can keep."""
    from app.services.storage import get_storage

    # reuse the report renderer
    payload = await report(assessment_id, fmt="json", principal=principal, session=session)
    if fmt == "markdown":
        data = reporting.render_markdown(payload).encode()
        content_type = "text/markdown"
    elif fmt == "pdf":
        from app.services.pdf_report import text_to_pdf

        data = text_to_pdf(reporting.render_markdown(payload))
        content_type = "application/pdf"
    else:
        import json as _json

        data = _json.dumps(payload, default=str).encode()
        content_type = "application/json"
    storage = get_storage()
    ref = await storage.put(
        f"reports/{assessment_id}/report.{fmt}", data, content_type=content_type
    )
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="report.exported",
        data={"backend": ref["backend"], "fmt": fmt, "url": ref.get("url")},
    )
    await session.commit()
    return {"stored": True, "ref": ref}


async def _assessment_findings(session, assessment_id: str) -> list[dict]:
    rows = (
        (
            await session.execute(
                select(Finding).where(Finding.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )
    return [finding_dict(f) for f in rows]


@router.post("/assessments/{assessment_id}/export/siem")
async def export_siem(
    assessment_id: str,
    fmt: str = Query(default="ecs", pattern="^(ecs|cef)$"),
    sink: str = Query(default="response", pattern="^(response|file)$"),
    confirmed_only: bool = Query(default=True),
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Export findings as SIEM events (ECS JSON-lines or CEF); Sentinel/Elastic-ingestible (BS-13)."""
    from app.services import siem

    await _get_assessment(session, principal, assessment_id)
    findings = await _assessment_findings(session, assessment_id)
    if confirmed_only:
        findings = [f for f in findings if f.get("status") == "confirmed"]
    events = siem.findings_to_events(assessment_id, principal.org_id, findings)
    payload, content_type = siem.serialize(events, fmt)
    sink_impl = siem.FileSiemSink() if sink == "file" else siem.ResponseSiemSink()
    result = await sink_impl.emit(
        payload, content_type, key=f"siem/{assessment_id}/events.{fmt}"
    )
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="siem.exported",
        data={"fmt": fmt, "sink": sink, "events": len(events)},
    )
    await session.commit()
    body = {"events": len(events), "format": fmt, "sink": result}
    if sink == "response":
        body["payload"] = payload
    return body


@router.post("/assessments/{assessment_id}/remediation-pr")
async def open_remediation_pr(
    assessment_id: str,
    provider: str = Query(default="local", pattern="^(local)$"),
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Open an advisory remediation change set (branch + REMEDIATION.md + patch stub) from
    confirmed findings, via a provider-agnostic adapter (BS-14). Proposal only — never merged."""
    from app.core.config import get_settings
    from app.services import remediation_pr as rpr

    await _get_assessment(session, principal, assessment_id)
    findings = await _assessment_findings(session, assessment_id)
    pr = rpr.build_pr_content(assessment_id, findings)
    root = f"{get_settings().remediation_pr_local_dir}/{principal.org_id}"
    try:
        provider_impl = rpr.get_provider(provider, local_root=root)
        pr = await provider_impl.open_pr(pr)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="remediation_pr.opened",
        data={"provider": pr.provider, "branch": pr.branch, "files": list(pr.files)},
    )
    await session.commit()
    return {
        "provider": pr.provider,
        "branch": pr.branch,
        "title": pr.title,
        "location": pr.location,
        "files": list(pr.files),
        "body": pr.body,
    }


@router.get("/assessments/{assessment_id}/attack-path")
async def attack_path(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    """Scoped attack-path graph derived from endpoints + findings (BE-05).

    Nodes: the target, discovered endpoints, and findings. Edges: target→endpoint
    (surface), endpoint→finding (weakness), and finding→finding chains where a weakness
    plausibly enables another (e.g. SQLi/BOLA on an endpoint feeding auth-bypass, or an
    open-redirect enabling credential theft). This is a scoped, evidence-derived graph,
    not a cloud/identity lateral-movement graph (see docs/DECISIONS.md)."""
    a = await _get_assessment(session, principal, assessment_id)
    target = await session.get(Target, a.target_id)
    endpoints = (
        (
            await session.execute(
                select(Endpoint).where(Endpoint.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )
    findings = (
        (
            await session.execute(
                select(Finding).where(Finding.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )

    nodes = [{"id": f"target:{target.id}", "type": "target", "label": target.name}]
    for e in endpoints:
        nodes.append(
            {
                "id": f"endpoint:{e.id}",
                "type": "endpoint",
                "label": f"{e.method} {e.path_template}",
                "auth_required": e.auth_required,
            }
        )
    for f in findings:
        nodes.append(
            {
                "id": f"finding:{f.id}",
                "type": "finding",
                "label": f.title,
                "severity": f.severity,
                "status": f.status,
                "check_class": f.check_class,
                "risk_score": f.risk_score,
            }
        )

    edges = []
    ep_ids = {e.id for e in endpoints}
    for e in endpoints:
        edges.append(
            {"from": f"target:{target.id}", "to": f"endpoint:{e.id}", "rel": "exposes"}
        )
    for f in findings:
        if f.endpoint_id and f.endpoint_id in ep_ids:
            edges.append(
                {
                    "from": f"endpoint:{f.endpoint_id}",
                    "to": f"finding:{f.id}",
                    "rel": "weakness",
                }
            )
    # chain heuristics: injection/BOLA that could enable further compromise
    enablers = [
        f
        for f in findings
        if f.check_class in ("sqli", "bola") and f.status in ("confirmed", "suspected")
    ]
    consequents = [
        f
        for f in findings
        if f.check_class in ("xss", "open_redirect", "info_disclosure")
    ]
    # Evidence-derived chaining (F-13): only chain an enabler to a consequent when they
    # share the same endpoint or the same path prefix — not all-pairs. This ties the edge
    # to observed surface rather than every possible combination.
    ep_by_id = {e.id: e for e in endpoints}

    def _prefix(fid_endpoint_id: str | None) -> str:
        e = ep_by_id.get(fid_endpoint_id)
        if not e:
            return ""
        segs = [s for s in (e.path_template or "").split("/") if s]
        return "/".join(segs[:2])  # first two path segments

    for a1 in enablers:
        for a2 in consequents:
            if a1.id == a2.id:
                continue
            same_endpoint = a1.endpoint_id and a1.endpoint_id == a2.endpoint_id
            same_prefix = (
                a1.endpoint_id
                and a2.endpoint_id
                and _prefix(a1.endpoint_id)
                and _prefix(a1.endpoint_id) == _prefix(a2.endpoint_id)
            )
            if same_endpoint or same_prefix:
                edges.append(
                    {
                        "from": f"finding:{a1.id}",
                        "to": f"finding:{a2.id}",
                        "rel": "may_enable",
                        "basis": "same_endpoint"
                        if same_endpoint
                        else "same_path_prefix",
                        "confidence": "heuristic",
                    }
                )
    return {
        "assessment_id": assessment_id,
        "nodes": nodes,
        "edges": edges,
        "note": "Scoped to this assessment; chain edges are evidence-derived "
        "(same endpoint or path prefix) and labeled heuristic.",
    }


# --------------------------------------------------------------------------- #
# regression & retest
# --------------------------------------------------------------------------- #
@router.post("/assessments/{assessment_id}/regression-tests")
async def generate_regression_tests(
    assessment_id: str,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    confirmed = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.assessment_id == assessment_id,
                    Finding.status == FindingStatus.CONFIRMED.value,
                )
            )
        )
        .scalars()
        .all()
    )
    created = []
    for f in confirmed:
        definition = build_regression_definition(
            f.check_class, f.reproduction or {}, f.title
        )
        row = RegressionTest(
            org_id=principal.org_id,
            target_id=a.target_id,
            origin_finding_id=f.id,
            check_class=f.check_class,
            title=definition["title"],
            definition=definition,
        )
        session.add(row)
        created.append(row)
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="regression.generated",
        data={"count": len(created)},
    )
    await session.commit()
    return {
        "created": len(created),
        "regression_tests": [
            {"id": r.id, "title": r.title, "check_class": r.check_class}
            for r in created
        ],
    }


@router.post("/assessments/{assessment_id}/regression-run")
async def run_regression_tests(
    assessment_id: str,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    a = await _get_assessment(session, principal, assessment_id)
    record = await session.get(AuthorizationRecord, a.authorization_id)
    tests = (
        (
            await session.execute(
                select(RegressionTest).where(RegressionTest.target_id == a.target_id)
            )
        )
        .scalars()
        .all()
    )
    if not tests:
        raise HTTPException(
            status_code=404, detail="no regression tests; generate them first"
        )

    guard = ScopeGuard(record, requests_made=0)
    active = guard.check_record_active()
    if not active.allowed:
        raise HTTPException(
            status_code=403, detail=f"authorization not usable: {active.reason}"
        )

    results = []
    async with GuardedHttpClient(guard) as client:
        for t in tests:
            res = await run_regression(client, t.definition)
            t.last_status = res.status
            from datetime import datetime

            t.last_run_at = datetime.now(UTC)
            results.append(
                {
                    "id": t.id,
                    "title": t.title,
                    "status": res.status,
                    "detail": res.detail,
                }
            )
    await write_audit(
        session,
        org_id=principal.org_id,
        assessment_id=assessment_id,
        event="regression.ran",
        data={"count": len(results)},
    )
    await session.commit()
    return {"results": results}


@router.post(
    "/assessments/{assessment_id}/retest", response_model=AssessmentOut, status_code=201
)
async def retest(
    assessment_id: str,
    body: RetestCreate,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    prev = await _get_assessment(session, principal, assessment_id)
    new = Assessment(
        org_id=principal.org_id,
        target_id=prev.target_id,
        authorization_id=prev.authorization_id,
        state=AssessmentState.CREATED.value,
        is_retest=True,
        incremental=body.incremental,
        previous_assessment_id=prev.id,
        requested_check_classes=body.requested_check_classes
        or prev.requested_check_classes,
    )
    session.add(new)
    await session.flush()
    # carry forward the discovery artifacts so the retest sees the same surface
    prev_artifacts = (
        (
            await session.execute(
                select(DiscoveryArtifact).where(
                    DiscoveryArtifact.assessment_id == prev.id
                )
            )
        )
        .scalars()
        .all()
    )
    for art in prev_artifacts:
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
        event="assessment.retest_created",
        data={"previous": prev.id},
    )
    await session.commit()
    await session.refresh(new)
    return _assessment_out(new)


@router.get("/assessments/{assessment_id}/regression-compare")
async def regression_compare(
    assessment_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    """Compare a retest against its predecessor: fixed / still-open / newly-introduced."""
    a = await _get_assessment(session, principal, assessment_id)
    if not a.previous_assessment_id:
        raise HTTPException(status_code=400, detail="assessment is not a retest")
    prev_findings = (
        (
            await session.execute(
                select(Finding).where(Finding.assessment_id == a.previous_assessment_id)
            )
        )
        .scalars()
        .all()
    )
    new_findings = (
        (
            await session.execute(
                select(Finding).where(Finding.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )
    prev_open = {
        f.dedup_key for f in prev_findings if f.status in ("confirmed", "suspected")
    }
    new_open = {
        f.dedup_key for f in new_findings if f.status in ("confirmed", "suspected")
    }
    fixed = prev_open - new_open
    still_open = prev_open & new_open
    newly = new_open - prev_open
    return {
        "previous_assessment_id": a.previous_assessment_id,
        "fixed": len(fixed),
        "still_open": len(still_open),
        "newly_introduced": len(newly),
        "fixed_keys": list(fixed)[:200],
        "still_open_keys": list(still_open)[:200],
        "newly_introduced_keys": list(newly)[:200],
    }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
async def _get_assessment(session, principal, assessment_id) -> Assessment:
    a = await session.get(Assessment, assessment_id)
    if not a or a.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="assessment not found")
    return a


def _assessment_out(a: Assessment) -> AssessmentOut:
    return AssessmentOut(
        id=a.id,
        target_id=a.target_id,
        authorization_id=a.authorization_id,
        state=a.state,
        is_retest=a.is_retest,
        incremental=a.incremental,
        previous_assessment_id=a.previous_assessment_id,
        requests_made=a.requests_made,
        error=a.error,
        completion_reason=a.completion_reason or "",
        summary=a.summary or {},
        created_at=a.created_at,
        started_at=a.started_at,
        finished_at=a.finished_at,
    )


def _finding_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id,
        check_class=f.check_class,
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        status=f.status,
        cwe=f.cwe,
        description=f.description,
        remediation=f.remediation,
        risk_score=f.risk_score,
        risk_breakdown=f.risk_breakdown or {},
        reproduction=f.reproduction or {},
        endpoint_id=f.endpoint_id,
        skill_ref=f.skill_ref or "",
    )


def _finding_dict(f: Finding) -> dict:
    return finding_dict(f)
