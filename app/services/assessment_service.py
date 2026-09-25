"""Assessment creation and report assembly shared by every entry point.

The REST router, the A2A executor and the MCP report resource all create or read
assessments the same way, so the tenant checks and the report payload live here once.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AssessmentState, VerificationStatus
from app.models import (
    Assessment,
    AuthorizationRecord,
    Coverage,
    DiscoveryArtifact,
    Endpoint,
    Finding,
    Target,
)
from app.services import reporting
from app.services.audit import write_audit


class AssessmentCreateError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


async def create_assessment(
    session: AsyncSession,
    *,
    org_id: str,
    target_id: str,
    authorization_id: str,
    requested_check_classes: list[str] | None = None,
    artifacts: list[dict] | None = None,
    audit_data: dict | None = None,
) -> Assessment:
    """Create an assessment bound to a verified authorization of the caller's org.

    ``artifacts`` are dicts with ``kind``, ``content`` and optional ``filename`` /
    ``endpoint_url``. Raises ``AssessmentCreateError`` with an HTTP-like status.
    """
    target = await session.get(Target, target_id)
    if not target or target.org_id != org_id:
        raise AssessmentCreateError(404, "target not found")
    record = await session.get(AuthorizationRecord, authorization_id)
    if not record or record.org_id != org_id or record.target_id != target_id:
        raise AssessmentCreateError(404, "authorization not found for target")
    if record.status != VerificationStatus.VERIFIED.value:
        raise AssessmentCreateError(
            403,
            f"authorization not verified (status={record.status}); "
            "verify ownership and re-create the authorization",
        )

    assessment = Assessment(
        org_id=org_id,
        target_id=target_id,
        authorization_id=authorization_id,
        state=AssessmentState.CREATED.value,
        requested_check_classes=list(requested_check_classes or []),
    )
    session.add(assessment)
    await session.flush()
    for art in artifacts or []:
        session.add(
            DiscoveryArtifact(
                org_id=org_id,
                assessment_id=assessment.id,
                kind=str(art.get("kind", "openapi")),
                filename=str(art.get("filename", "") or ""),
                content=str(art.get("content", "") or ""),
                endpoint_url=str(art.get("endpoint_url", "") or ""),
            )
        )
    await write_audit(
        session,
        org_id=org_id,
        assessment_id=assessment.id,
        event="assessment.created",
        data={"target_id": target_id, **(audit_data or {})},
    )
    return assessment


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "check_class": f.check_class,
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "status": f.status,
        "cwe": f.cwe,
        "description": f.description,
        "remediation": f.remediation,
        "risk_score": f.risk_score,
        "reproduction": f.reproduction or {},
        "skill_ref": f.skill_ref or "",
    }


async def build_report(session: AsyncSession, a: Assessment) -> dict:
    """The full JSON report payload for an assessment (same as GET .../report)."""
    target = await session.get(Target, a.target_id)
    record = await session.get(AuthorizationRecord, a.authorization_id)
    endpoints = (
        (await session.execute(select(Endpoint).where(Endpoint.assessment_id == a.id)))
        .scalars()
        .all()
    )
    findings = (
        (await session.execute(select(Finding).where(Finding.assessment_id == a.id)))
        .scalars()
        .all()
    )
    cov = (
        (await session.execute(select(Coverage).where(Coverage.assessment_id == a.id)))
        .scalars()
        .all()
    )
    return reporting.build_report_payload(
        emphasis=(a.summary or {}).get("report_emphasis", reporting.EMPHASES[0]),
        assessment={
            "id": a.id,
            "state": a.state,
            "completion_reason": a.completion_reason or "",
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "finished_at": a.finished_at.isoformat() if a.finished_at else None,
        },
        target={
            "name": target.name,
            "base_url": target.base_url,
            "environment": target.environment,
        },
        authorization={
            "id": record.id,
            "status": record.status,
            "environment": record.environment,
            "intensity": record.intensity,
            "authorized_by": record.authorized_by,
            "window_start": record.window_start.isoformat()
            if record.window_start
            else None,
            "window_end": record.window_end.isoformat() if record.window_end else None,
        },
        endpoints=[
            {
                "id": e.id,
                "method": e.method,
                "url": e.url,
                "provenance": e.provenance,
                "confidence": e.confidence,
                "auth_required": e.auth_required,
            }
            for e in endpoints
        ],
        findings=[finding_dict(f) for f in findings],
        coverage=[
            {
                "endpoint_id": c.endpoint_id,
                "check_class": c.check_class,
                "tested": c.tested,
                "reason_untested": c.reason_untested,
            }
            for c in cov
        ],
        risk=(a.summary or {}).get("risk", {}),
    )
