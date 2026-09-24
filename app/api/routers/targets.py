"""Targets, ownership verification, authorization records, and test accounts."""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    AuthorizationCreate,
    AuthorizationOut,
    OwnershipOut,
    OwnershipStart,
    TargetCreate,
    TargetOut,
    TestAccountCreate,
    TestAccountOut,
)
from app.core.auth import Principal, get_principal, require_role
from app.core.config import get_settings
from app.core.crypto import encrypt
from app.core.db import get_session
from app.core.enums import Environment, OwnershipMethod, Role, VerificationStatus
from app.models import (
    AuthorizationRecord,
    OwnershipVerification,
    Target,
    TestAccount,
)
from app.services import ownership as ownsvc
from app.services.audit import write_audit

router = APIRouter(tags=["targets"], prefix="/v1")


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


@router.post("/targets", response_model=TargetOut, status_code=201)
async def create_target(
    body: TargetCreate,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    if not _host_of(body.base_url):
        raise HTTPException(
            status_code=422, detail="base_url must be an absolute http(s) URL"
        )
    try:
        Environment(body.environment)
    except ValueError:
        raise HTTPException(
            status_code=422, detail=f"invalid environment {body.environment!r}"
        )
    row = Target(
        org_id=principal.org_id,
        name=body.name,
        base_url=body.base_url,
        environment=body.environment,
        description=body.description,
    )
    session.add(row)
    await session.commit()
    return TargetOut(
        id=row.id,
        name=row.name,
        base_url=row.base_url,
        environment=row.environment,
        description=row.description,
    )


@router.get("/targets", response_model=list[TargetOut])
async def list_targets(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    rows = (
        (await session.execute(select(Target).where(Target.org_id == principal.org_id)))
        .scalars()
        .all()
    )
    return [
        TargetOut(
            id=r.id,
            name=r.name,
            base_url=r.base_url,
            environment=r.environment,
            description=r.description,
        )
        for r in rows
    ]


async def _get_target(session, principal, target_id) -> Target:
    row = await session.get(Target, target_id)
    if not row or row.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="target not found")
    return row


@router.post(
    "/targets/{target_id}/ownership", response_model=OwnershipOut, status_code=201
)
async def start_ownership(
    target_id: str,
    body: OwnershipStart,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    target = await _get_target(session, principal, target_id)
    try:
        method = OwnershipMethod(body.method)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"invalid method {body.method!r}")
    host = _host_of(target.base_url)
    token = ownsvc.generate_ownership_token()
    row = OwnershipVerification(
        org_id=principal.org_id,
        target_id=target_id,
        method=method.value,
        token=token,
        host=host,
        status=VerificationStatus.PENDING.value,
    )
    session.add(row)
    await session.flush()

    # For lab_bundled / manual_attestation we can verify immediately.
    instructions = _instructions(method, host, token)
    if method in (OwnershipMethod.LAB_BUNDLED, OwnershipMethod.MANUAL_ATTESTATION):
        outcome = await ownsvc.verify_ownership(
            method=method,
            host=host,
            token=token,
            base_url=target.base_url,
            environment=Environment(target.environment),
            attestation=body.attestation,
        )
        row.status = outcome.status.value
        row.detail = outcome.detail
    await write_audit(
        session,
        org_id=principal.org_id,
        event="ownership.started",
        data={"target_id": target_id, "method": method.value, "status": row.status},
    )
    await session.commit()
    return OwnershipOut(
        id=row.id,
        method=row.method,
        host=host,
        token=token,
        status=row.status,
        detail=row.detail,
        instructions=instructions,
    )


@router.post(
    "/targets/{target_id}/ownership/{ownership_id}/verify", response_model=OwnershipOut
)
async def verify_ownership_endpoint(
    target_id: str,
    ownership_id: str,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    target = await _get_target(session, principal, target_id)
    row = await session.get(OwnershipVerification, ownership_id)
    if not row or row.target_id != target_id or row.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="ownership record not found")
    outcome = await ownsvc.verify_ownership(
        method=OwnershipMethod(row.method),
        host=row.host,
        token=row.token,
        base_url=target.base_url,
        environment=Environment(target.environment),
    )
    row.status = outcome.status.value
    row.detail = outcome.detail
    await write_audit(
        session,
        org_id=principal.org_id,
        event="ownership.verified",
        data={"target_id": target_id, "status": row.status},
    )
    await session.commit()
    return OwnershipOut(
        id=row.id,
        method=row.method,
        host=row.host,
        token=row.token,
        status=row.status,
        detail=row.detail,
        instructions=_instructions(OwnershipMethod(row.method), row.host, row.token),
    )


def _instructions(method: OwnershipMethod, host: str, token: str) -> str:
    s = get_settings()
    if method == OwnershipMethod.DNS_TXT:
        return f"Add DNS TXT record on {host}: {s.ownership_dns_token_prefix}={token}"
    if method == OwnershipMethod.HTTP_FILE:
        return f"Serve token at https://{host}{s.ownership_http_well_known_path} (content: {token})"
    if method == OwnershipMethod.MANUAL_ATTESTATION:
        return "Submit a signed delegated-permission attestation (>=32 chars) in 'attestation'."
    return "Bundled lab target on loopback — auto-verified."


@router.post(
    "/targets/{target_id}/authorizations",
    response_model=AuthorizationOut,
    status_code=201,
)
async def create_authorization(
    target_id: str,
    body: AuthorizationCreate,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    target = await _get_target(session, principal, target_id)
    host = _host_of(target.base_url)

    # Deny-by-default: an authorization is only VERIFIED if ownership is verified.
    verified_own = (
        (
            await session.execute(
                select(OwnershipVerification).where(
                    OwnershipVerification.target_id == target_id,
                    OwnershipVerification.status == VerificationStatus.VERIFIED.value,
                )
            )
        )
        .scalars()
        .first()
    )

    allowed_hosts = body.allowed_hosts or [host]
    # Scope safety: every allowed host must relate to the target host unless attested.
    if host not in allowed_hosts and not verified_own:
        raise HTTPException(
            status_code=422,
            detail="target host must be in allowed_hosts, or verify ownership first",
        )

    intensity = body.intensity
    env = body.environment
    # Guardrail: invasive intensity is never allowed in production.
    if intensity == "invasive" and env == "production":
        raise HTTPException(
            status_code=422, detail="invasive intensity forbidden in production"
        )

    status = (
        VerificationStatus.VERIFIED.value
        if verified_own
        else VerificationStatus.PENDING.value
    )
    record = AuthorizationRecord(
        org_id=principal.org_id,
        target_id=target_id,
        status=status,
        environment=env,
        intensity=intensity,
        allowed_hosts=allowed_hosts,
        allowed_ports=body.allowed_ports,
        allowed_methods=[m.upper() for m in body.allowed_methods],
        allowed_check_classes=body.allowed_check_classes,
        path_allowlist=body.path_allowlist,
        path_denylist=body.path_denylist,
        max_requests=body.max_requests,
        rate_limit_per_sec=body.rate_limit_per_sec,
        max_duration_seconds=body.max_duration_seconds,
        window_start=body.window_start,
        window_end=body.window_end,
        allow_state_changing=body.allow_state_changing,
        ownership_verification_id=verified_own.id if verified_own else None,
        authorized_by=body.authorized_by or principal.user_id,
        notes=body.notes,
    )
    session.add(record)
    await write_audit(
        session,
        org_id=principal.org_id,
        event="authorization.created",
        data={
            "target_id": target_id,
            "status": status,
            "intensity": intensity,
            "allowed_hosts": allowed_hosts,
        },
    )
    await session.commit()
    return _authz_out(record)


@router.get(
    "/targets/{target_id}/authorizations", response_model=list[AuthorizationOut]
)
async def list_authorizations(
    target_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_target(session, principal, target_id)
    rows = (
        (
            await session.execute(
                select(AuthorizationRecord).where(
                    AuthorizationRecord.target_id == target_id,
                    AuthorizationRecord.org_id == principal.org_id,
                )
            )
        )
        .scalars()
        .all()
    )
    return [_authz_out(r) for r in rows]


def _authz_out(r: AuthorizationRecord) -> AuthorizationOut:
    return AuthorizationOut(
        id=r.id,
        status=r.status,
        environment=r.environment,
        intensity=r.intensity,
        allowed_hosts=r.allowed_hosts,
        allowed_check_classes=r.allowed_check_classes,
        max_requests=r.max_requests,
        allow_state_changing=r.allow_state_changing,
    )


@router.post(
    "/targets/{target_id}/test-accounts", response_model=TestAccountOut, status_code=201
)
async def create_test_account(
    target_id: str,
    body: TestAccountCreate,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    await _get_target(session, principal, target_id)
    if body.auth_type not in ("form", "bearer", "basic", "header"):
        raise HTTPException(
            status_code=422, detail=f"invalid auth_type {body.auth_type!r}"
        )
    row = TestAccount(
        org_id=principal.org_id,
        target_id=target_id,
        label=body.label,
        role_name=body.role_name,
        auth_type=body.auth_type,
        username=body.username,
        secret_enc=encrypt(body.secret) if body.secret else "",
        login_config=body.login_config,
        owns_object_ids=body.owns_object_ids,
    )
    session.add(row)
    await session.commit()
    return TestAccountOut(
        id=row.id,
        label=row.label,
        role_name=row.role_name,
        auth_type=row.auth_type,
        username=row.username,
    )


@router.get("/targets/{target_id}/test-accounts", response_model=list[TestAccountOut])
async def list_test_accounts(
    target_id: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
):
    await _get_target(session, principal, target_id)
    rows = (
        (
            await session.execute(
                select(TestAccount).where(
                    TestAccount.target_id == target_id,
                    TestAccount.org_id == principal.org_id,
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        TestAccountOut(
            id=r.id,
            label=r.label,
            role_name=r.role_name,
            auth_type=r.auth_type,
            username=r.username,
        )
        for r in rows
    ]


@router.post("/targets/{target_id}/test-accounts/{account_id}/mfa")
async def complete_account_mfa(
    target_id: str,
    account_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Complete an MFA-gated login for a test account with an operator-supplied code.

    Establishes a session; if the target issues an MFA challenge, submits the code and
    returns the resulting session status. Credentials/tokens are never returned or logged.
    """
    from app.services.sessions import complete_mfa, establish_session

    await _get_target(session, principal, target_id)
    account = await session.get(TestAccount, account_id)
    if (
        not account
        or account.org_id != principal.org_id
        or account.target_id != target_id
    ):
        raise HTTPException(status_code=404, detail="test account not found")
    code = str(body.get("code", "")).strip()
    if not code:
        raise HTTPException(status_code=422, detail="'code' is required")

    state = await establish_session(account)
    if state.status == "pending_mfa":
        state = await complete_mfa(account, state, code, account.login_config or {})
    await write_audit(
        session,
        org_id=principal.org_id,
        event="test_account.mfa_completed",
        data={"account_id": account_id, "status": state.status},
    )
    await session.commit()
    if state.status != "active":
        raise HTTPException(
            status_code=400, detail=f"MFA/login not completed: {state.detail}"
        )
    return {
        "account_id": account_id,
        "status": state.status,
        "role_name": account.role_name,
        "detail": state.detail,
    }


@router.post("/targets/{target_id}/test-accounts/{account_id}/rotate-secret")
async def rotate_account_secret(
    target_id: str,
    account_id: str,
    body: dict,
    principal: Principal = Depends(require_role(Role.OPERATOR)),
    session: AsyncSession = Depends(get_session),
):
    """Rotate a test account's stored secret and (optionally) set a TTL (AU-05).

    Re-encrypts the new secret at rest and stamps `secret_rotated_at`. `ttl_days` (0 =
    no expiry) lets operations flag stale credentials. The plaintext secret is never
    returned or logged.
    """
    from datetime import datetime, timezone

    await _get_target(session, principal, target_id)
    account = await session.get(TestAccount, account_id)
    if (
        not account
        or account.org_id != principal.org_id
        or account.target_id != target_id
    ):
        raise HTTPException(status_code=404, detail="test account not found")
    secret = body.get("secret")
    if not secret:
        raise HTTPException(status_code=422, detail="'secret' is required")
    ttl_days = int(body.get("ttl_days", account.secret_ttl_days or 0))
    account.secret_enc = encrypt(secret)
    account.secret_rotated_at = datetime.now(timezone.utc)
    account.secret_ttl_days = ttl_days
    await write_audit(
        session,
        org_id=principal.org_id,
        event="test_account.secret_rotated",
        data={"account_id": account_id, "ttl_days": ttl_days},
    )
    await session.commit()
    return {
        "account_id": account_id,
        "rotated_at": account.secret_rotated_at.isoformat(),
        "ttl_days": ttl_days,
    }
