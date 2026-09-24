"""Organization onboarding and identity: signup, login, API-key management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    ApiKeyCreate,
    ApiKeyResult,
    LoginRequest,
    OrgSignup,
    SignupResult,
    TokenResult,
)
from app.core.auth import (
    Principal,
    create_access_token,
    generate_api_key,
    get_principal,
    hash_api_secret,
    hash_password,
    require_role,
    verify_password,
)
from app.core.db import get_session
from app.core.enums import Role
from app.models import ApiKey, Organization, User

router = APIRouter(tags=["identity"])


@router.post("/v1/onboarding/signup", response_model=SignupResult, status_code=201)
async def signup(body: OrgSignup, session: AsyncSession = Depends(get_session)):
    existing = (
        await session.execute(
            select(Organization).where(Organization.slug == body.org_slug)
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="org slug already taken")
    try:
        pw_hash = hash_password(body.admin_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    org = Organization(name=body.org_name, slug=body.org_slug)
    session.add(org)
    await session.flush()
    user = User(
        org_id=org.id,
        email=body.admin_email.lower(),
        password_hash=pw_hash,
        role=Role.OWNER.value,
    )
    session.add(user)
    await session.flush()

    full, prefix, secret = generate_api_key()
    session.add(
        ApiKey(
            org_id=org.id,
            user_id=user.id,
            name="bootstrap",
            prefix=prefix,
            secret_hash=hash_api_secret(secret),
            role=Role.OWNER.value,
        )
    )
    await session.commit()

    token = create_access_token(org_id=org.id, user_id=user.id, role=Role.OWNER.value)
    return SignupResult(
        org_id=org.id, user_id=user.id, access_token=token, api_key=full
    )


@router.post("/v1/onboarding/login", response_model=TokenResult)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)):
    org = (
        await session.execute(
            select(Organization).where(Organization.slug == body.org_slug)
        )
    ).scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=401, detail="invalid credentials")
    user = (
        await session.execute(
            select(User).where(User.org_id == org.id, User.email == body.email.lower())
        )
    ).scalar_one_or_none()
    if (
        not user
        or not user.is_active
        or not verify_password(body.password, user.password_hash)
    ):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = create_access_token(org_id=org.id, user_id=user.id, role=user.role)
    return TokenResult(access_token=token, org_id=org.id, role=user.role)


@router.post("/v1/api-keys", response_model=ApiKeyResult, status_code=201)
async def create_api_key(
    body: ApiKeyCreate,
    principal: Principal = Depends(require_role(Role.ADMIN)),
    session: AsyncSession = Depends(get_session),
):
    try:
        role = Role(body.role)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"invalid role {body.role!r}")
    full, prefix, secret = generate_api_key()
    row = ApiKey(
        org_id=principal.org_id,
        user_id=principal.user_id,
        name=body.name,
        prefix=prefix,
        secret_hash=hash_api_secret(secret),
        role=role.value,
    )
    session.add(row)
    await session.commit()
    return ApiKeyResult(id=row.id, api_key=full, prefix=prefix, role=role.value)


@router.delete("/v1/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    principal: Principal = Depends(require_role(Role.ADMIN)),
    session: AsyncSession = Depends(get_session),
):
    row = await session.get(ApiKey, key_id)
    if not row or row.org_id != principal.org_id:
        raise HTTPException(status_code=404, detail="not found")
    row.revoked = True
    await session.commit()


@router.post("/v1/onboarding/oidc/login", response_model=TokenResult)
async def oidc_login(body: dict):
    """SSO/OIDC login: exchange a provider ID token for a Sentrik JWT.

    The identity is mapped to a PRE-EXISTING active user by email; OIDC never creates
    tenants/users or elevates roles. Requires SENTINEL_OIDC_* to be configured.
    Body: {"id_token": "<provider id token>"}.
    """
    from app.core.oidc import login_with_id_token

    id_token = str(body.get("id_token", "")).strip()
    if not id_token:
        raise HTTPException(status_code=422, detail="'id_token' is required")
    try:
        result = await login_with_id_token(id_token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return TokenResult(
        access_token=result["access_token"],
        org_id=result["org_id"],
        role=result["role"],
    )


@router.get("/v1/me")
async def whoami(principal: Principal = Depends(get_principal)):
    return {
        "org_id": principal.org_id,
        "user_id": principal.user_id,
        "role": principal.role.value,
        "auth_method": principal.auth_method,
    }
