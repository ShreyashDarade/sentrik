"""Identity, authentication, and RBAC.

Two auth mechanisms:
  * Bearer JWT  — issued at login, carries org_id/user_id/role.
  * API key     — `sk_<prefix>_<secret>`; prefix indexes the row, secret is bcrypt-checked.

Both resolve to a `Principal` used for tenant scoping and role checks. Authorization
of *assessments against targets* is a separate, stronger concept handled by the scope
guard (app/security/scope.py) — this module only answers "who is calling and what
platform role do they hold".
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.db import get_session
from app.core.enums import Role
from app.models import ApiKey, Organization, User

# pbkdf2_sha256: pure-Python, no external native dependency, no 72-byte input ceiling.
# (bcrypt 4.x + passlib have a known backend-detection bug; pbkdf2 sidesteps it.)
_pwd = CryptContext(
    schemes=["pbkdf2_sha256"], deprecated="auto", pbkdf2_sha256__rounds=29000
)

ROLE_RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2, Role.OWNER: 3}


def _prepare(secret: str) -> str:
    # pbkdf2_sha256 has no length ceiling; passthrough (kept for interface stability).
    return secret


def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    return _pwd.hash(_prepare(password))


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _pwd.verify(_prepare(password), hashed)
    except (ValueError, TypeError):
        return False


@dataclass
class Principal:
    org_id: str
    user_id: str
    role: Role
    auth_method: str  # "jwt" | "api_key"

    def require_role(self, minimum: Role) -> None:
        if ROLE_RANK[self.role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role >= {minimum.value}, principal has {self.role.value}",
            )


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def create_access_token(*, org_id: str, user_id: str, role: str) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "org": org_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=s.access_token_ttl_minutes)).timestamp()),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    s = get_settings()
    try:
        return jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"invalid token: {exc}"
        )


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #
def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, secret). Full key shown once; only hash is stored."""
    prefix = secrets.token_hex(4)  # 8 hex chars
    secret = secrets.token_urlsafe(24)
    full = f"sk_{prefix}_{secret}"
    return full, prefix, secret


def hash_api_secret(secret: str) -> str:
    return _pwd.hash(_prepare(secret))


def parse_api_key(raw: str) -> tuple[str, str] | None:
    parts = raw.split("_", 2)
    if len(parts) != 3 or parts[0] != "sk" or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]  # prefix, secret


async def _principal_from_api_key(raw: str, session: AsyncSession) -> Principal:
    parsed = parse_api_key(raw)
    if not parsed:
        raise HTTPException(status_code=401, detail="malformed API key")
    prefix, secret = parsed
    row = (
        await session.execute(
            select(ApiKey).where(ApiKey.prefix == prefix, ApiKey.revoked == False)
        )
    ).scalar_one_or_none()
    # constant-time-ish: always run a verify to reduce timing oracle even when prefix misses
    if row is None:
        _pwd.verify(_prepare(secret), _pwd.hash("decoy"))
        raise HTTPException(status_code=401, detail="invalid API key")
    if not _pwd.verify(_prepare(secret), row.secret_hash):
        raise HTTPException(status_code=401, detail="invalid API key")
    try:
        role = Role(row.role)
    except ValueError:
        role = Role.VIEWER
    return Principal(
        org_id=row.org_id, user_id=row.user_id, role=role, auth_method="api_key"
    )


async def _principal_from_jwt(token: str, session: AsyncSession) -> Principal:
    claims = decode_access_token(token)
    org_id, user_id, role_str = (
        claims.get("org"),
        claims.get("sub"),
        claims.get("role", "viewer"),
    )
    if not org_id or not user_id:
        raise HTTPException(status_code=401, detail="token missing org/subject")
    user = (
        await session.execute(
            select(User).where(User.id == user_id, User.org_id == org_id)
        )
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    try:
        role = Role(role_str)
    except ValueError:
        role = Role.VIEWER
    return Principal(org_id=org_id, user_id=user_id, role=role, auth_method="jwt")


async def get_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> Principal:
    """FastAPI dependency: resolve caller from Bearer JWT or X-API-Key header."""
    if x_api_key:
        return await _principal_from_api_key(x_api_key.strip(), session)
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="expected 'Bearer <token>'")
        return await _principal_from_jwt(token.strip(), session)
    raise HTTPException(
        status_code=401,
        detail="authentication required (Bearer token or X-API-Key)",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(minimum: Role):
    """Dependency factory enforcing a minimum platform role."""

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        principal.require_role(minimum)
        return principal

    return _dep


async def ensure_org_access(principal: Principal, org_id: str) -> None:
    """Tenant isolation guard: a principal may only touch its own org's rows."""
    if not hmac.compare_digest(principal.org_id, org_id):
        raise HTTPException(
            status_code=404, detail="resource not found"
        )  # do not leak existence


async def get_or_create_bootstrap_org(
    session: AsyncSession, name: str, slug: str
) -> Organization:
    existing = (
        await session.execute(select(Organization).where(Organization.slug == slug))
    ).scalar_one_or_none()
    if existing:
        return existing
    org = Organization(name=name, slug=slug)
    session.add(org)
    await session.flush()
    return org
