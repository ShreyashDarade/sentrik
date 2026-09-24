"""SSO / OIDC login.

Verifies a provider-issued OpenID Connect **ID token** (RS256/ES256 signed against
the provider's JWKS) and maps the identity to a *pre-existing* Sentrik user, minting
a normal Sentrik access token via :func:`app.core.auth.create_access_token`.

Security posture (deliberately conservative):
  * An OIDC identity may only ever map to a user that already exists and is active.
    It never creates organizations, never creates users, and never elevates roles.
  * Only asymmetric algorithms (RS256/ES256) are accepted. ``alg: none`` and any
    HMAC (HS*) algorithm are rejected outright, so a leaked/guessed shared secret
    cannot forge a token.
  * ``audience`` and ``issuer`` are always checked against Settings.

Everything (issuer, audience, JWKS URL, email claim, enabled flag) is sourced from
Settings — no hardcoded issuer, keys, or endpoints.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from jose import jwt
from jose.exceptions import JWTError
from sqlalchemy import func, select

from app.core.auth import create_access_token
from app.core.db import get_sessionmaker
from app.models import User

# Only asymmetric signature algorithms are permitted. This explicitly excludes
# "none" and every HS* (HMAC) algorithm.
_ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")

_JWKS_TTL_SECONDS = 300
# In-process JWKS cache: {cache_key: (expires_at_monotonic, jwks_dict)}.
_jwks_cache: dict[str, tuple[float, dict]] = {}

_HTTP_TIMEOUT = 10.0


def _clear_jwks_cache() -> None:
    """Testing/ops helper: drop the in-process JWKS cache."""
    _jwks_cache.clear()


async def _fetch_json(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as http:
            resp = await http.get(url)
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError as exc:
        raise ValueError(f"OIDC network error fetching {url!r}: {exc}") from exc
    except ValueError as exc:  # includes JSON decode errors
        raise ValueError(f"OIDC: invalid JSON from {url!r}: {exc}") from exc


async def fetch_jwks(settings) -> dict:
    """Fetch (and cache) the provider JWKS.

    If ``settings.oidc_jwks_url`` is set it is used directly; otherwise the JWKS URI
    is discovered from ``{issuer}/.well-known/openid-configuration``.

    Cached in-process for :data:`_JWKS_TTL_SECONDS`. Raises :class:`ValueError` on
    any network/parse error or if the discovery document is unusable.
    """
    jwks_url = (settings.oidc_jwks_url or "").strip()
    issuer = (settings.oidc_issuer or "").strip()

    cache_key = jwks_url or issuer
    if not cache_key:
        raise ValueError("OIDC: neither oidc_jwks_url nor oidc_issuer is configured")

    cached = _jwks_cache.get(cache_key)
    if cached is not None and cached[0] > time.monotonic():
        return cached[1]

    if not jwks_url:
        discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        discovery = await _fetch_json(discovery_url)
        jwks_url = discovery.get("jwks_uri", "").strip()
        if not jwks_url:
            raise ValueError(
                f"OIDC discovery at {discovery_url!r} did not provide a 'jwks_uri'"
            )

    jwks = await _fetch_json(jwks_url)
    if not isinstance(jwks, dict) or not jwks.get("keys"):
        raise ValueError(f"OIDC JWKS at {jwks_url!r} has no 'keys'")

    _jwks_cache[cache_key] = (time.monotonic() + _JWKS_TTL_SECONDS, jwks)
    return jwks


def _select_key(jwks: dict, kid: str | None) -> dict:
    """Pick the JWK matching the token's ``kid`` (or the sole key if none given)."""
    keys = jwks.get("keys") or []
    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return key
        raise ValueError(f"OIDC: no JWKS key matches token kid {kid!r}")
    if len(keys) == 1:
        return keys[0]
    raise ValueError("OIDC: token has no 'kid' and JWKS has multiple keys")


async def verify_id_token(token: str, settings) -> dict:
    """Verify a provider ID token against the JWKS and return its claims.

    Enforces RS256/ES256-family signatures, ``audience == settings.oidc_audience``
    and ``issuer == settings.oidc_issuer``. Raises :class:`ValueError` on any failure.
    """
    if not token or not isinstance(token, str):
        raise ValueError("OIDC: empty id_token")

    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise ValueError(f"OIDC: malformed token header: {exc}") from exc

    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        raise ValueError(
            f"OIDC: refusing token with algorithm {alg!r}; "
            f"only asymmetric {list(_ALLOWED_ALGS)} accepted"
        )

    if not (settings.oidc_audience or "").strip():
        raise ValueError("OIDC: oidc_audience is not configured")
    if not (settings.oidc_issuer or "").strip():
        raise ValueError("OIDC: oidc_issuer is not configured")

    jwks = await fetch_jwks(settings)
    key = _select_key(jwks, header.get("kid"))

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=list(_ALLOWED_ALGS),
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require_aud": True, "require_iss": True, "require_exp": True},
        )
    except JWTError as exc:
        raise ValueError(f"OIDC: id_token verification failed: {exc}") from exc

    return claims


async def login_with_id_token(id_token: str) -> dict[str, Any]:
    """Full SSO login flow: verify an ID token and map it to a pre-existing user.

    Returns ``{access_token, org_id, user_id, role, email}`` on success. Raises
    :class:`ValueError` if OIDC is disabled, the token is invalid, or no active
    provisioned user matches the token's email. Never creates orgs/users.
    """
    from app.core.config import get_settings

    settings = get_settings()
    if not settings.oidc_enabled:
        raise ValueError("OIDC not enabled")

    claims = await verify_id_token(id_token, settings)

    email_claim = settings.oidc_email_claim or "email"
    email = claims.get(email_claim)
    if not email or not isinstance(email, str):
        raise ValueError(
            f"OIDC: token has no usable {email_claim!r} claim"
        )
    email = email.strip().lower()

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        rows = (
            await session.execute(
                select(User).where(func.lower(User.email) == email)
            )
        ).scalars().all()

    active = next((u for u in rows if u.is_active), None)
    if active is None:
        raise ValueError("no provisioned user for this identity")

    token = create_access_token(
        org_id=active.org_id, user_id=active.id, role=active.role
    )
    return {
        "access_token": token,
        "org_id": active.org_id,
        "user_id": active.id,
        "role": active.role,
        "email": active.email,
    }
