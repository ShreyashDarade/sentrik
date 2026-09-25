"""Authentication for the protocol endpoints (MCP at /mcp, A2A at /a2a).

The MCP and A2A servers are mounted as sub-applications, outside FastAPI's dependency
system, so this pure-ASGI middleware authenticates their requests with the same
credentials as the REST API (``X-API-Key`` or ``Authorization: Bearer <jwt>``) and:

* rejects unauthenticated calls with a 401 JSON envelope,
* publishes the resolved ``Principal`` in a context variable (``principal_var``) so
  MCP tool/resource handlers can tenant-scope every lookup,
* sets ``scope["user"]`` / ``scope["auth"]`` so the A2A SDK's request context (and its
  task store owner scoping) sees an authenticated user whose name is the org id.

The A2A agent card (``/.well-known/agent-card.json``) stays public: discovery is
harmless and the card itself declares the API-key scheme callers must use.
"""

from __future__ import annotations

import json
from contextvars import ContextVar

from fastapi import HTTPException
from starlette.authentication import AuthCredentials, BaseUser
from starlette.datastructures import Headers

from app.core.auth import Principal, _principal_from_api_key, _principal_from_jwt
from app.core.db import get_sessionmaker

principal_var: ContextVar[Principal | None] = ContextVar("protocol_principal", default=None)

PROTECTED_PREFIXES = ("/mcp", "/a2a")


class PrincipalUser(BaseUser):
    """Starlette user adapter: ``display_name`` is the org id (tenant scope)."""

    def __init__(self, principal: Principal):
        self.principal = principal

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.principal.org_id

    @property
    def identity(self) -> str:
        return self.principal.user_id


async def resolve_principal(
    x_api_key: str | None, authorization: str | None
) -> Principal | None:
    """Resolve a caller from raw header values; ``None`` when absent or invalid."""
    try:
        async with get_sessionmaker()() as session:
            if x_api_key:
                return await _principal_from_api_key(x_api_key.strip(), session)
            if authorization:
                scheme, _, token = authorization.partition(" ")
                if scheme.lower() == "bearer" and token:
                    return await _principal_from_jwt(token.strip(), session)
    except HTTPException:
        return None
    return None


def current_org_id() -> str | None:
    """Org of the authenticated protocol caller, or ``None`` outside HTTP (stdio)."""
    principal = principal_var.get()
    return principal.org_id if principal else None


class ProtocolAuthMiddleware:
    def __init__(self, app, prefixes: tuple[str, ...] = PROTECTED_PREFIXES):
        self.app = app
        self.prefixes = prefixes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith(self.prefixes):
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        principal = await resolve_principal(
            headers.get("x-api-key"), headers.get("authorization")
        )
        if principal is None:
            body = json.dumps(
                {
                    "error": {
                        "code": "http_401",
                        "detail": "authentication required (Bearer token or X-API-Key)",
                    }
                }
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        scope["user"] = PrincipalUser(principal)
        scope["auth"] = AuthCredentials(["authenticated", f"role:{principal.role.value}"])
        token = principal_var.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            principal_var.reset(token)
