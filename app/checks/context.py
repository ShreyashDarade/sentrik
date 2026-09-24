"""CheckContext — everything a check is allowed to touch, and nothing more."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.enums import TestIntensity
from app.security.http_client import GuardedHttpClient


@dataclass
class AuthSession:
    """A resolved authenticated session for a test account (role-scoped)."""

    role_name: str
    label: str
    headers: dict = field(default_factory=dict)  # e.g. {"Authorization": "Bearer ..."}
    cookies: dict = field(default_factory=dict)
    owns_object_ids: list = field(default_factory=list)
    expired: bool = False


@dataclass
class EndpointView:
    """Read-only projection of a discovered endpoint for a check."""

    id: str
    method: str
    url: str
    path_template: str
    parameters: list[dict]
    request_body_schema: dict
    auth_required: bool
    fingerprint: str


@dataclass
class CheckContext:
    client: GuardedHttpClient
    endpoint: EndpointView
    intensity: TestIntensity
    base_url: str
    sessions: list[AuthSession] = field(default_factory=list)
    # bounded knobs supplied by orchestrator (per-check request ceilings, etc.)
    max_payloads: int = 12

    def session_for_role(self, role_name: str) -> AuthSession | None:
        for s in self.sessions:
            if s.role_name == role_name and not s.expired:
                return s
        return None

    def query_params(self) -> list[dict]:
        return [p for p in self.endpoint.parameters if p.get("in") == "query"]

    def body_params(self) -> list[dict]:
        return [p for p in self.endpoint.parameters if p.get("in") == "body"]

    def injectable_params(self) -> list[dict]:
        """Parameters worth injecting into (query + body, skipping obvious non-strings)."""
        out = []
        for p in self.endpoint.parameters:
            if p.get("in") in ("query", "body", "path"):
                out.append(p)
        return out
