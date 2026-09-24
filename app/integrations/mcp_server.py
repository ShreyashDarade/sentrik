"""MCP server exposing Sentinel's security checks as tools.

This publishes each registered check as an MCP tool plus a `run_check` meta-tool, so
MCP-capable clients (Claude Code, Cursor, etc.) can invoke checks through the Model
Context Protocol. Crucially, every tool call is still bound to a stored, verified
`AuthorizationRecord` and routed through the deterministic `ScopeGuard` +
`GuardedHttpClient` — the MCP client cannot widen scope. A call must supply an
`authorization_id`; the server rejects out-of-scope or unverified requests.

Requires the optional `mcp` package. `build_tools()` works without it (returns the
tool schema list) so the tool surface is inspectable/testable offline.
"""

from __future__ import annotations

import logging

from app.checks.base import registry

log = logging.getLogger("sentrik.mcp")

try:
    from mcp.server.mcpserver import MCPServer

    MCP_AVAILABLE = True
except Exception:  # noqa: BLE001  pragma: no cover
    MCP_AVAILABLE = False


def build_tools() -> list[dict]:
    """Return the MCP tool schema list (usable without the mcp package installed)."""
    tools: list[dict] = [
        {
            "name": "run_check",
            "description": (
                "Run a named security check against a URL within an authorized "
                "assessment scope. Enforced by the deterministic scope guard."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "authorization_id": {
                        "type": "string",
                        "description": "A verified AuthorizationRecord id (scope binding).",
                    },
                    "check_name": {
                        "type": "string",
                        "enum": [c.name for c in registry.all()],
                    },
                    "url": {
                        "type": "string",
                        "description": "Target URL (must be in scope).",
                    },
                    "method": {"type": "string", "default": "GET"},
                    "auth_required": {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "Caller-declared: whether the endpoint requires "
                            "authentication. Feeds exposure scoring; not verified here."
                        ),
                    },
                },
                "required": ["authorization_id", "check_name", "url"],
            },
        }
    ]
    for c in registry.all():
        tools.append(
            {
                "name": f"check.{c.name}",
                "description": f"{c.check_class.value} check ({c.intensity.value}, {c.cwe}). "
                "Bound to an authorized scope.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "authorization_id": {"type": "string"},
                        "url": {"type": "string"},
                        "auth_required": {"type": "boolean", "default": False},
                    },
                    "required": ["authorization_id", "url"],
                },
            }
        )
    return tools


async def _run_check_bound(
    authorization_id: str,
    check_name: str,
    url: str,
    method: str = "GET",
    auth_required: bool = False,
) -> dict:
    """Execute one check against a URL under a stored authorization record's scope.

    ``auth_required`` is caller-declared (the MCP client knows its endpoint; we do not
    probe for it here) and is echoed back in the result so consumers can see the
    assumption that fed exposure scoring.
    """
    from sqlalchemy import select

    from app.checks.context import CheckContext, EndpointView
    from app.core.db import get_sessionmaker
    from app.discovery.normalize import endpoint_fingerprint, templatize_path
    from app.models import AuthorizationRecord
    from app.security.http_client import GuardedHttpClient
    from app.security.scope import ScopeGuard, ScopeViolation

    check = registry.get(check_name)
    if check is None:
        return {"error": f"unknown check {check_name!r}"}

    sm = get_sessionmaker()
    async with sm() as session:
        record = (
            await session.execute(
                select(AuthorizationRecord).where(
                    AuthorizationRecord.id == authorization_id
                )
            )
        ).scalar_one_or_none()
    if record is None:
        return {"error": "authorization record not found"}

    guard = ScopeGuard(record)
    active = guard.check_record_active()
    if not active.allowed:
        return {"error": f"authorization not usable: {active.reason}"}
    cls_ok = guard.check_class_allowed(check.check_class.value, check.intensity)
    if not cls_ok.allowed:
        return {"error": f"check not permitted: {cls_ok.reason}"}
    req_ok = guard.check_request(method, url)
    if not req_ok.allowed:
        return {"error": f"out of scope: {req_ok.reason}"}

    from urllib.parse import urlsplit

    fingerprint = endpoint_fingerprint(method, url)
    ev = EndpointView(
        # Ad-hoc (non-persisted) endpoint: identify it by its own fingerprint so results
        # from different URLs are distinguishable, rather than a fixed label.
        id=f"adhoc-{fingerprint[:16]}",
        method=method.upper(),
        url=url,
        path_template=templatize_path(urlsplit(url).path or "/"),
        parameters=[
            {"name": k, "in": "query", "type": "string", "required": False}
            for k in _query_keys(url)
        ],
        request_body_schema={},
        auth_required=bool(auth_required),
        fingerprint=fingerprint,
    )
    findings_out = []
    applied = False
    try:
        async with GuardedHttpClient(guard) as client:
            ctx = CheckContext(
                client=client, endpoint=ev, intensity=check.intensity, base_url=url
            )
            applied = await check.applies_to(ctx)
            if applied:
                for f in await check.run(ctx):
                    findings_out.append(_finding_payload(f))
    except ScopeViolation as exc:
        return {"error": f"scope violation: {exc.reason}"}
    return {
        "check": check_name,
        "url": url,
        "endpoint_id": ev.id,
        "applicable": applied,
        "auth_required_declared": bool(auth_required),
        "findings": findings_out,
        "requests_made": guard.requests_made,
    }


def _finding_payload(f) -> dict:
    """Serialize a RawFinding for MCP callers *with* its proof.

    Evidence is already redacted by ``build_evidence_exchange`` at capture time; the
    reproduction recipe lets the caller (or Sentrik's validator) re-run the exact probe.
    """
    return {
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "cwe": f.cwe,
        "check_class": f.check_class,
        "description": f.description,
        "remediation": f.remediation,
        "endpoint_url": f.endpoint_url,
        "reproduction": dict(f.reproduction or {}),
        "evidence": [
            {
                "kind": e.kind,
                "note": e.note,
                "request": dict(getattr(e, "request", {}) or {}),
                "response": dict(getattr(e, "response", {}) or {}),
            }
            for e in (f.evidence or [])
        ],
    }


def _query_keys(url: str) -> list[str]:
    from urllib.parse import parse_qs, urlsplit

    return list(parse_qs(urlsplit(url).query).keys())


def build_server():
    """Build the MCP server (mcp 2.x MCPServer). Registers `run_check` plus one tool
    per check; every tool is bound to a stored authorization record's scope."""
    if not MCP_AVAILABLE:
        raise RuntimeError("mcp package not installed")
    server = MCPServer("sentrik-security")

    @server.tool(
        name="run_check",
        description="Run a named security check against a URL within an authorized scope.",
    )
    async def run_check(
        authorization_id: str,
        check_name: str,
        url: str,
        method: str = "GET",
        auth_required: bool = False,
    ) -> dict:
        return await _run_check_bound(
            authorization_id, check_name, url, method, auth_required
        )

    # one thin tool per registered check
    for c in registry.all():
        _register_check_tool(
            server, c.name, c.check_class.value, c.intensity.value, c.cwe
        )

    return server


def _register_check_tool(
    server, check_name: str, check_class: str, intensity: str, cwe: str
):
    async def _tool(
        authorization_id: str, url: str, auth_required: bool = False
    ) -> dict:
        return await _run_check_bound(
            authorization_id, check_name, url, auth_required=auth_required
        )

    _tool.__name__ = f"check_{check_name.replace('.', '_')}"
    server.tool(
        name=f"check.{check_name}",
        description=f"{check_class} check ({intensity}, {cwe}); bound to authorized scope.",
    )(_tool)


def serve_stdio() -> None:
    """Run the Sentrik MCP server over stdio (blocking).

    Register it with an MCP client (Claude Code / Cursor) — example config:

        {
          "mcpServers": {
            "sentrik": {
              "command": "python",
              "args": ["-m", "app.integrations.mcp_server"],
              "env": {"SENTINEL_DATABASE_URL": "sqlite+aiosqlite:///./sentinel.db"}
            }
          }
        }

    Every tool call remains bound to a stored, verified AuthorizationRecord and is routed
    through the deterministic ScopeGuard + GuardedHttpClient — the MCP client cannot widen
    scope. Approval/permission gating is delegated to the client's own tool-approval UX.
    """
    server = build_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover
    serve_stdio()
