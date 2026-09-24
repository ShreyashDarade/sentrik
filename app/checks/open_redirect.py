"""Open-redirect check — inject an external URL into redirect-like parameters.

If a parameter value controls a Location header (302/3xx) or a meta-refresh to an
attacker-controlled host, it is an open redirect. SAFE_ACTIVE, non-state-changing.
The guarded client blocks the redirect from actually being followed cross-host, but
we inspect the *Location header on the first hop* to detect the vulnerability safely.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding, registry
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange
from app.security.scope import ScopeViolation

REDIRECT_PARAM_HINTS = (
    "redirect",
    "return",
    "url",
    "next",
    "dest",
    "continue",
    "goto",
    "callback",
)
CANARY_HOST = "evil.example.net"
CANARY = f"https://{CANARY_HOST}/probe"


class OpenRedirectCheck(BaseCheck):
    name = "redirect.open"
    check_class = CheckClass.OPEN_REDIRECT
    intensity = TestIntensity.SAFE_ACTIVE
    cwe = "CWE-601"
    state_changing = False

    async def applies_to(self, ctx: CheckContext) -> bool:
        return any(
            any(h in p.get("name", "").lower() for h in REDIRECT_PARAM_HINTS)
            for p in ctx.injectable_params()
        )

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        candidates = [
            p
            for p in ctx.injectable_params()
            if any(h in p.get("name", "").lower() for h in REDIRECT_PARAM_HINTS)
        ]
        findings: list[RawFinding] = []
        for param in candidates[: ctx.max_payloads]:
            f = await self._probe(ctx, param)
            if f:
                findings.append(f)
        return findings

    async def _probe(self, ctx: CheckContext, param: dict) -> RawFinding | None:
        name = param["name"]
        overrides = {name: CANARY}
        try:
            # max_redirects=0-ish: we want to see the first-hop Location, not follow it.
            resp = await ctx.client.get(
                ctx.endpoint.url, params=overrides, max_redirects=0
            )
        except ScopeViolation:
            # The guard blocked following a cross-host redirect — that itself proves the
            # app tried to redirect to our canary. Treat as strong signal.
            return self._finding(
                ctx, name, location=CANARY, blocked_by_guard=True, evidence=None
            )
        except TargetUnreachable:
            return None

        location = resp.headers.get("location", "")
        if location and urlsplit(location).hostname == CANARY_HOST:
            ev = RawEvidence(
                kind="http_exchange",
                note=f"Location header points to attacker-controlled host via param {name!r}",
                **build_evidence_exchange(
                    request={
                        "method": "GET",
                        "url": resp.url,
                        "headers": resp.request_headers,
                        "body": None,
                    },
                    response={
                        "status": resp.status_code,
                        "headers": resp.headers,
                        "body": "",
                        "elapsed_ms": resp.elapsed_ms,
                    },
                ),
            )
            return self._finding(
                ctx, name, location=location, blocked_by_guard=False, evidence=ev
            )
        return None

    def _finding(
        self, ctx, name, *, location, blocked_by_guard, evidence
    ) -> RawFinding:
        return RawFinding(
            check_class=self.check_class.value,
            title=f"Open redirect via parameter '{name}'",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH if not blocked_by_guard else Confidence.MEDIUM,
            cwe=self.cwe,
            description=(
                f"Parameter '{name}' controls the redirect target; a request set it to "
                f"{location!r}, an attacker-controlled host. This enables phishing and OAuth token theft."
            ),
            remediation=(
                "Validate redirect targets against an allowlist of internal paths/hosts. "
                "Reject absolute external URLs, or map to server-side identifiers."
            ),
            evidence=[evidence] if evidence else [],
            endpoint_url=ctx.endpoint.url,
            dedup_seed=f"open_redirect:{name}",
            reproduction={
                "method": "GET",
                "url": ctx.endpoint.url,
                "param": name,
                "payload": CANARY,
                "detector": "location_header_host",
            },
        )


registry.register(OpenRedirectCheck())
