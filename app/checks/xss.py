"""Reflected XSS check — unique-marker reflection with context awareness.

Injects a uniquely identifiable marker containing HTML-significant characters and
checks whether it is reflected *unescaped* in an HTML response. Escaped reflections
(&lt;, &gt;) are not flagged. SAFE_ACTIVE, non-state-changing.
"""

from __future__ import annotations

import secrets

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding, registry
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange


class ReflectedXssCheck(BaseCheck):
    name = "xss.reflected"
    check_class = CheckClass.XSS
    intensity = TestIntensity.SAFE_ACTIVE
    cwe = "CWE-79"
    state_changing = False

    async def applies_to(self, ctx: CheckContext) -> bool:
        return bool(ctx.injectable_params())

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        params = ctx.injectable_params()
        findings: list[RawFinding] = []
        for param in params[: ctx.max_payloads]:
            finding = await self._probe(ctx, param)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ctx: CheckContext, param: dict) -> RawFinding | None:
        name = param["name"]
        token = secrets.token_hex(5)
        # Distinctive breakout payload; the raw '<' '>' must survive to be dangerous.
        marker = f"<szx{token}>'\"</szx{token}>"
        overrides = {name: marker}
        try:
            if ctx.endpoint.method == "GET":
                resp = await ctx.client.get(ctx.endpoint.url, params=overrides)
            else:
                resp = await ctx.client.request(
                    ctx.endpoint.method, ctx.endpoint.url, data=overrides
                )
        except TargetUnreachable:
            return None

        ctype = resp.headers.get("content-type", "").lower()
        body = resp.text
        raw_present = f"<szx{token}>" in body
        escaped_present = f"&lt;szx{token}&gt;" in body

        if raw_present and not escaped_present:
            severity = Severity.HIGH if "html" in ctype else Severity.MEDIUM
            confidence = Confidence.HIGH if "html" in ctype else Confidence.MEDIUM
            ev = RawEvidence(
                kind="http_exchange",
                note=f"unescaped reflection of marker in param {name!r} (content-type={ctype})",
                **build_evidence_exchange(
                    request={
                        "method": ctx.endpoint.method,
                        "url": resp.url,
                        "headers": resp.request_headers,
                        "body": resp.request_body,
                    },
                    response={
                        "status": resp.status_code,
                        "headers": resp.headers,
                        "body": body,
                        "elapsed_ms": resp.elapsed_ms,
                    },
                ),
            )
            return RawFinding(
                check_class=self.check_class.value,
                title=f"Reflected XSS in parameter '{name}'",
                severity=severity,
                confidence=confidence,
                cwe=self.cwe,
                description=(
                    f"Input to parameter '{name}' is reflected into the response without HTML "
                    f"encoding, allowing script injection in a victim's browser."
                ),
                remediation=(
                    "Context-encode all user input on output (HTML entity encoding for HTML "
                    "context). Apply a strict Content-Security-Policy. Prefer framework auto-escaping."
                ),
                evidence=[ev],
                endpoint_url=ctx.endpoint.url,
                dedup_seed=f"xss:{name}",
                reproduction={
                    "method": ctx.endpoint.method,
                    "url": ctx.endpoint.url,
                    "param": name,
                    "payload": marker,
                    "detector": "unescaped_reflection",
                    "marker": token,
                },
            )
        return None


registry.register(ReflectedXssCheck())
