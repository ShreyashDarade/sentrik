"""Security-headers & information-disclosure check — passive, read-only.

Fetches the endpoint once and inspects response headers for missing/weak security
controls and obvious server/version disclosure. PASSIVE intensity: no injection.
"""

from __future__ import annotations

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding, registry
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange

# header -> (human name, severity if missing)
EXPECTED_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
    "x-frame-options": ("X-Frame-Options", Severity.LOW),
    "strict-transport-security": ("Strict-Transport-Security", Severity.MEDIUM),
}
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


class SecurityHeadersCheck(BaseCheck):
    name = "headers.security"
    check_class = CheckClass.SECURITY_HEADERS
    intensity = TestIntensity.PASSIVE
    cwe = "CWE-693"
    state_changing = False

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.endpoint.method != "GET":
            return []
        try:
            resp = await ctx.client.get(ctx.endpoint.url)
        except TargetUnreachable:
            return []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        findings: list[RawFinding] = []

        ev = RawEvidence(
            kind="http_exchange",
            note="response headers inspected",
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

        # only report on HTML/main documents to avoid noise on assets
        is_https = resp.url.lower().startswith("https://")
        missing = []
        worst = Severity.INFO
        for hkey, (hname, sev) in EXPECTED_HEADERS.items():
            if hkey == "strict-transport-security" and not is_https:
                continue
            if hkey not in headers_lower:
                missing.append(hname)
                if _sev_rank(sev) > _sev_rank(worst):
                    worst = sev
        if missing:
            findings.append(
                RawFinding(
                    check_class=self.check_class.value,
                    title=f"Missing security headers: {', '.join(missing)}",
                    severity=worst,
                    confidence=Confidence.CERTAIN,
                    cwe=self.cwe,
                    description=(
                        "The response is missing recommended security headers: "
                        + ", ".join(missing)
                        + "."
                    ),
                    remediation=(
                        "Add the missing headers at the application or reverse-proxy layer. "
                        "Use a strict CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, "
                        "and HSTS on HTTPS endpoints."
                    ),
                    evidence=[ev],
                    endpoint_url=ctx.endpoint.url,
                    dedup_seed=f"headers:{sorted(missing)}",
                )
            )

        disclosed = {
            h: headers_lower[h] for h in DISCLOSURE_HEADERS if h in headers_lower
        }
        if disclosed:
            findings.append(
                RawFinding(
                    check_class=CheckClass.INFO_DISCLOSURE.value,
                    title="Server/technology version disclosure in headers",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    cwe="CWE-200",
                    description=f"Response discloses technology details: {disclosed}.",
                    remediation="Suppress or genericize Server/X-Powered-By style headers.",
                    evidence=[ev],
                    endpoint_url=ctx.endpoint.url,
                    dedup_seed=f"disclosure:{sorted(disclosed)}",
                )
            )
        return findings


def _sev_rank(sev: Severity) -> int:
    order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    return order.index(sev)


registry.register(SecurityHeadersCheck())
