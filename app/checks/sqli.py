"""SQL injection check — error-based and boolean-differential detection.

Strategy (SAFE_ACTIVE, non-state-changing):
  1. Baseline the endpoint with a benign value.
  2. Inject error-provoking payloads; match known DB error signatures in the response.
  3. Boolean-differential: send a TRUE-ish and FALSE-ish payload; a stable, meaningful
     difference in response (status/length/body) that tracks the boolean is strong signal.
Only GET/those already-authorized methods are used; no payload is destructive.
"""

from __future__ import annotations

import re

from app.checks.base import (
    BaseCheck,
    CheckContext,
    CheckError,
    RawEvidence,
    RawFinding,
    registry,
)
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange

DB_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"psql:.*ERROR",
    r"sqlite3?\.(OperationalError|Warning)",
    r"sqlite_error",
    r"near \".*\": syntax error",
    r"ORA-\d{5}",
    r"microsoft odbc .* driver",
    r"sqlstate\[",
    r"syntax error at or near",
]
_ERROR_RE = re.compile("|".join(DB_ERROR_SIGNATURES), re.IGNORECASE)

ERROR_PAYLOADS = ["'", '"', "')", "';", '"))', "' OR '1'='1' -- "]
TRUE_PAYLOAD = "1' OR '1'='1"
FALSE_PAYLOAD = "1' AND '1'='2"


class SqlInjectionCheck(BaseCheck):
    name = "sqli.reflected"
    check_class = CheckClass.SQLI
    intensity = TestIntensity.SAFE_ACTIVE
    cwe = "CWE-89"
    state_changing = False

    async def applies_to(self, ctx: CheckContext) -> bool:
        return bool(ctx.injectable_params()) or "{id}" in ctx.endpoint.path_template

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        params = ctx.query_params() or ctx.injectable_params()
        if not params:
            return []
        findings: list[RawFinding] = []
        # Focus on a bounded number of parameters/payloads.
        for param in params[: ctx.max_payloads]:
            finding = await self._probe_param(ctx, param)
            if finding:
                findings.append(finding)
        return findings

    async def _probe_param(self, ctx: CheckContext, param: dict) -> RawFinding | None:
        name = param["name"]
        base_val = "1"
        try:
            baseline = await self._send(ctx, {name: base_val})
        except (TargetUnreachable, CheckError):
            return None

        evidence: list[RawEvidence] = []

        # 1) error-based
        for payload in ERROR_PAYLOADS:
            try:
                resp = await self._send(ctx, {name: base_val + payload})
            except TargetUnreachable:
                continue
            if _ERROR_RE.search(resp.text):
                evidence.append(
                    RawEvidence(
                        kind="http_exchange",
                        note=f"DB error signature reflected for payload {payload!r} in param {name!r}",
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
                                "body": resp.text,
                                "elapsed_ms": resp.elapsed_ms,
                            },
                        ),
                    )
                )
                return RawFinding(
                    check_class=self.check_class.value,
                    title=f"SQL injection (error-based) in parameter '{name}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe=self.cwe,
                    description=(
                        f"Injecting a single quote into parameter '{name}' elicited a database "
                        f"error, indicating unsanitized input reaching a SQL query."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. Never concatenate "
                        "user input into SQL. Apply strict input validation and least-privilege DB accounts."
                    ),
                    evidence=evidence,
                    endpoint_url=ctx.endpoint.url,
                    dedup_seed=f"sqli:error:{name}",
                    reproduction={
                        "method": ctx.endpoint.method,
                        "url": ctx.endpoint.url,
                        "param": name,
                        "payload": base_val + payload,
                        "detector": "db_error_signature",
                    },
                )

        # 2) boolean-differential
        try:
            r_true = await self._send(ctx, {name: TRUE_PAYLOAD})
            r_false = await self._send(ctx, {name: FALSE_PAYLOAD})
        except TargetUnreachable:
            return None
        if self._boolean_differs(baseline, r_true, r_false):
            for r, lbl in ((r_true, "TRUE"), (r_false, "FALSE")):
                evidence.append(
                    RawEvidence(
                        kind="http_exchange",
                        note=f"boolean payload ({lbl})",
                        **build_evidence_exchange(
                            request={
                                "method": ctx.endpoint.method,
                                "url": r.url,
                                "headers": r.request_headers,
                                "body": r.request_body,
                            },
                            response={
                                "status": r.status_code,
                                "headers": r.headers,
                                "body": r.text,
                                "elapsed_ms": r.elapsed_ms,
                            },
                        ),
                    )
                )
            return RawFinding(
                check_class=self.check_class.value,
                title=f"SQL injection (boolean-based) in parameter '{name}'",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                cwe=self.cwe,
                description=(
                    f"Parameter '{name}' shows a consistent boolean-differential response to "
                    f"`OR 1=1` vs `AND 1=2` payloads, indicating a blind SQL injection."
                ),
                remediation="Use parameterized queries and reject SQL metacharacters where inappropriate.",
                evidence=evidence,
                endpoint_url=ctx.endpoint.url,
                dedup_seed=f"sqli:boolean:{name}",
                reproduction={
                    "method": ctx.endpoint.method,
                    "url": ctx.endpoint.url,
                    "param": name,
                    "true_payload": TRUE_PAYLOAD,
                    "false_payload": FALSE_PAYLOAD,
                    "detector": "boolean_differential",
                },
            )
        return None

    async def _send(self, ctx: CheckContext, overrides: dict):
        method = ctx.endpoint.method
        if method == "GET":
            return await ctx.client.get(ctx.endpoint.url, params=overrides)
        return await ctx.client.request(method, ctx.endpoint.url, data=overrides)

    @staticmethod
    def _boolean_differs(baseline, r_true, r_false) -> bool:
        # TRUE should resemble baseline; FALSE should differ meaningfully.
        if r_true.status_code != r_false.status_code:
            return True
        lt, lf = len(r_true.text), len(r_false.text)
        if max(lt, lf) == 0:
            return False
        diff_ratio = abs(lt - lf) / max(lt, lf)
        # require the TRUE response to be close to baseline to reduce noise
        lb = len(baseline.text) or 1
        true_close = abs(lt - lb) / max(lt, lb) < 0.15
        return diff_ratio > 0.30 and true_close


registry.register(SqlInjectionCheck())
