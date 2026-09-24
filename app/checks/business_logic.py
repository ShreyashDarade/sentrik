"""Business-logic check: missing server-side numeric range validation (CP-01).

Many business-logic flaws reduce to a quantity/amount/count style parameter that the
server accepts outside its meaningful range (zero, negative) and then *applies* in a
computation (totals, discounts, pagination), instead of rejecting it. This check is
read-only (GET only, non-state-changing, SAFE_ACTIVE) and evidence-based:

  1. baseline: a normal in-range value is accepted (2xx);
  2. type validation exists: a non-numeric value is rejected (4xx) — so the parameter
     really is treated as a number by the server;
  3. an out-of-range value is nevertheless accepted (2xx) AND echoed back in the body
     as a standalone number, i.e. it was applied rather than clamped or ignored.

Only when all three hold is a finding raised; that keeps false positives low and gives
the independent validator a deterministic recipe (``detector: numeric_bounds``).
"""

from __future__ import annotations

import re

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding, registry
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange

# Parameter names that carry business meaning where range matters.
_RANGE_PARAM = re.compile(
    r"(quantity|qty|amount|count|units?|seats?|tickets?|items?|discount|percent|"
    r"limit|page|per_page|size|offset)",
    re.IGNORECASE,
)
_NUMERIC_TYPES = {"integer", "number", "int", "float"}
BASELINE_VALUE = "1"
OUT_OF_RANGE_VALUES = ["-1", "0"]
NON_NUMERIC_VALUE = "abc"


def _echoes_number(body: str, value: str) -> bool:
    """True if ``value`` appears in the body as a standalone numeric token."""
    return re.search(rf"(?<![\w.-]){re.escape(value)}(?![\w.])", body or "") is not None


class NumericBoundsCheck(BaseCheck):
    name = "business_logic.numeric_bounds"
    check_class = CheckClass.BUSINESS_LOGIC
    intensity = TestIntensity.SAFE_ACTIVE
    cwe = "CWE-20"
    state_changing = False

    def _candidate_params(self, ctx: CheckContext) -> list[dict]:
        out = []
        for p in ctx.endpoint.parameters:
            name = p.get("name", "")
            ptype = str(p.get("type", "")).lower()
            if p.get("in", "query") != "query":
                continue
            if _RANGE_PARAM.search(name) or ptype in _NUMERIC_TYPES:
                out.append(p)
        return out

    async def applies_to(self, ctx: CheckContext) -> bool:
        return ctx.endpoint.method == "GET" and bool(self._candidate_params(ctx))

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for param in self._candidate_params(ctx)[: ctx.max_payloads]:
            finding = await self._probe_param(ctx, param)
            if finding:
                findings.append(finding)
        return findings

    async def _send(self, ctx: CheckContext, overrides: dict):
        return await ctx.client.get(ctx.endpoint.url, params=overrides)

    async def _probe_param(self, ctx: CheckContext, param: dict) -> RawFinding | None:
        name = param["name"]
        try:
            baseline = await self._send(ctx, {name: BASELINE_VALUE})
            if not (200 <= baseline.status_code < 300):
                return None
            typed = await self._send(ctx, {name: NON_NUMERIC_VALUE})
            if typed.status_code < 400:
                return None  # not treated as a number server-side; out of scope here
            for value in OUT_OF_RANGE_VALUES:
                resp = await self._send(ctx, {name: value})
                if 200 <= resp.status_code < 300 and _echoes_number(resp.text, value):
                    return self._finding(ctx, name, value, baseline, resp)
        except TargetUnreachable:
            return None
        return None

    def _finding(self, ctx, name, value, baseline, resp) -> RawFinding:
        def _ev(r, note):
            return RawEvidence(
                kind="http_exchange",
                note=note,
                **build_evidence_exchange(
                    request={
                        "method": "GET",
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

        return RawFinding(
            check_class=self.check_class.value,
            title=f"Missing server-side range validation for '{name}'",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            cwe=self.cwe,
            description=(
                f"Parameter '{name}' is validated for type (non-numeric input is rejected) "
                f"but not for business range: the value {value} was accepted with status "
                f"{resp.status_code} and applied in the response. Out-of-range quantities, "
                f"amounts or counts can corrupt totals, pricing or pagination logic."
            ),
            remediation=(
                "Enforce business-rule bounds server-side (e.g. quantity >= 1, amounts > 0, "
                "page >= 1) and reject out-of-range values with a 4xx; never derive totals "
                "or entitlements from unvalidated client-supplied numbers."
            ),
            evidence=[
                _ev(baseline, f"baseline {name}={BASELINE_VALUE} accepted"),
                _ev(resp, f"out-of-range {name}={value} accepted and applied"),
            ],
            endpoint_url=ctx.endpoint.url,
            dedup_seed=f"business_logic:range:{name}",
            reproduction={
                "method": "GET",
                "url": ctx.endpoint.url,
                "param": name,
                "payload": value,
                "baseline_value": BASELINE_VALUE,
                "detector": "numeric_bounds",
            },
        )


registry.register(NumericBoundsCheck())
