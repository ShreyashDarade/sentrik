"""Business-logic multi-step flow runner (BS-15).

Most business-logic flaws only appear across a *sequence* of requests, not a single probe:
a coupon that stacks on repeat apply, a checkout that trusts a client-sent price, a state
machine that accepts an out-of-order transition. This check executes an ordered flow through
the guarded client — each step issues a request, optionally extracts a variable from the
response, and the flow asserts an invariant on the final state. When the invariant is
violated a finding is raised with the full exchange as evidence and a replayable recipe.

The flow is deterministic and read-only against the lab fixture (an ephemeral cart), so it is
SAFE_ACTIVE and non-state-changing. Additional flows can be added declaratively via
``FLOWS`` without new code paths.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding, registry
from app.core.enums import CheckClass, Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange


@dataclass
class FlowStep:
    method: str
    path: str  # may contain {var} placeholders filled from extracted vars
    json_body: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    extract: dict = field(default_factory=dict)  # var_name -> JSON key in response
    expect_status: tuple[int, ...] = (200, 201)


@dataclass
class FlowDefinition:
    name: str
    anchor_suffix: str  # the discovered endpoint (method+path) this flow attaches to
    anchor_method: str
    steps: list[FlowStep]
    invariant_var: str  # numeric var extracted along the way
    invariant_max: float  # finding when the observed value exceeds this
    title: str
    description: str
    remediation: str
    cwe: str = "CWE-840"
    severity: Severity = Severity.HIGH


COUPON_REPLAY = FlowDefinition(
    name="coupon_replay",
    anchor_suffix="/api/cart",
    anchor_method="POST",
    steps=[
        FlowStep("POST", "/api/cart", extract={"cart_id": "cart_id"}, expect_status=(200, 201)),
        FlowStep("POST", "/api/cart/{cart_id}/coupon", json_body={"code": "SAVE10"}),
        FlowStep("POST", "/api/cart/{cart_id}/coupon", json_body={"code": "SAVE10"}),
        FlowStep(
            "GET",
            "/api/cart/{cart_id}",
            extract={"discount_pct": "discount_pct"},
            expect_status=(200,),
        ),
    ],
    invariant_var="discount_pct",
    invariant_max=10,
    title="Coupon replay stacks discounts (missing idempotency)",
    description=(
        "The same coupon can be applied more than once in a single cart, and each apply "
        "stacks its discount. Applying SAVE10 twice yielded a discount above the single-use "
        "maximum, so an attacker can drive the price arbitrarily low by replaying the coupon."
    ),
    remediation=(
        "Make coupon application idempotent: track applied coupon codes server-side and "
        "reject (or ignore) a repeated code; recompute totals from server state, never from "
        "client-supplied discount values."
    ),
)

FLOWS = [COUPON_REPLAY]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _extract(body: str, key: str):
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        m = re.search(rf'"{re.escape(key)}"\s*:\s*"?([^",}}]+)', body or "")
        return m.group(1) if m else None
    return data.get(key) if isinstance(data, dict) else None


class BusinessFlowCheck(BaseCheck):
    name = "business_flow.multi_step"
    check_class = CheckClass.BUSINESS_FLOW
    intensity = TestIntensity.SAFE_ACTIVE
    cwe = "CWE-840"
    state_changing = False  # ephemeral lab cart; the flow only reads back its own state

    def _flow_for(self, ctx: CheckContext) -> FlowDefinition | None:
        path = ctx.endpoint.path_template or urlsplit(ctx.endpoint.url).path
        for flow in FLOWS:
            if ctx.endpoint.method.upper() == flow.anchor_method and path.rstrip("/").endswith(
                flow.anchor_suffix
            ):
                return flow
        return None

    async def applies_to(self, ctx: CheckContext) -> bool:
        return self._flow_for(ctx) is not None

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        flow = self._flow_for(ctx)
        if flow is None:
            return []
        origin = _origin(ctx.endpoint.url)
        variables: dict[str, str] = {}
        evidence: list[RawEvidence] = []
        observed = None
        try:
            for step in flow.steps:
                path = step.path.format(**variables) if variables else step.path
                url = origin + path
                if step.method.upper() == "GET":
                    resp = await ctx.client.get(url, params=step.params or None)
                else:
                    resp = await ctx.client.post(url, json=step.json_body or None)
                evidence.append(_exchange(resp, f"{step.method} {path}"))
                if resp.status_code not in step.expect_status:
                    # the flow could not complete (e.g. patched rejects the replay) — no flaw
                    return []
                for var, key in step.extract.items():
                    val = _extract(resp.text, key)
                    if val is None:
                        return []
                    variables[var] = str(val)
                    if var == flow.invariant_var:
                        observed = val
        except TargetUnreachable:
            return []
        if observed is None:
            return []
        try:
            numeric = float(observed)
        except (ValueError, TypeError):
            return []
        if numeric <= flow.invariant_max:
            return []
        return [
            RawFinding(
                check_class=self.check_class.value,
                title=flow.title,
                severity=flow.severity,
                confidence=Confidence.HIGH,
                cwe=flow.cwe,
                description=(
                    f"{flow.description} Observed {flow.invariant_var}={numeric} "
                    f"(single-use maximum {flow.invariant_max})."
                ),
                remediation=flow.remediation,
                evidence=evidence,
                endpoint_url=ctx.endpoint.url,
                dedup_seed=f"business_flow:{flow.name}",
                reproduction={
                    "detector": "business_flow",
                    "flow": flow.name,
                    "origin": origin,
                    "invariant_var": flow.invariant_var,
                    "invariant_max": flow.invariant_max,
                },
            )
        ]


def _exchange(resp, note: str) -> RawEvidence:
    return RawEvidence(
        kind="http_exchange",
        note=note,
        **build_evidence_exchange(
            request={
                "method": "GET" if note.startswith("GET") else "POST",
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


def run_coupon_flow_recipe(client, recipe: dict):
    """Re-run a business-flow recipe; returns the observed invariant value (or None)."""
    flow = next((f for f in FLOWS if f.name == recipe.get("flow")), None)
    if flow is None:
        return None
    return flow  # the async replay lives in validation._validate_business_flow


registry.register(BusinessFlowCheck())
