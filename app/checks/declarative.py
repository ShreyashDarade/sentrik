"""Declarative check runtime (AG-09).

A `DeclarativeCheck` implements the same `BaseCheck` contract as the built-in Python
checks, but its behavior is defined entirely by a manifest (from a versioned SKILL.md).
This lets an operator add a *working* new detection at runtime — no code deploy — while
every request still flows through the scope-enforced `GuardedHttpClient` and every
declared intensity/method is gated by the authorization record.

Manifest shape (YAML frontmatter of a SKILL.md, or JSON):

    name: cors.reflect-origin
    version: 1.0.0
    check_class: cors            # arbitrary string; must be authorized to run
    intensity: safe_active       # passive | safe_active | invasive
    cwe: CWE-942
    severity: medium             # info|low|medium|high|critical
    confidence: high             # low|medium|high|certain
    title: "Reflected-origin CORS misconfiguration"
    description: "..."
    remediation: "..."
    detector:
      type: header_reflects      # see DETECTORS below
      request_header: Origin
      header_value: "https://evil.example.net"
      response_header: access-control-allow-origin
      require_header: access-control-allow-credentials
      require_value: "true"

Supported detector `type`s:
  * error_signature   — inject `payloads` into params; match any of `signatures` (regex).
  * reflection        — inject a unique marker; flag if reflected UNescaped.
  * status_code       — inject `payloads`; flag if response status in `trigger_status`.
  * header_missing    — GET; flag if any of `headers` are absent on the response.
  * header_present    — GET; flag if any of `headers` are present (disclosure).
  * header_reflects   — send `request_header: header_value`; flag if `response_header`
                        echoes the value (optionally require `require_header==require_value`).

Everything the detector needs is validated defensively; a malformed manifest yields no
findings rather than raising.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from app.checks.base import BaseCheck, CheckContext, RawEvidence, RawFinding
from app.checks.xss import renderable_html_context
from app.core.enums import Confidence, Severity, TestIntensity
from app.security.http_client import TargetUnreachable
from app.security.redaction import build_evidence_exchange

DETECTOR_TYPES = {
    "error_signature",
    "reflection",
    "status_code",
    "header_missing",
    "header_present",
    "header_reflects",
}


@dataclass(frozen=True)
class _ClassRef:
    """Lightweight stand-in for a CheckClass enum so arbitrary class strings work."""

    value: str


def _coerce_intensity(value: str) -> TestIntensity:
    try:
        return TestIntensity(value)
    except ValueError:
        return TestIntensity.PASSIVE


def _coerce_sev(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.MEDIUM


def _coerce_conf(value: str) -> Confidence:
    try:
        return Confidence(value)
    except ValueError:
        return Confidence.MEDIUM


def manifest_is_executable(manifest: dict) -> bool:
    """True if the manifest carries a valid declarative detector we can run."""
    det = manifest.get("detector")
    return isinstance(det, dict) and det.get("type") in DETECTOR_TYPES


class DeclarativeCheck(BaseCheck):
    def __init__(self, manifest: dict):
        self.manifest = manifest or {}
        self.name = str(self.manifest.get("name", "declarative.unnamed"))
        self._class = _ClassRef(
            str(self.manifest.get("check_class", "info_disclosure"))
        )
        self.intensity = _coerce_intensity(
            str(self.manifest.get("intensity", "passive"))
        )
        self.cwe = str(self.manifest.get("cwe", ""))
        self.state_changing = bool(self.manifest.get("state_changing", False))
        # F-11: declarative policy — which environments this check may run in. Empty ⇒ any
        # (subject to the deterministic scope/intensity gates). Normalized to lower-case.
        self.allowed_environments = [
            str(e).lower()
            for e in (self.manifest.get("allowed_environments") or [])
            if str(e).strip()
        ]
        self.detector = self.manifest.get("detector", {}) or {}
        self._severity = _coerce_sev(str(self.manifest.get("severity", "medium")))
        self._confidence = _coerce_conf(str(self.manifest.get("confidence", "medium")))
        self._title = str(self.manifest.get("title", self.name))
        self._description = str(self.manifest.get("description", ""))
        self._remediation = str(self.manifest.get("remediation", ""))

    # BaseCheck expects check_class to expose `.value`
    @property
    def check_class(self):  # type: ignore[override]
        return self._class

    async def applies_to(self, ctx: CheckContext) -> bool:
        dtype = self.detector.get("type")
        if dtype in ("header_missing", "header_present", "header_reflects"):
            return ctx.endpoint.method == "GET"
        # injection-style detectors need at least one injectable parameter
        return bool(ctx.injectable_params()) or "{id}" in ctx.endpoint.path_template

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        dtype = self.detector.get("type")
        try:
            if dtype == "error_signature":
                return await self._error_signature(ctx)
            if dtype == "reflection":
                return await self._reflection(ctx)
            if dtype == "status_code":
                return await self._status_code(ctx)
            if dtype in ("header_missing", "header_present"):
                return await self._header_presence(
                    ctx, want_present=(dtype == "header_present")
                )
            if dtype == "header_reflects":
                return await self._header_reflects(ctx)
        except TargetUnreachable:
            return []
        return []

    # ------------------------------------------------------------------ #
    # detectors
    # ------------------------------------------------------------------ #
    async def _send(self, ctx, overrides: dict, headers: dict | None = None):
        method = ctx.endpoint.method
        if method == "GET":
            return await ctx.client.get(
                ctx.endpoint.url, params=overrides, headers=headers
            )
        return await ctx.client.request(
            method, ctx.endpoint.url, data=overrides, headers=headers
        )

    def _finding(self, ctx, resp, note: str, seed: str, repro: dict) -> RawFinding:
        ev = RawEvidence(
            kind="http_exchange",
            note=note,
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
        return RawFinding(
            check_class=self._class.value,
            title=self._title,
            severity=self._severity,
            confidence=self._confidence,
            cwe=self.cwe,
            description=self._description or note,
            remediation=self._remediation,
            evidence=[ev],
            endpoint_url=ctx.endpoint.url,
            dedup_seed=f"declarative:{self.name}:{seed}",
            reproduction={**repro, "declarative": self.name},
        )

    async def _error_signature(self, ctx: CheckContext) -> list[RawFinding]:
        payloads = [str(p) for p in self.detector.get("payloads", ["'"])][
            : ctx.max_payloads
        ]
        sigs = self.detector.get("signatures", [])
        rx = re.compile("|".join(sigs), re.IGNORECASE) if sigs else None
        if rx is None:
            return []
        for param in (ctx.query_params() or ctx.injectable_params())[
            : ctx.max_payloads
        ]:
            name = param["name"]
            for payload in payloads:
                resp = await self._send(ctx, {name: payload})
                if rx.search(resp.text):
                    return [
                        self._finding(
                            ctx,
                            resp,
                            f"signature matched for payload {payload!r} in {name!r}",
                            f"error:{name}",
                            {
                                "method": ctx.endpoint.method,
                                "url": ctx.endpoint.url,
                                "param": name,
                                "payload": payload,
                                "detector": "error_signature",
                                "signatures": list(sigs),
                            },
                        )
                    ]
        return []

    async def _status_code(self, ctx: CheckContext) -> list[RawFinding]:
        payloads = [str(p) for p in self.detector.get("payloads", ["'"])][
            : ctx.max_payloads
        ]
        trigger = {int(s) for s in self.detector.get("trigger_status", [500])}
        for param in (ctx.query_params() or ctx.injectable_params())[
            : ctx.max_payloads
        ]:
            name = param["name"]
            for payload in payloads:
                resp = await self._send(ctx, {name: payload})
                if resp.status_code in trigger:
                    return [
                        self._finding(
                            ctx,
                            resp,
                            f"status {resp.status_code} on payload {payload!r} in {name!r}",
                            f"status:{name}",
                            {
                                "method": ctx.endpoint.method,
                                "url": ctx.endpoint.url,
                                "param": name,
                                "payload": payload,
                                "detector": "status_code",
                                "trigger_status": sorted(trigger),
                            },
                        )
                    ]
        return []

    async def _reflection(self, ctx: CheckContext) -> list[RawFinding]:
        template = self.detector.get("marker_template", "<zzz{token}>")
        for param in ctx.injectable_params()[: ctx.max_payloads]:
            name = param["name"]
            token = secrets.token_hex(5)
            marker = template.format(token=token)
            resp = await self._send(ctx, {name: marker})
            # Same rule as the built-in XSS check: only an HTML document with a
            # non-error status is a renderable context (JSON/4xx echoes are not).
            if not renderable_html_context(
                resp.status_code, resp.headers.get("content-type", "")
            ):
                continue
            escaped = marker.replace("<", "&lt;").replace(">", "&gt;")
            if marker in resp.text and (escaped == marker or escaped not in resp.text):
                return [
                    self._finding(
                        ctx,
                        resp,
                        f"unescaped reflection of marker in {name!r}",
                        f"reflect:{name}",
                        {
                            "method": ctx.endpoint.method,
                            "url": ctx.endpoint.url,
                            "param": name,
                            "payload": marker,
                            "marker": token,
                            "marker_template": template,
                            "detector": "reflection",
                        },
                    )
                ]
        return []

    async def _header_presence(
        self, ctx: CheckContext, want_present: bool
    ) -> list[RawFinding]:
        headers = [h.lower() for h in self.detector.get("headers", [])]
        if not headers:
            return []
        resp = await self._send(ctx, {})
        present = {k.lower() for k in resp.headers}
        if want_present:
            hit = [h for h in headers if h in present]
        else:
            hit = [h for h in headers if h not in present]
        if hit:
            verb = "present" if want_present else "missing"
            return [
                self._finding(
                    ctx,
                    resp,
                    f"headers {verb}: {hit}",
                    f"headers:{sorted(hit)}",
                    {
                        "method": "GET",
                        "url": ctx.endpoint.url,
                        "detector": "header_presence",
                        "headers": hit,
                        "want_present": want_present,
                    },
                )
            ]
        return []

    async def _header_reflects(self, ctx: CheckContext) -> list[RawFinding]:
        req_header = self.detector.get("request_header")
        value = self.detector.get("header_value", "https://evil.example.net")
        resp_header = str(self.detector.get("response_header", "")).lower()
        if not req_header or not resp_header:
            return []
        resp = await self._send(ctx, {}, headers={req_header: value})
        rh = {k.lower(): v for k, v in resp.headers.items()}
        echoed = rh.get(resp_header, "")
        if value not in echoed and echoed != "*":
            return []
        require_header = self.detector.get("require_header")
        if require_header:
            rv = rh.get(str(require_header).lower(), "")
            if str(self.detector.get("require_value", "")).lower() not in rv.lower():
                return []
        return [
            self._finding(
                ctx,
                resp,
                f"{resp_header} reflects injected {req_header}",
                f"header_reflect:{resp_header}",
                {
                    "method": "GET",
                    "url": ctx.endpoint.url,
                    "detector": "header_reflects",
                    "request_header": req_header,
                    "header_value": value,
                    "response_header": resp_header,
                },
            )
        ]


def build_declarative_check(manifest: dict) -> DeclarativeCheck | None:
    """Construct a DeclarativeCheck from a stored manifest, or None if not executable."""
    if not manifest_is_executable(manifest):
        return None
    try:
        return DeclarativeCheck(manifest)
    except Exception:  # noqa: BLE001
        return None
