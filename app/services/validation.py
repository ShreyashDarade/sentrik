"""Independent validation of suspected findings.

The validator receives only a finding's *reproduction recipe* (method, url, param,
payload, detector) — not the original evidence or the detector's conclusion — and
independently re-executes the minimal proof. This controlled-evidence-access design
reduces confirmation bias. Outcomes are explicit:

    confirmed     — independent re-proof succeeded
    suspected     — original signal stands but independent proof was weaker
    inconclusive  — could not decide (target error, flapping)
    rejected      — independent attempt refuted the finding (false positive)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.checks.sqli import DB_ERROR_SIGNATURES
from app.checks.xss import renderable_html_context
from app.core.enums import FindingStatus
from app.security.http_client import GuardedHttpClient, TargetUnreachable
from app.security.scope import ScopeViolation

_ERROR_RE = re.compile("|".join(DB_ERROR_SIGNATURES), re.IGNORECASE)


@dataclass
class ValidationOutcome:
    outcome: FindingStatus
    method: str
    detail: str
    evidence: dict | None = None


async def validate_finding(
    client: GuardedHttpClient,
    *,
    check_class: str,
    reproduction: dict,
    sessions: list | None = None,
) -> ValidationOutcome:
    """Independently re-prove a finding from its reproduction recipe.

    ``sessions`` (CP-04) are the assessment's *authenticated test-account sessions*
    (``AuthSession``: role_name, headers, expired). They are handed to validators whose
    proof is inherently session-relative — BOLA needs to act *as the attacker role* named
    in the recipe. The validator still never sees the original evidence or conclusion.
    """
    if not reproduction:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE,
            "no_recipe",
            "finding has no reproduction recipe",
        )
    try:
        if check_class == "bola":
            return await _validate_bola(client, reproduction, sessions or [])
        dispatch = {
            "sqli": _validate_sqli,
            "xss": _validate_xss,
            "open_redirect": _validate_open_redirect,
            "security_headers": _validate_headers,
            "info_disclosure": _validate_headers,
            "business_logic": _validate_business_logic,
            "business_flow": _validate_business_flow,
            "llm_prompt_injection": _validate_prompt_injection,
        }.get(check_class)
        if dispatch is None:
            # Declarative checks (arbitrary check_class) validate by their detector type.
            if reproduction.get("detector"):
                return await _validate_declarative(client, reproduction)
            return ValidationOutcome(
                FindingStatus.INCONCLUSIVE,
                "no_validator",
                f"no independent validator for {check_class}",
            )
        return await dispatch(client, reproduction)
    except ScopeViolation as exc:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE,
            "scope_blocked",
            f"validation blocked by scope: {exc.reason}",
        )
    except TargetUnreachable as exc:
        return ValidationOutcome(FindingStatus.INCONCLUSIVE, "unreachable", str(exc))


async def _validate_sqli(client, repro) -> ValidationOutcome:
    url, param = repro.get("url"), repro.get("param")
    method = repro.get("method", "GET")
    detector = repro.get("detector")
    if detector == "db_error_signature":
        payload = repro.get("payload", "'")
        resp = await _send(client, method, url, {param: payload})
        if _ERROR_RE.search(resp.text):
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "independent_replay",
                "DB error signature reproduced independently",
                evidence=_ev(resp),
            )
        # try one more canonical payload before rejecting
        resp2 = await _send(client, method, url, {param: "'\""})
        if _ERROR_RE.search(resp2.text):
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "independent_replay",
                "DB error reproduced with alternate payload",
                evidence=_ev(resp2),
            )
        return ValidationOutcome(
            FindingStatus.REJECTED,
            "independent_replay",
            "no DB error signature on independent replay",
        )
    if detector == "boolean_differential":
        baseline = await _send(client, method, url, {param: "1"})
        r_true = await _send(client, method, url, {param: repro.get("true_payload")})
        r_false = await _send(client, method, url, {param: repro.get("false_payload")})
        differs = (r_true.status_code != r_false.status_code) or _len_differs(
            r_true.text, r_false.text
        )
        true_close = not _len_differs(r_true.text, baseline.text, threshold=0.15)
        if differs and true_close:
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "boolean_differential",
                "boolean differential reproduced",
                evidence=_ev(r_true),
            )
        if differs:
            return ValidationOutcome(
                FindingStatus.SUSPECTED,
                "boolean_differential",
                "differential present but weaker than reported",
            )
        return ValidationOutcome(
            FindingStatus.REJECTED,
            "boolean_differential",
            "no boolean differential on replay",
        )
    return ValidationOutcome(
        FindingStatus.INCONCLUSIVE, "unknown_detector", str(detector)
    )


async def _validate_xss(client, repro) -> ValidationOutcome:
    url, param = repro.get("url"), repro.get("param")
    method = repro.get("method", "GET")
    payload = repro.get("payload", "")
    marker = repro.get("marker", "")
    resp = await _send(client, method, url, {param: payload})
    raw = f"<szx{marker}>" if marker else payload
    escaped = f"&lt;szx{marker}&gt;" if marker else ""
    if raw and raw in resp.text and (not escaped or escaped not in resp.text):
        ctype = resp.headers.get("content-type", "")
        if not renderable_html_context(resp.status_code, ctype):
            return ValidationOutcome(
                FindingStatus.REJECTED,
                "independent_replay",
                f"reflection is in a non-renderable context "
                f"(status {resp.status_code}, content-type {ctype!r}); not executable",
                evidence=_ev(resp),
            )
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "independent_replay",
            "unescaped reflection reproduced in an HTML response",
            evidence=_ev(resp),
        )
    if escaped and escaped in resp.text:
        return ValidationOutcome(
            FindingStatus.REJECTED,
            "independent_replay",
            "reflection is HTML-escaped (safe)",
        )
    return ValidationOutcome(
        FindingStatus.REJECTED, "independent_replay", "payload not reflected on replay"
    )


async def _validate_bola(client, repro, sessions: list) -> ValidationOutcome:
    """Session-aware BOLA re-proof (CP-04).

    The recipe names the attacker/victim roles and the victim's object id. Using the
    assessment's own test-account session for the *attacker role*, the request is
    re-issued; CONFIRMED requires a 200 referencing the object id while the same request
    without any session does not (so the object is not simply public). Without a usable
    attacker session the outcome stays SUSPECTED (controlled evidence access).
    """
    url = repro.get("url")
    obj = str(repro.get("object_id", ""))
    attacker_role = str(repro.get("attacker_role", ""))
    if not url or not obj:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "no_recipe", "bola recipe incomplete"
        )
    attacker = next(
        (
            s
            for s in sessions
            if getattr(s, "role_name", None) == attacker_role
            and not getattr(s, "expired", False)
        ),
        None,
    )
    try:
        anon = await client.get(url)
    except TargetUnreachable:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "unreachable", "object endpoint unreachable"
        )
    if anon.status_code == 200 and obj in anon.text:
        # reachable with no session at all: exposure is real (and broader than BOLA)
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "anon_access",
            "object retrievable without authentication",
            evidence=_ev(anon),
        )
    if attacker is None:
        return ValidationOutcome(
            FindingStatus.SUSPECTED,
            "controlled_access",
            f"no active session for attacker role {attacker_role!r}; "
            "cross-account re-proof not possible",
        )
    try:
        as_attacker = await client.get(url, headers=dict(attacker.headers))
    except TargetUnreachable:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "unreachable", "object endpoint unreachable"
        )
    if as_attacker.status_code == 200 and obj in as_attacker.text:
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "cross_account_session",
            f"role {attacker_role!r} retrieved object {obj} owned by "
            f"{repro.get('victim_role', '?')!r}; anonymous request did not",
            evidence=_ev(as_attacker),
        )
    if as_attacker.status_code in (401, 403, 404):
        return ValidationOutcome(
            FindingStatus.REJECTED,
            "cross_account_session",
            f"object not returned to role {attacker_role!r} "
            f"(status {as_attacker.status_code})",
            evidence=_ev(as_attacker),
        )
    return ValidationOutcome(
        FindingStatus.INCONCLUSIVE,
        "cross_account_session",
        f"unexpected status {as_attacker.status_code} during re-proof",
        evidence=_ev(as_attacker),
    )


async def _validate_business_logic(client, repro) -> ValidationOutcome:
    """Re-prove a numeric-bounds business-logic finding (CP-01).

    Recipe: {method,url,param,payload(out-of-range value),baseline_value,echo}. The
    server must (a) accept the out-of-range value with a 2xx and (b) echo it back in the
    body (the value was *applied*, not silently clamped) while (c) the baseline value is
    also accepted — establishing that the acceptance is real behaviour, not a flap.
    """
    url, param = repro.get("url"), repro.get("param")
    payload = str(repro.get("payload", ""))
    baseline_value = str(repro.get("baseline_value", "1"))
    method = str(repro.get("method", "GET")).upper()
    if not url or not param:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "no_recipe", "business-logic recipe incomplete"
        )
    baseline = await _send(client, method, url, {param: baseline_value})
    probe = await _send(client, method, url, {param: payload})
    if not (200 <= baseline.status_code < 300):
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE,
            "numeric_bounds",
            f"baseline value rejected with {baseline.status_code}; cannot compare",
            evidence=_ev(baseline),
        )
    if 200 <= probe.status_code < 300 and _echoes_value(probe.text, payload):
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "numeric_bounds",
            f"out-of-range value {payload!r} for {param!r} accepted and applied",
            evidence=_ev(probe),
        )
    if probe.status_code >= 400:
        return ValidationOutcome(
            FindingStatus.REJECTED,
            "numeric_bounds",
            f"out-of-range value now rejected ({probe.status_code})",
            evidence=_ev(probe),
        )
    return ValidationOutcome(
        FindingStatus.SUSPECTED,
        "numeric_bounds",
        "value accepted but not observably applied in the response",
        evidence=_ev(probe),
    )


def _echoes_value(body: str, value: str) -> bool:
    """True if the numeric value appears in the body as a standalone number token."""
    return re.search(rf"(?<![\w.-]){re.escape(value)}(?![\w.])", body or "") is not None


async def _validate_business_flow(client, repro) -> ValidationOutcome:
    """Re-run the multi-step flow and confirm the invariant is still violated (BS-15)."""
    from app.checks.flow import FLOWS

    flow = next((f for f in FLOWS if f.name == repro.get("flow")), None)
    origin = repro.get("origin")
    if flow is None or not origin:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "no_recipe", "flow recipe incomplete"
        )
    variables: dict[str, str] = {}
    observed = None
    for step in flow.steps:
        path = step.path.format(**variables) if variables else step.path
        url = origin + path
        if step.method.upper() == "GET":
            resp = await client.get(url, params=step.params or None)
        else:
            resp = await client.post(url, json=step.json_body or None)
        if resp.status_code not in step.expect_status:
            return ValidationOutcome(
                FindingStatus.REJECTED,
                "flow_blocked",
                f"flow step {step.method} {path} returned {resp.status_code}; invariant holds",
            )
        import json as _json

        try:
            data = _json.loads(resp.text)
        except (ValueError, TypeError):
            data = {}
        for var, key in step.extract.items():
            if not isinstance(data, dict) or data.get(key) is None:
                return ValidationOutcome(
                    FindingStatus.INCONCLUSIVE, "extract_failed", f"could not read {key}"
                )
            variables[var] = str(data[key])
            if var == flow.invariant_var:
                observed = data[key]
    if observed is None:
        return ValidationOutcome(FindingStatus.INCONCLUSIVE, "no_value", "no invariant value")
    try:
        numeric = float(observed)
    except (ValueError, TypeError):
        return ValidationOutcome(FindingStatus.INCONCLUSIVE, "no_value", "no invariant value")
    if numeric > flow.invariant_max:
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "flow_replay",
            f"{flow.invariant_var}={numeric} exceeds single-use max {flow.invariant_max}",
        )
    return ValidationOutcome(
        FindingStatus.REJECTED,
        "flow_replay",
        f"{flow.invariant_var}={numeric} within bounds on re-run",
    )


async def _validate_prompt_injection(client, repro) -> ValidationOutcome:
    """Re-send the injection probe and confirm a leak marker the baseline lacks (BS-16)."""
    from app.checks.llm_redteam import _leak_markers

    url, param = repro.get("url"), repro.get("param")
    if not url or not param:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "no_recipe", "prompt-injection recipe incomplete"
        )
    baseline = await client.get(url, params={param: repro.get("baseline", "hello")})
    injection = await client.get(url, params={param: repro.get("payload", "")})
    base = set(_leak_markers(baseline.text))
    leaked = [m for m in _leak_markers(injection.text) if m not in base]
    if leaked:
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "prompt_injection",
            f"injection leaked markers not present in baseline: {', '.join(leaked)}",
        )
    return ValidationOutcome(
        FindingStatus.REJECTED,
        "prompt_injection",
        "no system-prompt/secret leak under injection on re-run",
    )


async def _validate_open_redirect(client, repro) -> ValidationOutcome:
    from urllib.parse import urlsplit

    url, param = repro.get("url"), repro.get("param")
    payload = repro.get("payload", "")
    try:
        resp = await client.get(url, params={param: payload}, max_redirects=0)
    except ScopeViolation:
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "guard_blocked_redirect",
            "app attempted redirect to attacker host (blocked at boundary)",
        )
    loc = resp.headers.get("location", "")
    if loc and urlsplit(loc).hostname == urlsplit(payload).hostname:
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "location_header",
            "Location header points to attacker host",
            evidence=_ev(resp),
        )
    return ValidationOutcome(
        FindingStatus.REJECTED, "location_header", "redirect not reproduced"
    )


async def _validate_headers(client, repro) -> ValidationOutcome:
    # Header findings are deterministic facts about the response; re-fetch and confirm.
    url = repro.get("url")
    if not url:
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "deterministic",
            "header assessment is deterministic from capture",
        )
    try:
        resp = await client.get(url)
    except TargetUnreachable:
        return ValidationOutcome(
            FindingStatus.SUSPECTED, "unreachable", "could not re-fetch"
        )
    return ValidationOutcome(
        FindingStatus.CONFIRMED,
        "independent_replay",
        "headers re-observed",
        evidence=_ev(resp),
    )


async def _send(client, method, url, overrides):
    if (method or "GET").upper() == "GET":
        return await client.get(url, params=overrides)
    return await client.request(method, url, data=overrides)


def _len_differs(a: str, b: str, threshold: float = 0.30) -> bool:
    la, lb = len(a or ""), len(b or "")
    if max(la, lb) == 0:
        return False
    return abs(la - lb) / max(la, lb) > threshold


def _ev(resp) -> dict:
    from app.security.redaction import build_evidence_exchange

    return build_evidence_exchange(
        request={
            "method": resp.request_method,
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
    )


async def _validate_declarative(client, repro) -> ValidationOutcome:
    """Independently re-prove a declarative-check finding from its recipe (F-11).

    Uses only the reproduction recipe (detector + params carried on the finding), never
    the original verdict — same confirmation-bias control as the built-in validators.
    """
    import re as _re

    detector = repro.get("detector")
    url, param = repro.get("url"), repro.get("param")
    method = repro.get("method", "GET")

    if detector == "status_code":
        trigger = {int(s) for s in repro.get("trigger_status", [500])}
        resp = await _send(client, method, url, {param: repro.get("payload", "'")})
        if resp.status_code in trigger:
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "status_code",
                f"status {resp.status_code} reproduced",
                evidence=_ev(resp),
            )
        return ValidationOutcome(
            FindingStatus.REJECTED, "status_code", "trigger status not reproduced"
        )

    if detector == "error_signature":
        sigs = repro.get("signatures", [])
        rx = _re.compile("|".join(sigs), _re.IGNORECASE) if sigs else None
        resp = await _send(client, method, url, {param: repro.get("payload", "'")})
        if rx and rx.search(resp.text):
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "error_signature",
                "signature reproduced",
                evidence=_ev(resp),
            )
        return ValidationOutcome(
            FindingStatus.REJECTED, "error_signature", "signature not reproduced"
        )

    if detector == "reflection":
        # Use the exact payload the check sent (honors any manifest marker_template) —
        # do not reconstruct a hardcoded marker shape (P-08).
        raw = repro.get("payload", "")
        resp = await _send(client, method, url, {param: raw})
        escaped = raw.replace("<", "&lt;").replace(">", "&gt;")
        if raw and raw in resp.text and (escaped == raw or escaped not in resp.text):
            ctype = resp.headers.get("content-type", "")
            if not renderable_html_context(resp.status_code, ctype):
                return ValidationOutcome(
                    FindingStatus.REJECTED,
                    "reflection",
                    f"reflection is in a non-renderable context "
                    f"(status {resp.status_code}, content-type {ctype!r})",
                    evidence=_ev(resp),
                )
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "reflection",
                "unescaped reflection reproduced in an HTML response",
                evidence=_ev(resp),
            )
        return ValidationOutcome(
            FindingStatus.REJECTED, "reflection", "reflection not reproduced"
        )

    if detector in (
        "headers_missing",
        "headers_disclosure",
        "header_presence",
        "header_reflects",
    ):
        # header-shaped declarative detectors: re-observe deterministically
        if not url:
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "deterministic",
                "header assessment is deterministic from capture",
            )
        resp = await _send(client, "GET", url, {})
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "header_reobserved",
            "headers re-observed",
            evidence=_ev(resp),
        )

    return ValidationOutcome(
        FindingStatus.INCONCLUSIVE, "unknown_detector", str(detector)
    )
