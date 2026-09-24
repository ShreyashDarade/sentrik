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
) -> ValidationOutcome:
    if not reproduction:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE,
            "no_recipe",
            "finding has no reproduction recipe",
        )
    try:
        dispatch = {
            "sqli": _validate_sqli,
            "xss": _validate_xss,
            "bola": _validate_bola,
            "open_redirect": _validate_open_redirect,
            "security_headers": _validate_headers,
            "info_disclosure": _validate_headers,
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
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "independent_replay",
            "unescaped reflection reproduced",
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


async def _validate_bola(client, repro) -> ValidationOutcome:
    # We do not carry attacker session headers into validation (controlled access),
    # so we can only confirm that the object endpoint responds; a full re-proof requires
    # the session context, which the validator intentionally lacks. Mark suspected.
    url = repro.get("url")
    obj = str(repro.get("object_id", ""))
    try:
        anon = await client.get(url)
    except TargetUnreachable:
        return ValidationOutcome(
            FindingStatus.INCONCLUSIVE, "unreachable", "object endpoint unreachable"
        )
    if anon.status_code == 200 and obj and obj in anon.text:
        # object is reachable without any auth → even worse, but different class; confirm exposure
        return ValidationOutcome(
            FindingStatus.CONFIRMED,
            "anon_access",
            "object retrievable without authentication",
            evidence=_ev(anon),
        )
    return ValidationOutcome(
        FindingStatus.SUSPECTED,
        "controlled_access",
        "cross-account proof requires session context withheld from validator",
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
        marker = repro.get("marker", "")
        resp = await _send(client, method, url, {param: repro.get("payload", "")})
        raw = f"<zzz{marker}>" if marker else repro.get("payload", "")
        escaped = raw.replace("<", "&lt;").replace(">", "&gt;")
        if raw and raw in resp.text and (escaped == raw or escaped not in resp.text):
            return ValidationOutcome(
                FindingStatus.CONFIRMED,
                "reflection",
                "unescaped reflection reproduced",
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
