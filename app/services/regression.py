"""Convert confirmed findings into replayable regression tests, and execute them.

A regression test captures the minimal reproduction (method/url/param/payload/detector)
plus an assertion that the vulnerability is *absent*. Re-running it after a fix yields
FIXED (assertion holds → vuln gone) or REGRESSED/STILL_VULNERABLE. This mirrors the
"convert findings into CI/CD regression tests" capability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.checks.sqli import DB_ERROR_SIGNATURES
from app.security.http_client import GuardedHttpClient, TargetUnreachable
from app.security.scope import ScopeViolation

_ERROR_RE = re.compile("|".join(DB_ERROR_SIGNATURES), re.IGNORECASE)


def build_regression_definition(
    check_class: str, reproduction: dict, title: str
) -> dict:
    """Serializable regression test definition derived from a confirmed finding."""
    return {
        "check_class": check_class,
        "title": f"Regression: {title}",
        "reproduction": reproduction,
        "assertion": _assertion_for(check_class),
        "version": "1.0",
    }


def _assertion_for(check_class: str) -> str:
    return {
        "sqli": "no DB error signature and no boolean differential",
        "xss": "payload is not reflected unescaped",
        "open_redirect": "no redirect to attacker-controlled host",
        "bola": "cross-account object access is denied",
        "security_headers": "required security headers present",
        "info_disclosure": "no version disclosure headers",
    }.get(check_class, "vulnerability no longer reproduces")


@dataclass
class RegressionResult:
    status: str  # "fixed" | "still_vulnerable" | "inconclusive"
    detail: str
    evidence: dict | None = None


async def run_regression(
    client: GuardedHttpClient, definition: dict
) -> RegressionResult:
    """Execute a regression test. 'fixed' means the vuln no longer reproduces."""
    check_class = definition.get("check_class")
    repro = definition.get("reproduction", {})
    try:
        if check_class == "sqli":
            return await _regress_sqli(client, repro)
        if check_class == "xss":
            return await _regress_xss(client, repro)
        if check_class == "open_redirect":
            return await _regress_open_redirect(client, repro)
        if check_class in ("security_headers", "info_disclosure"):
            return await _regress_headers(client, repro)
        if check_class == "bola":
            return RegressionResult(
                "inconclusive", "BOLA regression requires session context"
            )
        return RegressionResult(
            "inconclusive", f"no regression runner for {check_class}"
        )
    except ScopeViolation as exc:
        return RegressionResult("inconclusive", f"blocked by scope: {exc.reason}")
    except TargetUnreachable as exc:
        return RegressionResult("inconclusive", f"unreachable: {exc}")


async def _regress_sqli(client, repro) -> RegressionResult:
    url, param = repro.get("url"), repro.get("param")
    method = repro.get("method", "GET")
    if repro.get("detector") == "db_error_signature":
        resp = await _send(client, method, url, {param: repro.get("payload", "'")})
        if _ERROR_RE.search(resp.text):
            return RegressionResult(
                "still_vulnerable", "DB error still reproduces", _ev(resp)
            )
        return RegressionResult(
            "fixed", "no DB error signature; injection appears remediated", _ev(resp)
        )
    # boolean
    baseline = await _send(client, method, url, {param: "1"})
    r_true = await _send(client, method, url, {param: repro.get("true_payload")})
    r_false = await _send(client, method, url, {param: repro.get("false_payload")})
    differs = (r_true.status_code != r_false.status_code) or _len_differs(
        r_true.text, r_false.text
    )
    if differs and not _len_differs(r_true.text, baseline.text, 0.15):
        return RegressionResult(
            "still_vulnerable", "boolean differential still present", _ev(r_true)
        )
    return RegressionResult("fixed", "boolean differential gone", _ev(r_true))


async def _regress_xss(client, repro) -> RegressionResult:
    url, param = repro.get("url"), repro.get("param")
    method = repro.get("method", "GET")
    marker = repro.get("marker", "")
    resp = await _send(client, method, url, {param: repro.get("payload", "")})
    raw = f"<szx{marker}>" if marker else repro.get("payload", "")
    escaped = f"&lt;szx{marker}&gt;" if marker else ""
    if raw and raw in resp.text and (not escaped or escaped not in resp.text):
        return RegressionResult(
            "still_vulnerable", "payload still reflected unescaped", _ev(resp)
        )
    return RegressionResult("fixed", "payload no longer reflected unescaped", _ev(resp))


async def _regress_open_redirect(client, repro) -> RegressionResult:
    from urllib.parse import urlsplit

    url, param = repro.get("url"), repro.get("param")
    payload = repro.get("payload", "")
    try:
        resp = await client.get(url, params={param: payload}, max_redirects=0)
    except ScopeViolation:
        return RegressionResult(
            "still_vulnerable", "app still redirects to attacker host"
        )
    loc = resp.headers.get("location", "")
    if loc and urlsplit(loc).hostname == urlsplit(payload).hostname:
        return RegressionResult(
            "still_vulnerable", "still redirects to attacker host", _ev(resp)
        )
    return RegressionResult("fixed", "redirect no longer honored", _ev(resp))


async def _regress_headers(client, repro) -> RegressionResult:
    url = repro.get("url")
    if not url:
        return RegressionResult("inconclusive", "no url in recipe")
    resp = await client.get(url)
    return RegressionResult("inconclusive", "re-observe headers manually", _ev(resp))


async def _send(client, method, url, overrides):
    if (method or "GET").upper() == "GET":
        return await client.get(url, params=overrides)
    return await client.request(method, url, data=overrides)


def _len_differs(a, b, threshold=0.30) -> bool:
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
