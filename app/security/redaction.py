"""Redaction utilities for evidence and logs.

Untrusted target responses and our own requests may carry secrets (auth tokens,
cookies, PII). We redact before persisting evidence or emitting logs. Redaction is
conservative and reversible only in that the *shape* is preserved for reproduction.
"""

from __future__ import annotations

import re

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "x-auth-token",
    "x-csrf-token",
    "x-session-token",
}
SENSITIVE_PARAM_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "session",
    "ssn",
    "credit",
    "card",
)

_PATTERNS = [
    (re.compile(r"\b\d{13,19}\b"), "[REDACTED_PAN]"),  # card-ish numbers
    (
        re.compile(r"\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"sk_[a-f0-9]{8}_[A-Za-z0-9_-]{20,}"), "[REDACTED_APIKEY]"),
]

MAX_BODY_CHARS = 8192


def redact_headers(headers: dict | None) -> dict:
    if not headers:
        return {}
    out = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = "[REDACTED]"
        else:
            out[k] = redact_text(str(v))
    return out


def redact_text(text: str | None) -> str:
    if not text:
        return ""
    red = text
    for pattern, repl in _PATTERNS:
        red = pattern.sub(repl, red)
    return red


def redact_params(params: dict | list | None) -> dict | list:
    if params is None:
        return {}
    if isinstance(params, dict):
        return {
            k: (
                "[REDACTED]"
                if any(h in k.lower() for h in SENSITIVE_PARAM_HINTS)
                else redact_text(str(v))
            )
            for k, v in params.items()
        }
    if isinstance(params, list):
        return [
            redact_params(p) if isinstance(p, (dict, list)) else redact_text(str(p))
            for p in params
        ]
    return {}


def truncate_body(body: str | bytes | None) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:
            body = repr(body)
    body = redact_text(body)
    if len(body) > MAX_BODY_CHARS:
        return (
            body[:MAX_BODY_CHARS]
            + f"\n...[truncated {len(body) - MAX_BODY_CHARS} chars]"
        )
    return body


def build_evidence_exchange(*, request: dict, response: dict) -> dict:
    """Normalize a request/response pair into a redacted evidence exchange."""
    return {
        "request": {
            "method": request.get("method", ""),
            "url": request.get("url", ""),
            "headers": redact_headers(request.get("headers")),
            "body": truncate_body(request.get("body")),
        },
        "response": {
            "status": response.get("status"),
            "headers": redact_headers(response.get("headers")),
            "body": truncate_body(response.get("body")),
            "elapsed_ms": response.get("elapsed_ms"),
        },
    }
