"""Remediation guidance generation.

Maps a finding's check class + specifics to actionable, prioritized remediation
guidance with references. Deterministic knowledge base; an LLM brain can enrich the
`context_note` but the core guidance is always available offline.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import CheckClass

_KB = {
    CheckClass.SQLI.value: {
        "summary": "Use parameterized queries / prepared statements everywhere.",
        "steps": [
            "Replace string-concatenated SQL with parameter binding (e.g. psycopg, SQLAlchemy).",
            "Validate and canonicalize input types (ints as ints).",
            "Apply least-privilege database accounts; disable stacked queries.",
            "Add a WAF rule as defense-in-depth, not as the primary fix.",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "cwe": "CWE-89",
    },
    CheckClass.XSS.value: {
        "summary": "Context-encode output and deploy a strict Content-Security-Policy.",
        "steps": [
            "HTML-entity-encode user data on output; use framework auto-escaping.",
            "Set a strict CSP (no unsafe-inline).",
            "Sanitize rich HTML with an allowlist library.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
        "cwe": "CWE-79",
    },
    CheckClass.BOLA.value: {
        "summary": "Enforce per-object ownership checks server-side on every request.",
        "steps": [
            "Resolve the authenticated principal and verify it owns/may access the object.",
            "Centralize authorization (policy layer) rather than per-controller checks.",
            "Do not rely on unguessable identifiers as an access control.",
        ],
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
        ],
        "cwe": "CWE-639",
    },
    CheckClass.OPEN_REDIRECT.value: {
        "summary": "Validate redirect targets against an allowlist.",
        "steps": [
            "Reject absolute external URLs in redirect parameters.",
            "Map redirect intents to server-side identifiers.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
        ],
        "cwe": "CWE-601",
    },
    CheckClass.SECURITY_HEADERS.value: {
        "summary": "Add the missing security headers at the app or proxy layer.",
        "steps": [
            "Set Content-Security-Policy, X-Content-Type-Options, X-Frame-Options.",
            "Enable HSTS on HTTPS with a long max-age once verified.",
        ],
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "cwe": "CWE-693",
    },
    CheckClass.INFO_DISCLOSURE.value: {
        "summary": "Suppress technology/version disclosure headers.",
        "steps": ["Remove or genericize Server / X-Powered-By headers."],
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "cwe": "CWE-200",
    },
}

_PRIORITY_BY_SEVERITY = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
    "info": "P4",
}


@dataclass
class Remediation:
    summary: str
    steps: list[str]
    references: list[str]
    priority: str
    effort: str
    context_note: str = ""


def build_remediation(
    check_class: str, severity: str, context_note: str = ""
) -> Remediation:
    kb = _KB.get(
        check_class,
        {
            "summary": "Review and remediate the identified weakness following secure-coding guidance.",
            "steps": [
                "Investigate the affected code path.",
                "Apply input validation / output encoding / access control as appropriate.",
            ],
            "references": ["https://owasp.org/www-project-top-ten/"],
        },
    )
    effort = {
        "sqli": "medium",
        "bola": "high",
        "xss": "low",
        "open_redirect": "low",
    }.get(check_class, "low")
    return Remediation(
        summary=kb["summary"],
        steps=list(kb["steps"]),
        references=list(kb["references"]),
        priority=_PRIORITY_BY_SEVERITY.get(severity, "P3"),
        effort=effort,
        context_note=context_note,
    )
