"""SIEM / Microsoft-ecosystem export (BS-13).

Provider-agnostic export of confirmed findings as security events a SIEM can ingest:

* **ECS JSON-lines** — Elastic Common Schema, the shape Microsoft Sentinel and Elastic
  both accept for custom events (one JSON object per line).
* **CEF** — ArcSight Common Event Format, understood by most legacy SIEMs.

Sinks are pluggable behind ``SiemSink``: ``FileSiemSink`` writes to the configured object
store; ``WebhookSiemSink`` POSTs to an HTTP collector through the SSRF-guarded fetch path.
Nothing here calls a paid or external service by default — the default sink returns the
serialized events to the caller.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime

_SEVERITY_TO_NUM = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}


@dataclass
class SecurityEvent:
    event_id: str
    assessment_id: str
    org_id: str
    check_class: str
    title: str
    severity: str
    status: str
    cwe: str
    endpoint_url: str
    skill_ref: str
    detected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_ecs(self) -> dict:
        """Elastic Common Schema document (Sentinel/Elastic-ingestible)."""
        return {
            "@timestamp": self.detected_at,
            "event": {
                "kind": "alert",
                "category": ["vulnerability"],
                "type": ["info"],
                "id": self.event_id,
                "severity": _SEVERITY_TO_NUM.get(self.severity, 1),
                "provider": "sentrik",
                "dataset": "sentrik.finding",
            },
            "vulnerability": {
                "category": [self.check_class],
                "classification": self.cwe,
                "severity": self.severity,
                "description": self.title,
                "scanner": {"vendor": "Sentrik"},
            },
            "url": {"full": self.endpoint_url},
            "organization": {"id": self.org_id},
            "sentrik": {
                "assessment_id": self.assessment_id,
                "status": self.status,
                "skill_ref": self.skill_ref,
            },
        }

    def to_cef(self) -> str:
        """ArcSight CEF line."""
        num = _SEVERITY_TO_NUM.get(self.severity, 1)
        ext = (
            f"cs1Label=assessmentId cs1={self.assessment_id} "
            f"cs2Label=cwe cs2={self.cwe} "
            f"cs3Label=skillRef cs3={self.skill_ref} "
            f"request={self.endpoint_url} "
            f"outcome={self.status} rt={self.detected_at}"
        )
        name = self.title.replace("|", "\\|").replace("=", "\\=")
        return (
            f"CEF:0|Sentrik|Sentrik|1.0|{self.check_class}|{name}|{num}|{ext}".strip()
        )


def findings_to_events(assessment_id: str, org_id: str, findings: list[dict]) -> list[SecurityEvent]:
    return [
        SecurityEvent(
            event_id=f["id"],
            assessment_id=assessment_id,
            org_id=org_id,
            check_class=f.get("check_class", ""),
            title=f.get("title", ""),
            severity=f.get("severity", "info"),
            status=f.get("status", ""),
            cwe=f.get("cwe", ""),
            endpoint_url=(f.get("reproduction") or {}).get("url", ""),
            skill_ref=f.get("skill_ref", ""),
        )
        for f in findings
    ]


def serialize(events: list[SecurityEvent], fmt: str) -> tuple[str, str]:
    """Return (payload_text, content_type) for the requested format."""
    if fmt == "cef":
        return "\n".join(e.to_cef() for e in events) + ("\n" if events else ""), "text/plain"
    # default: ECS JSON-lines
    return (
        "\n".join(json.dumps(e.to_ecs(), default=str) for e in events)
        + ("\n" if events else ""),
        "application/x-ndjson",
    )


class SiemSink(ABC):
    @abstractmethod
    async def emit(self, payload: str, content_type: str, *, key: str) -> dict: ...


class ResponseSiemSink(SiemSink):
    """Default: no external call; the caller receives the serialized events inline."""

    async def emit(self, payload: str, content_type: str, *, key: str) -> dict:
        return {"sink": "response", "bytes": len(payload.encode())}


class FileSiemSink(SiemSink):
    """Persist to the configured object store (db/local/s3)."""

    async def emit(self, payload: str, content_type: str, *, key: str) -> dict:
        from app.services.storage import get_storage

        ref = await get_storage().put(key, payload.encode(), content_type=content_type)
        return {"sink": "file", "ref": ref}


class WebhookSiemSink(SiemSink):
    """POST to an HTTP collector, refusing SSRF-prone destinations."""

    def __init__(self, url: str):
        self.url = url

    async def emit(self, payload: str, content_type: str, *, key: str) -> dict:
        import httpx

        from app.security.netguard import NetGuardError, parse_url, resolve_host

        try:
            _scheme, host, port, _path = parse_url(self.url)
            info = resolve_host(host, port, allow_dns=True)
        except NetGuardError as exc:
            raise ValueError(f"unsafe SIEM webhook URL: {exc}") from exc
        if info.is_hard_blocked or info.is_private or info.is_loopback:
            raise ValueError("SIEM webhook destination is private/loopback/metadata (refused)")
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self.url, content=payload.encode(), headers={"content-type": content_type}
            )
        return {"sink": "webhook", "status": resp.status_code}
