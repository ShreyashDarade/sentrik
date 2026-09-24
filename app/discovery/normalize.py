"""Normalized endpoint representation, fingerprinting, and provenance-aware merge."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.core.enums import Provenance

# Confidence per provenance: explicit specs are trustworthy; crawl inference less so.
PROVENANCE_CONFIDENCE = {
    Provenance.OPENAPI: 0.95,
    Provenance.GRAPHQL: 0.9,
    Provenance.POSTMAN: 0.85,
    Provenance.HAR: 0.8,
    Provenance.TRAFFIC: 0.75,
    Provenance.CRAWL: 0.55,
    Provenance.MANUAL: 0.7,
}

# Path segments that look like identifiers → templatized for dedup/fingerprint.
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-f-]{16,})$")


def templatize_path(path: str) -> str:
    """Replace id-like segments with {id} so /users/1 and /users/2 fingerprint equally."""
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
        elif _ID_SEGMENT.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


@dataclass
class DiscoveredEndpoint:
    method: str
    url: str
    provenance: Provenance
    path_template: str = ""
    parameters: list[dict] = field(default_factory=list)  # {name,in,type,required}
    request_body_schema: dict = field(default_factory=dict)
    auth_required: bool = False
    roles: list[str] = field(default_factory=list)
    api_version: str = ""
    confidence: float = 0.5

    def __post_init__(self):
        self.method = (self.method or "GET").upper()
        if not self.path_template:
            self.path_template = templatize_path(urlsplit(self.url).path or "/")
        if not self.api_version:
            self.api_version = _infer_version(urlsplit(self.url).path or "")
        if self.confidence == 0.5:
            self.confidence = PROVENANCE_CONFIDENCE.get(self.provenance, 0.5)

    @property
    def fingerprint(self) -> str:
        return endpoint_fingerprint(self.method, self.url, self.path_template)


def _infer_version(path: str) -> str:
    m = re.search(r"/(v\d+(?:\.\d+)?)(?:/|$)", path)
    return m.group(1) if m else ""


def endpoint_fingerprint(method: str, url: str, path_template: str = "") -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    tmpl = path_template or templatize_path(parts.path or "/")
    key = f"{method.upper()} {host}:{port}{tmpl}"
    return hashlib.sha1(key.encode()).hexdigest()


def endpoint_surface_signature(
    method: str,
    url: str,
    path_template: str = "",
    *,
    parameters: list[dict] | None = None,
    auth_required: bool = False,
    roles: list[str] | None = None,
    request_body_schema: dict | None = None,
    api_version: str = "",
) -> str:
    """A change-sensitive signature of an endpoint's *testable surface* (F-14).

    The plain :func:`endpoint_fingerprint` only identifies location (method + host + path
    template), so a retest driven purely by fingerprint would skip an endpoint whose
    parameters, authentication, roles, request body, or API version changed since the last
    assessment — exactly the surface a regression retest must re-cover. This signature adds
    those dimensions so an incremental scan re-tests changed endpoints, not just new ones.
    """
    params = sorted(
        f"{(p.get('name') or '').lower()}:{(p.get('in') or 'query').lower()}"
        for p in (parameters or [])
        if p.get("name")
    )
    body_keys = sorted((request_body_schema or {}).keys())
    payload = {
        "fp": endpoint_fingerprint(method, url, path_template),
        "params": params,
        "auth": bool(auth_required),
        "roles": sorted(r for r in (roles or []) if r),
        "body": body_keys,
        "api_version": api_version or "",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(canonical.encode()).hexdigest()


def merge_endpoints(endpoints: list[DiscoveredEndpoint]) -> list[DiscoveredEndpoint]:
    """Deduplicate by fingerprint, keeping the highest-confidence provenance and
    unioning parameters. Consolidates duplicates while preserving distinct params."""
    by_fp: dict[str, DiscoveredEndpoint] = {}
    for ep in endpoints:
        fp = ep.fingerprint
        existing = by_fp.get(fp)
        if existing is None:
            by_fp[fp] = ep
            continue
        # merge: keep higher confidence base, union params by name+in
        base = existing if existing.confidence >= ep.confidence else ep
        other = ep if base is existing else existing
        merged_params = {
            (_p["name"], _p.get("in", "query")): _p for _p in base.parameters
        }
        for p in other.parameters:
            merged_params.setdefault((p["name"], p.get("in", "query")), p)
        base.parameters = list(merged_params.values())
        base.auth_required = base.auth_required or other.auth_required
        base.roles = sorted(set(base.roles) | set(other.roles))
        if not base.request_body_schema and other.request_body_schema:
            base.request_body_schema = other.request_body_schema
        by_fp[fp] = base
    return list(by_fp.values())
