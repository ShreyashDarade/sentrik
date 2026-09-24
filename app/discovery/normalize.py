"""Normalized endpoint representation, fingerprinting, and provenance-aware merge."""

from __future__ import annotations

import hashlib
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
