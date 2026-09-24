"""Artifact parsers: OpenAPI (2.0/3.x), HAR, Postman v2.1, GraphQL introspection.

All parsers are defensive: malformed artifacts yield partial results plus a list of
warnings rather than raising, because uploaded artifacts are untrusted input.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from app.core.enums import Provenance
from app.discovery.normalize import DiscoveredEndpoint

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


@dataclass
class ParseResult:
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def extend(self, other: "ParseResult") -> None:
        self.endpoints.extend(other.endpoints)
        self.warnings.extend(other.warnings)


def _load(content: str | dict) -> tuple[dict | list | None, str | None]:
    if isinstance(content, (dict, list)):
        return content, None
    text = content.strip()
    if not text:
        return None, "empty artifact"
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        pass
    try:
        import yaml

        return yaml.safe_load(text), None
    except Exception as exc:  # noqa: BLE001
        return None, f"could not parse as JSON or YAML: {exc}"


# --------------------------------------------------------------------------- #
# OpenAPI / Swagger
# --------------------------------------------------------------------------- #
def parse_openapi(content: str | dict, *, base_url: str = "") -> ParseResult:
    res = ParseResult()
    doc, err = _load(content)
    if err or not isinstance(doc, dict):
        res.warnings.append(err or "OpenAPI root is not an object")
        return res

    servers = _openapi_servers(doc, base_url)
    version = _openapi_version_tag(doc)
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        res.warnings.append("no 'paths' object found")
        return res

    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            res.warnings.append(f"path {raw_path!r} is not an object; skipped")
            continue
        shared_params = (
            item.get("parameters", [])
            if isinstance(item.get("parameters"), list)
            else []
        )
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params = _collect_openapi_params(shared_params + op.get("parameters", []))
            body = _openapi_request_body(op, doc)
            auth_required = bool(op.get("security", doc.get("security")))
            roles = _openapi_scopes(op)
            for server in servers:
                url = urljoin(server.rstrip("/") + "/", raw_path.lstrip("/"))
                res.endpoints.append(
                    DiscoveredEndpoint(
                        method=method,
                        url=url,
                        provenance=Provenance.OPENAPI,
                        parameters=params,
                        request_body_schema=body,
                        auth_required=auth_required,
                        roles=roles,
                        api_version=version,
                    )
                )
    return res


def _openapi_servers(doc: dict, base_url: str) -> list[str]:
    servers = []
    if isinstance(doc.get("servers"), list):
        for s in doc["servers"]:
            if isinstance(s, dict) and s.get("url"):
                u = s["url"]
                if u.startswith("/") and base_url:
                    u = base_url.rstrip("/") + u
                servers.append(u)
    if not servers:  # swagger 2.0
        host = doc.get("host")
        if host:
            scheme = (doc.get("schemes") or ["https"])[0]
            servers.append(f"{scheme}://{host}{doc.get('basePath', '')}")
    if not servers:
        servers = [base_url or "http://localhost"]
    return servers


def _openapi_version_tag(doc: dict) -> str:
    info = doc.get("info", {})
    if isinstance(info, dict) and info.get("version"):
        return str(info["version"])
    return ""


def _collect_openapi_params(raw_params) -> list[dict]:
    out = []
    for p in raw_params or []:
        if not isinstance(p, dict):
            continue
        schema = p.get("schema", {}) if isinstance(p.get("schema"), dict) else {}
        out.append(
            {
                "name": p.get("name", ""),
                "in": p.get("in", "query"),
                "type": schema.get("type") or p.get("type") or "string",
                "required": bool(p.get("required", False)),
            }
        )
    return [p for p in out if p["name"]]


def _openapi_request_body(op: dict, doc: dict) -> dict:
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        content = rb.get("content", {})
        for ctype, media in content.items():
            if isinstance(media, dict) and "schema" in media:
                return {"content_type": ctype, "schema": media["schema"]}
    return {}


def _openapi_scopes(op: dict) -> list[str]:
    roles = []
    for sec in op.get("security", []) or []:
        if isinstance(sec, dict):
            for scopes in sec.values():
                if isinstance(scopes, list):
                    roles.extend(str(s) for s in scopes)
    return sorted(set(roles))


# --------------------------------------------------------------------------- #
# HAR
# --------------------------------------------------------------------------- #
def parse_har(
    content: str | dict, *, in_scope_hosts: set[str] | None = None
) -> ParseResult:
    res = ParseResult()
    doc, err = _load(content)
    if err or not isinstance(doc, dict):
        res.warnings.append(err or "HAR root is not an object")
        return res
    entries = (
        doc.get("log", {}).get("entries") if isinstance(doc.get("log"), dict) else None
    )
    if not isinstance(entries, list):
        res.warnings.append("HAR has no log.entries array")
        return res

    for entry in entries:
        try:
            req = entry.get("request", {})
            url = req.get("url", "")
            method = req.get("method", "GET")
            if not url:
                continue
            host = (urlsplit(url).hostname or "").lower()
            if in_scope_hosts and host not in in_scope_hosts:
                continue  # only ingest traffic to in-scope hosts
            params = [
                {
                    "name": q.get("name", ""),
                    "in": "query",
                    "type": "string",
                    "required": False,
                }
                for q in req.get("queryString", [])
                if q.get("name")
            ]
            body = {}
            post = req.get("postData")
            if isinstance(post, dict):
                for p in post.get("params", []) or []:
                    if p.get("name"):
                        params.append(
                            {
                                "name": p["name"],
                                "in": "body",
                                "type": "string",
                                "required": False,
                            }
                        )
                if post.get("mimeType"):
                    body = {"content_type": post.get("mimeType")}
            auth = any(
                h.get("name", "").lower() in ("authorization", "cookie")
                for h in req.get("headers", [])
            )
            res.endpoints.append(
                DiscoveredEndpoint(
                    method=method,
                    url=url,
                    provenance=Provenance.HAR,
                    parameters=params,
                    request_body_schema=body,
                    auth_required=auth,
                )
            )
        except Exception as exc:  # noqa: BLE001
            res.warnings.append(f"skipped malformed HAR entry: {exc}")
    return res


# --------------------------------------------------------------------------- #
# Postman collection v2.1
# --------------------------------------------------------------------------- #
def parse_postman(content: str | dict) -> ParseResult:
    res = ParseResult()
    doc, err = _load(content)
    if err or not isinstance(doc, dict):
        res.warnings.append(err or "Postman root is not an object")
        return res

    variables = {
        v.get("key"): v.get("value")
        for v in doc.get("variable", [])
        if isinstance(v, dict)
    }

    def resolve(s: str) -> str:
        if not isinstance(s, str):
            return s
        for k, v in variables.items():
            if k and v is not None:
                s = s.replace("{{" + str(k) + "}}", str(v))
        return s

    def walk(items):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if "item" in it:  # folder
                walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = req.get("method", "GET")
            url = req.get("url")
            raw = url.get("raw") if isinstance(url, dict) else url
            raw = resolve(raw or "")
            if not raw:
                continue
            params = []
            if isinstance(url, dict):
                for q in url.get("query", []) or []:
                    if isinstance(q, dict) and q.get("key"):
                        params.append(
                            {
                                "name": q["key"],
                                "in": "query",
                                "type": "string",
                                "required": False,
                            }
                        )
            auth = bool(req.get("auth")) or any(
                h.get("key", "").lower() == "authorization"
                for h in req.get("header", [])
                if isinstance(h, dict)
            )
            body = {}
            if isinstance(req.get("body"), dict) and req["body"].get("mode"):
                body = {"content_type": req["body"]["mode"]}
            res.endpoints.append(
                DiscoveredEndpoint(
                    method=method,
                    url=raw,
                    provenance=Provenance.POSTMAN,
                    parameters=params,
                    request_body_schema=body,
                    auth_required=auth,
                )
            )

    walk(doc.get("item", []))
    if not res.endpoints:
        res.warnings.append("no requests found in Postman collection")
    return res


# --------------------------------------------------------------------------- #
# GraphQL introspection
# --------------------------------------------------------------------------- #
def parse_graphql_introspection(
    content: str | dict, *, endpoint_url: str
) -> ParseResult:
    res = ParseResult()
    doc, err = _load(content)
    if err or not isinstance(doc, dict):
        res.warnings.append(err or "GraphQL introspection root is not an object")
        return res
    schema = (
        doc.get("data", {}).get("__schema") if "data" in doc else doc.get("__schema")
    )
    if not isinstance(schema, dict):
        res.warnings.append("no __schema in introspection result")
        return res
    type_map = {
        t.get("name"): t for t in schema.get("types", []) if isinstance(t, dict)
    }
    for root_key in ("queryType", "mutationType"):
        root = schema.get(root_key)
        if not isinstance(root, dict):
            continue
        root_type = type_map.get(root.get("name"))
        if not root_type:
            continue
        for fld in root_type.get("fields", []) or []:
            name = fld.get("name")
            if not name:
                continue
            params = [
                {
                    "name": a.get("name", ""),
                    "in": "body",
                    "type": "graphql",
                    "required": False,
                }
                for a in fld.get("args", [])
                if a.get("name")
            ]
            res.endpoints.append(
                DiscoveredEndpoint(
                    method="POST",
                    url=endpoint_url,
                    provenance=Provenance.GRAPHQL,
                    parameters=params,
                    path_template=f"/graphql#{root_key}.{name}",
                    request_body_schema={"operation": root_key, "field": name},
                    auth_required=True,
                )
            )
    return res


def parse_artifact(kind: str, content: str | dict, **kw) -> ParseResult:
    """Dispatch by artifact kind. Unknown kinds return a warning."""
    kind = (kind or "").lower()
    if kind in ("openapi", "swagger"):
        return parse_openapi(content, base_url=kw.get("base_url", ""))
    if kind == "har":
        return parse_har(content, in_scope_hosts=kw.get("in_scope_hosts"))
    if kind == "postman":
        return parse_postman(content)
    if kind == "graphql":
        return parse_graphql_introspection(
            content, endpoint_url=kw.get("endpoint_url", "")
        )
    r = ParseResult()
    r.warnings.append(f"unknown artifact kind {kind!r}")
    return r
