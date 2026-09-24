"""Passive, scope-bounded crawler using the guarded HTTP client.

This does authorized browsing only: GET requests inside scope, bounded page count,
extracting links and form actions/inputs. Every request passes through the
GuardedHttpClient, so scope/budget/rate limits are enforced automatically.
"""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlsplit

from app.core.enums import Provenance
from app.discovery.normalize import DiscoveredEndpoint
from app.security.http_client import GuardedHttpClient, TargetUnreachable
from app.security.scope import ScopeViolation

_HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_ACTION = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_FORM_METHOD = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT = re.compile(r"""<input\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


async def crawl(
    client: GuardedHttpClient,
    seed_url: str,
    *,
    max_pages: int = 25,
    max_depth: int = 3,
) -> tuple[list[DiscoveredEndpoint], list[str]]:
    """Return (endpoints, warnings). Never raises on individual page errors."""
    seed_host = (urlsplit(seed_url).hostname or "").lower()
    seen: set[str] = set()
    endpoints: list[DiscoveredEndpoint] = []
    warnings: list[str] = []
    queue: deque[tuple[str, int]] = deque([(seed_url, 0)])

    while queue and len(seen) < max_pages:
        url, depth = queue.popleft()
        norm = _normalize(url)
        if norm in seen or depth > max_depth:
            continue
        seen.add(norm)
        try:
            resp = await client.get(url)
        except ScopeViolation as exc:
            warnings.append(f"crawl blocked by scope: {exc.reason}")
            continue
        except TargetUnreachable as exc:
            warnings.append(f"crawl unreachable {url}: {exc}")
            continue

        endpoints.append(
            DiscoveredEndpoint(method="GET", url=url, provenance=Provenance.CRAWL)
        )
        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype.lower():
            continue

        # forms → endpoints with parameters
        for form_html in _FORM.findall(resp.text):
            action_m = _FORM_ACTION.search(form_html)
            method_m = _FORM_METHOD.search(form_html)
            action = urljoin(url, action_m.group(1)) if action_m else url
            method = (method_m.group(1) if method_m else "GET").upper()
            if (urlsplit(action).hostname or "").lower() != seed_host:
                continue
            names = _INPUT.findall(form_html)
            params = [
                {
                    "name": n,
                    "in": "body" if method != "GET" else "query",
                    "type": "string",
                    "required": False,
                }
                for n in names
            ]
            endpoints.append(
                DiscoveredEndpoint(
                    method=method,
                    url=action,
                    provenance=Provenance.CRAWL,
                    parameters=params,
                )
            )

        # links → enqueue same-host
        if depth < max_depth:
            for href in _HREF.findall(resp.text):
                nxt = urljoin(url, href)
                if not nxt.startswith(("http://", "https://")):
                    continue
                if (urlsplit(nxt).hostname or "").lower() != seed_host:
                    continue
                if _normalize(nxt) not in seen:
                    queue.append((nxt, depth + 1))

    return endpoints, warnings


def _normalize(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")
