"""GuardedHttpClient — the single sanctioned egress path for all target traffic.

Every request is authorized by a ScopeGuard *before* it leaves, redirects are
re-authorized hop-by-hop (deny-by-default), a token-bucket rate limiter enforces
the authorized rate, and the request budget is decremented atomically. Checks never
get a raw httpx client; they get this wrapper. This is the network choke point.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from app.core.config import get_settings
from app.security.scope import ScopeGuard, ScopeViolation


@dataclass
class GuardedResponse:
    status_code: int
    headers: dict
    text: str
    elapsed_ms: float
    url: str
    request_method: str
    request_headers: dict
    request_body: str | None


class RateLimiter:
    """Simple async token bucket."""

    def __init__(self, rate_per_sec: float, burst: float | None = None):
        self.rate = max(rate_per_sec, 0.1)
        self.capacity = burst if burst is not None else max(self.rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(
                self.capacity, self.tokens + (now - self.updated) * self.rate
            )
            self.updated = now
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
                self.updated = time.monotonic()
            else:
                self.tokens -= 1.0


class GuardedHttpClient:
    def __init__(self, guard: ScopeGuard, *, on_request=None):
        self.guard = guard
        self._settings = get_settings()
        self._rate = RateLimiter(
            guard.record.rate_limit_per_sec or self._settings.default_rate_limit_per_sec
        )
        self._on_request = on_request  # callback(count) for accounting/persistence
        self._client: httpx.AsyncClient | None = None
        # Target-health signals (AU-08). We track *connection* failures, not HTTP 5xx,
        # because a 5xx can be an intended probe result (e.g. error-based SQLi).
        self.request_count = 0
        self.error_count = 0
        self.consecutive_errors = 0

    async def __aenter__(self) -> GuardedHttpClient:
        # follow_redirects=False: we re-authorize each hop ourselves.
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(self._settings.outbound_connect_timeout),
            verify=True,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data=None,
        json=None,
        max_redirects: int = 3,
    ) -> GuardedResponse:
        """Authorize, rate-limit, budget, then perform. Follows redirects with re-auth."""
        if self._client is None:
            raise RuntimeError(
                "GuardedHttpClient must be used as an async context manager"
            )

        # Precondition gates
        self.guard.check_record_active().raise_if_denied()
        self.guard.check_budget(additional=1).raise_if_denied()
        decision = self.guard.check_request(method, url)
        decision.raise_if_denied()
        # Anti-DNS-rebinding (AU-03), belt-and-suspenders with the connect-to-pinned-IP
        # below: re-resolve immediately before connecting and reject if the host now
        # resolves to a changed IP set or a private/metadata address. The actual socket
        # then connects to the *validated* IP (see _build_pinned), fully closing the
        # resolve→connect TOCTOU while TLS SNI/cert validation keeps the hostname.
        self._assert_no_rebinding(url, decision.details.get("ips") or [])

        await self._rate.acquire()
        self.guard.note_requests(1)
        if self._on_request:
            await _maybe_await(self._on_request(self.guard.requests_made))

        current_url = url
        current_method = method
        current_ips = decision.details.get("ips") or []
        redirects = 0
        while True:
            start = time.perf_counter()
            self.request_count += 1
            try:
                from app.core.observability import span

                # AU-03: connect to the validated IP (URL host → pinned IP) while
                # preserving the Host header and TLS SNI, so DNS cannot be rebound
                # between the scope check and the socket connect.
                req = self._build_pinned(
                    current_method,
                    current_url,
                    current_ips,
                    headers,
                    params,
                    data,
                    json,
                )
                with span("http.request", method=current_method, url=current_url):
                    resp = await self._client.send(req)
            except httpx.HTTPError as exc:
                self.error_count += 1
                self.consecutive_errors += 1
                raise TargetUnreachable(
                    f"request to {current_url} failed: {exc}"
                ) from exc
            self.consecutive_errors = 0  # a completed HTTP response = target reachable
            elapsed = (time.perf_counter() - start) * 1000.0

            if (
                resp.status_code in (301, 302, 303, 307, 308)
                and "location" in resp.headers
            ):
                redirects += 1
                if redirects > max_redirects:
                    break
                location = str(resp.url.join(resp.headers["location"]))
                # Re-authorize the redirect target — deny-by-default across hosts.
                decision = self.guard.check_request("GET", location, is_redirect=True)
                if not decision.allowed:
                    raise ScopeViolation(
                        f"redirect to out-of-scope location blocked: {decision.reason}",
                        decision.code,
                        decision.details,
                    )
                # 303 / 302-with-GET semantics: switch to GET, drop body.
                if resp.status_code in (301, 302, 303):
                    current_method, data, json = "GET", None, None
                current_url = location
                current_ips = decision.details.get("ips") or []
                self.guard.check_budget(additional=1).raise_if_denied()
                await self._rate.acquire()
                self.guard.note_requests(1)
                continue
            break

        body_text = (
            resp.text if len(resp.content) < 2_000_000 else resp.text[:2_000_000]
        )
        return GuardedResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=body_text,
            elapsed_ms=elapsed,
            url=str(resp.url),
            request_method=current_method,
            request_headers=dict(headers or {}),
            request_body=_body_repr(data, json),
        )

    def _build_pinned(self, method, url, ips, headers, params, data, json):
        """Build an httpx request pinned to a validated IP (AU-03).

        For a real hostname with a validated IP, the connection target is rewritten to
        the IP while the Host header and TLS SNI keep the original hostname (so cert
        validation still works). IP-literal targets (e.g. loopback lab) are unchanged.
        """
        import ipaddress

        from app.security.netguard import NetGuardError, parse_url

        req = self._client.build_request(
            method, url, headers=headers, params=params, data=data, json=json
        )
        try:
            scheme, host, port, _path = parse_url(url)
        except NetGuardError:
            return req
        try:
            ipaddress.ip_address(host)
            return req  # already an IP literal → nothing to pin
        except ValueError:
            pass
        pinned = ips[0] if ips else None
        if not pinned:
            return req
        default_port = 443 if scheme == "https" else 80
        host_header = host if port == default_port else f"{host}:{port}"
        req.url = req.url.copy_with(host=pinned)
        req.headers["Host"] = host_header
        req.extensions = dict(req.extensions or {})
        req.extensions["sni_hostname"] = host
        return req

    def _assert_no_rebinding(self, url: str, validated_ips: list) -> None:
        """Re-resolve and reject if resolution changed to an unvalidated/private IP (AU-03)."""
        from app.security.netguard import NetGuardError, parse_url, resolve_host

        try:
            _scheme, host, port, _path = parse_url(url)
            info = resolve_host(host, port, allow_dns=True)
        except NetGuardError:
            return  # a parse/resolve failure will be handled by the request path itself
        if info.is_hard_blocked or info.is_private or info.is_loopback:
            # loopback/private is only reachable when the guard already permits it; if the
            # guard validated public IPs but the host now resolves private → rebinding.
            if validated_ips and not any(
                ip in validated_ips for ip in info.resolved_ips
            ):
                raise ScopeViolation(
                    f"DNS rebinding detected: {host} now resolves to "
                    f"{info.resolved_ips} (was {validated_ips})",
                    "dns_rebinding",
                    {
                        "host": host,
                        "now": info.resolved_ips,
                        "validated": validated_ips,
                    },
                )
        if validated_ips and set(info.resolved_ips) - set(validated_ips):
            # resolution introduced new IPs not seen at scope-check time
            new = sorted(set(info.resolved_ips) - set(validated_ips))
            raise ScopeViolation(
                f"DNS rebinding detected: {host} resolution changed, new IPs {new}",
                "dns_rebinding",
                {"host": host, "new_ips": new, "validated": validated_ips},
            )

    @property
    def unhealthy(self) -> bool:
        """True when the target appears in distress (too many consecutive conn failures)."""
        return (
            self.consecutive_errors
            >= self._settings.target_health_max_consecutive_errors
        )

    async def get(self, url: str, **kw) -> GuardedResponse:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> GuardedResponse:
        return await self.request("POST", url, **kw)


class TargetUnreachable(RuntimeError):
    pass


async def _maybe_await(value):
    if asyncio.iscoroutine(value):
        return await value
    return value


def _body_repr(data, json) -> str | None:
    if json is not None:
        import json as _j

        try:
            return _j.dumps(json)[:4096]
        except (TypeError, ValueError):
            return str(json)[:4096]
    if data is not None:
        return str(data)[:4096]
    return None
