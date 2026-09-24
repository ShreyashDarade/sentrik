"""Network boundary primitives: hostname/IP classification and SSRF defenses.

These run *before* any outbound request leaves the sandbox. They are independent of
the LLM and cannot be influenced by target content, retrieved documents, or skills.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# Link-local / cloud metadata endpoints that must never be reachable regardless of scope.
HARD_BLOCK_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure IMDS
    "100.100.100.100",  # Alibaba metadata
    "fd00:ec2::254",
}
HARD_BLOCK_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}


@dataclass
class HostInfo:
    scheme: str
    host: str
    port: int
    resolved_ips: list[str]
    is_loopback: bool
    is_private: bool
    is_hard_blocked: bool


class NetGuardError(ValueError):
    pass


def default_port_for_scheme(scheme: str) -> int:
    return {"http": 80, "https": 443}.get(scheme.lower(), 0)


def parse_url(url: str) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, path). Raises NetGuardError on malformed input."""
    if not url or "://" not in url:
        raise NetGuardError(f"malformed URL: {url!r}")
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise NetGuardError(f"unsupported scheme {scheme!r} (only http/https)")
    host = parts.hostname
    if not host:
        raise NetGuardError(f"URL has no host: {url!r}")
    port = parts.port or default_port_for_scheme(scheme)
    path = parts.path or "/"
    return scheme, host.lower(), port, path


def _classify_ip(ip: str) -> tuple[bool, bool]:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, False
    return obj.is_loopback, (obj.is_private or obj.is_link_local or obj.is_reserved)


def resolve_host(host: str, port: int, *, allow_dns: bool = True) -> HostInfo:
    """Resolve a hostname to IPs and classify it. IP literals skip DNS.

    Edge cases handled: IP literals (v4/v6), unresolvable hosts, hard-blocked
    metadata endpoints, hosts that resolve to multiple IPs (any private/loopback
    flags the whole host), DNS disabled.
    """
    scheme = "http"  # scheme not needed here; classification is IP-based
    hard = host in HARD_BLOCK_HOSTS
    resolved: list[str] = []

    # IP literal?
    try:
        ipaddress.ip_address(host)
        resolved = [host]
    except ValueError:
        if allow_dns:
            try:
                infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
                resolved = sorted({str(info[4][0]) for info in infos})
            except socket.gaierror as exc:
                raise NetGuardError(f"cannot resolve host {host!r}: {exc}")
        else:
            resolved = []

    is_loopback = False
    is_private = False
    for ip in resolved:
        lb, pv = _classify_ip(ip)
        is_loopback = is_loopback or lb
        is_private = is_private or pv
        if ip in HARD_BLOCK_IPS:
            hard = True

    return HostInfo(
        scheme=scheme,
        host=host,
        port=port,
        resolved_ips=resolved,
        is_loopback=is_loopback,
        is_private=is_private,
        is_hard_blocked=hard,
    )


def assert_not_hard_blocked(info: HostInfo) -> None:
    if info.is_hard_blocked:
        raise NetGuardError(
            f"destination {info.host} resolves to a hard-blocked metadata/link-local endpoint"
        )
