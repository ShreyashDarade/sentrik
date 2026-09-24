"""Ownership / authorization-to-test verification.

Supported methods:
  * dns_txt          — a TXT record `sentrik-site-verification=<token>` on the host.
  * http_file        — a file at /.well-known/sentrik-verification.txt containing the token.
  * manual_attestation — a signed delegated-permission attestation (hash recorded).
  * lab_bundled      — the bundled controlled vulnerable app; auto-trusted on loopback only.

Verification is best-effort and defensive: network/DNS failures return a FAILED status
with a reason, never an exception that aborts onboarding.
"""

from __future__ import annotations

import hashlib
import secrets
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.core.config import get_settings
from app.core.enums import Environment, OwnershipMethod, VerificationStatus


@dataclass
class VerificationOutcome:
    status: VerificationStatus
    detail: str


def generate_ownership_token() -> str:
    return secrets.token_hex(16)


def expected_dns_value(token: str) -> str:
    return f"{get_settings().ownership_dns_token_prefix}={token}"


def host_of(base_url: str) -> str:
    return (urlsplit(base_url).hostname or "").lower()


async def verify_ownership(
    *,
    method: OwnershipMethod,
    host: str,
    token: str,
    base_url: str,
    environment: Environment,
    attestation: str | None = None,
) -> VerificationOutcome:
    if method == OwnershipMethod.LAB_BUNDLED:
        return _verify_lab(host)
    if method == OwnershipMethod.MANUAL_ATTESTATION:
        return _verify_attestation(attestation)
    if method == OwnershipMethod.DNS_TXT:
        return _verify_dns(host, token)
    if method == OwnershipMethod.HTTP_FILE:
        return await _verify_http_file(base_url, token)
    return VerificationOutcome(
        VerificationStatus.FAILED, f"unsupported method {method}"
    )


def _verify_lab(host: str) -> VerificationOutcome:
    # Bundled lab apps only ever run on loopback; trust only those.
    if host in ("127.0.0.1", "localhost", "::1") or host.startswith("127."):
        return VerificationOutcome(
            VerificationStatus.VERIFIED, "bundled lab target on loopback"
        )
    return VerificationOutcome(
        VerificationStatus.FAILED,
        "lab_bundled method only valid for loopback controlled apps",
    )


def _verify_attestation(attestation: str | None) -> VerificationOutcome:
    if not attestation or len(attestation.strip()) < 32:
        return VerificationOutcome(
            VerificationStatus.FAILED,
            "manual attestation requires a signed statement of >= 32 chars",
        )
    digest = hashlib.sha256(attestation.encode()).hexdigest()
    return VerificationOutcome(
        VerificationStatus.VERIFIED, f"attestation recorded (sha256={digest[:16]}...)"
    )


def _verify_dns(host: str, token: str) -> VerificationOutcome:
    want = expected_dns_value(token)
    try:
        # Prefer dnspython if present, else fall back to a TXT lookup via socket is not
        # possible; use a minimal resolver via socket.getaddrinfo is insufficient for TXT.
        try:
            import dns.resolver  # type: ignore

            answers = dns.resolver.resolve(host, "TXT")
            values = [
                "".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
                for r in answers
            ]
        except ImportError:
            return VerificationOutcome(
                VerificationStatus.PENDING,
                "dnspython not installed; cannot check TXT automatically. "
                f"Add TXT record: {want}",
            )
        if any(want in v for v in values):
            return VerificationOutcome(
                VerificationStatus.VERIFIED, f"TXT record matched on {host}"
            )
        return VerificationOutcome(
            VerificationStatus.FAILED,
            f"expected TXT {want!r} not found (saw {values[:5]})",
        )
    except Exception as exc:  # noqa: BLE001
        return VerificationOutcome(
            VerificationStatus.FAILED, f"DNS lookup failed: {exc}"
        )


async def _verify_http_file(base_url: str, token: str) -> VerificationOutcome:
    s = get_settings()
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    url = origin + s.ownership_http_well_known_path
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            resp = await client.get(url)
        if resp.status_code == 200 and token in resp.text:
            return VerificationOutcome(
                VerificationStatus.VERIFIED, f"token found at {url}"
            )
        return VerificationOutcome(
            VerificationStatus.FAILED,
            f"token not found at {url} (status={resp.status_code})",
        )
    except httpx.HTTPError as exc:
        return VerificationOutcome(
            VerificationStatus.FAILED, f"could not fetch {url}: {exc}"
        )


def resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
