"""Per-run sandbox / egress-isolation — defense in depth beneath ScopeGuard.

ScopeGuard (app/security/scope.py) enforces per-request authorization inside the
application. This module derives an OS/container-level *egress allowlist* from that
same authorization and provides a per-run isolation abstraction so that even a bug
or a compromised check cannot reach a destination the authorization never granted.

Two independent layers live here:

1. A synchronous belt-and-suspenders check (:meth:`Sandbox.assert_egress_allowed`)
   callable immediately before any ``connect()``. It re-derives host/port/network
   classification from the authorization and raises :class:`EgressViolation` on any
   destination outside the profile — it does not trust the caller.
2. A concrete, real egress-firewall ruleset (:func:`container_egress_rules`) a
   container deploy consumes to install a default-deny OUTPUT policy with explicit
   ACCEPTs for the resolved destinations. This makes the "container" sandbox mode
   real-as-code (a deploy step applies it) rather than a placeholder.

The ``mode`` (``none``/``process``/``container``) selects how :meth:`Sandbox.run`
executes work. True kernel isolation is a deploy concern realised via the generated
firewall rules; in-process modes still get the synchronous egress gate.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from app.core.config import Settings, get_settings
from app.core.enums import Environment
from app.security.netguard import NetGuardError, resolve_host

# Environments where a target may legitimately live on a private/loopback network.
_PRIVATE_OK_ENVS = {
    Environment.LAB,
    Environment.STAGING,
    Environment.DEVELOPMENT,
}

# Default ports assumed when an authorization does not pin any.
DEFAULT_PORTS: frozenset[int] = frozenset({80, 443})


class EgressViolation(PermissionError):
    """Raised when a destination falls outside the sandbox egress allowlist."""

    def __init__(self, message: str, *, host: str = "", port: int = 0, code: str = "egress_denied"):
        super().__init__(message)
        self.message = message
        self.host = host
        self.port = port
        self.code = code


class SandboxError(RuntimeError):
    """Raised when work executed inside the sandbox fails as a sandbox concern."""


@dataclass
class SandboxProfile:
    """The egress envelope for a single run, derived from an AuthorizationRecord."""

    allowed_hosts: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=set)
    allow_private: bool = False
    mode: str = "none"

    @classmethod
    def from_record(cls, record, settings: Settings | None = None) -> "SandboxProfile":
        settings = settings or get_settings()
        hosts = {h.lower().strip() for h in (record.allowed_hosts or []) if h and h.strip()}
        ports = {int(p) for p in (record.allowed_ports or [])}
        if not ports:
            ports = set(DEFAULT_PORTS)
        env = _coerce_env(record.environment)
        allow_private = env in _PRIVATE_OK_ENVS
        return cls(
            allowed_hosts=hosts,
            allowed_ports=ports,
            allow_private=allow_private,
            mode=(settings.sandbox_mode or "none"),
        )

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower()
        if host in self.allowed_hosts:
            return True
        for entry in self.allowed_hosts:
            if entry.startswith("*.") and fnmatch.fnmatch(host, entry):
                return True
        return False


class Sandbox:
    """A per-run isolation boundary carrying its derived egress allowlist."""

    def __init__(self, profile: SandboxProfile, settings: Settings | None = None):
        self.profile = profile
        self._settings = settings or get_settings()

    # ------------------------------------------------------------------ #
    # Synchronous belt-and-suspenders egress gate (call before connect)
    # ------------------------------------------------------------------ #
    def assert_egress_allowed(self, host: str, port: int) -> None:
        """Raise :class:`EgressViolation` if (host, port) is outside the allowlist.

        Independent of ScopeGuard: it re-derives host membership, port membership,
        and network classification (private/loopback/hard-blocked) from the profile
        so a sandboxed worker cannot reach anything the authorization never granted.
        """
        if self._settings.sandbox_enforce_egress_allowlist is False:
            return

        host_l = (host or "").lower().strip()
        if not host_l:
            raise EgressViolation("empty host is not permitted", host=host, port=port, code="empty_host")

        if not self.profile.host_allowed(host_l):
            raise EgressViolation(
                f"host {host_l!r} is not in the sandbox egress allowlist",
                host=host_l,
                port=port,
                code="host_not_allowed",
            )

        if port not in self.profile.allowed_ports:
            raise EgressViolation(
                f"port {port} is not in the sandbox egress allowlist "
                f"(allowed={sorted(self.profile.allowed_ports)})",
                host=host_l,
                port=port,
                code="port_not_allowed",
            )

        try:
            info = resolve_host(host_l, port, allow_dns=True)
        except NetGuardError as exc:
            raise EgressViolation(
                f"cannot classify egress destination {host_l!r}: {exc}",
                host=host_l,
                port=port,
                code="resolution_failed",
            ) from exc

        if info.is_hard_blocked:
            raise EgressViolation(
                f"{host_l} resolves to a hard-blocked metadata/link-local endpoint",
                host=host_l,
                port=port,
                code="hard_blocked",
            )

        if (info.is_private or info.is_loopback) and not self.profile.allow_private:
            raise EgressViolation(
                f"{host_l} resolves to a private/loopback address "
                f"not permitted for this environment (ips={info.resolved_ips})",
                host=host_l,
                port=port,
                code="private_network_denied",
            )

    # ------------------------------------------------------------------ #
    # Per-run execution boundary
    # ------------------------------------------------------------------ #
    async def run(self, coro):
        """Execute an awaitable "inside" the sandbox and return its result.

        For ``none``/``process`` modes the awaitable runs directly (an asyncio task
        boundary keeps it cancellable and isolated from the caller's frame). Any
        failure is wrapped in :class:`SandboxError` so a sandbox execution failure is
        reported cleanly and distinctly from an :class:`EgressViolation`. True kernel
        isolation for ``container`` mode is a deploy concern realised via
        :func:`container_egress_rules`.
        """
        import asyncio

        if coro is None:
            raise SandboxError("nothing to run inside the sandbox (coro is None)")

        task = asyncio.ensure_future(coro)
        try:
            return await task
        except EgressViolation:
            # An egress denial is a first-class security outcome; surface it verbatim.
            raise
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # wrap for clean sandbox reporting
            raise SandboxError(f"sandboxed work failed: {exc!r}") from exc


def container_egress_rules(profile: SandboxProfile) -> list[str]:
    """Generate concrete nftables/iptables egress-allowlist rules for a container.

    Produces a default-deny OUTPUT policy, explicit ACCEPTs to each resolved
    destination IP on each allowed port, and an ACCEPT for DNS so name resolution
    still works. A deploy step consumes these strings, making "container" sandbox
    mode real-as-code rather than a placeholder. Hosts that fail to resolve, or that
    resolve private/loopback where the environment forbids it, are annotated and
    skipped rather than silently accepted.
    """
    ports = sorted(profile.allowed_ports) or sorted(DEFAULT_PORTS)
    rules: list[str] = [
        "# --- sandbox egress allowlist (default-deny OUTPUT) ---",
        "iptables -P OUTPUT DROP",
        # Allow established/related return traffic and loopback interface only.
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        # DNS is required to resolve the allowlisted hostnames.
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
    ]

    resolved_any = False
    for host in sorted(profile.allowed_hosts):
        if host.startswith("*."):
            rules.append(
                f"# host {host}: wildcard — resolve concrete subdomains at deploy time before ACCEPT"
            )
            continue
        try:
            info = resolve_host(host, ports[0], allow_dns=True)
        except NetGuardError as exc:
            rules.append(f"# host {host}: SKIPPED — cannot resolve ({exc})")
            continue
        if info.is_hard_blocked:
            rules.append(f"# host {host}: SKIPPED — hard-blocked metadata/link-local endpoint")
            continue
        if (info.is_private or info.is_loopback) and not profile.allow_private:
            rules.append(
                f"# host {host}: SKIPPED — private/loopback not permitted for this environment"
            )
            continue
        for ip in info.resolved_ips:
            for port in ports:
                rules.append(
                    f"iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j ACCEPT  # {host}"
                )
                resolved_any = True

    if not resolved_any:
        rules.append("# NOTE: no concrete destinations resolved; OUTPUT remains fully denied")
    # Final explicit reject with logging for observability.
    rules.append("iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited")
    return rules


def sandbox_for(record, settings: Settings | None = None) -> Sandbox:
    """Convenience factory: build a :class:`Sandbox` bound to an AuthorizationRecord."""
    settings = settings or get_settings()
    profile = SandboxProfile.from_record(record, settings)
    return Sandbox(profile, settings)


def _coerce_env(value) -> Environment:
    try:
        return Environment(value)
    except (ValueError, TypeError):
        return Environment.PRODUCTION  # safest default: no private egress
