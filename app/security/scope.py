"""ScopeGuard — deny-by-default authorization enforcement bound to an AuthorizationRecord.

Enforced at four choke points: scheduler (before planning a step), tool gateway
(before a check runs), network boundary (every outbound request, incl. redirects),
and evidence store (tenant tagging). Nothing the LLM or a target says can widen scope.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.config import get_settings
from app.core.enums import Environment, TestIntensity, VerificationStatus
from app.models import AuthorizationRecord
from app.security.netguard import (
    NetGuardError,
    default_port_for_scheme,
    parse_url,
    resolve_host,
)


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    code: str = "ok"
    details: dict = field(default_factory=dict)

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise ScopeViolation(self.reason, self.code, self.details)


class ScopeViolation(PermissionError):
    def __init__(
        self, reason: str, code: str = "scope_denied", details: dict | None = None
    ):
        super().__init__(reason)
        self.reason = reason
        self.code = code
        self.details = details or {}


# Intensity ordering for graduated permissions.
_INTENSITY_RANK = {
    TestIntensity.PASSIVE: 0,
    TestIntensity.SAFE_ACTIVE: 1,
    TestIntensity.INVASIVE: 2,
}

# Methods considered state-changing.
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class ScopeGuard:
    """Stateless-ish evaluator over one AuthorizationRecord plus a mutable request budget."""

    def __init__(self, record: AuthorizationRecord, *, requests_made: int = 0):
        self.record = record
        self.requests_made = requests_made
        self._settings = get_settings()
        self._allowed_hosts = {
            h.lower().strip() for h in (record.allowed_hosts or []) if h
        }
        self._allowed_ports = set(record.allowed_ports or [])
        self._allowed_methods = {m.upper() for m in (record.allowed_methods or [])}
        self._allowed_checks = set(record.allowed_check_classes or [])
        self._path_allow = list(record.path_allowlist or [])
        self._path_deny = list(record.path_denylist or [])

    # ------------------------------------------------------------------ #
    # Precondition: the record itself must be usable
    # ------------------------------------------------------------------ #
    def check_record_active(self, *, now: datetime | None = None) -> ScopeDecision:
        now = now or datetime.now(UTC)
        if self.record.status != VerificationStatus.VERIFIED.value:
            return ScopeDecision(
                False,
                f"authorization not verified (status={self.record.status})",
                code="authz_unverified",
            )
        # testing window
        ws, we = self.record.window_start, self.record.window_end
        if ws and now < _aware(ws):
            return ScopeDecision(
                False,
                f"outside testing window (starts {ws.isoformat()})",
                code="window_not_started",
            )
        if we and now > _aware(we):
            return ScopeDecision(
                False,
                f"outside testing window (ended {we.isoformat()})",
                code="window_ended",
            )
        return ScopeDecision(True, "record active")

    # ------------------------------------------------------------------ #
    # Budgets
    # ------------------------------------------------------------------ #
    def check_budget(self, *, additional: int = 1) -> ScopeDecision:
        limit = min(
            self.record.max_requests or 0, self._settings.max_requests_per_assessment
        )
        if limit and self.requests_made + additional > limit:
            return ScopeDecision(
                False,
                f"request budget exhausted ({self.requests_made}/{limit})",
                code="budget_exhausted",
                details={"made": self.requests_made, "limit": limit},
            )
        return ScopeDecision(True, "within budget")

    def note_requests(self, n: int = 1) -> None:
        self.requests_made += n

    # ------------------------------------------------------------------ #
    # Check-class / intensity gating (tool gateway)
    # ------------------------------------------------------------------ #
    def check_class_allowed(
        self, check_class: str, intensity: TestIntensity
    ) -> ScopeDecision:
        if self._allowed_checks and check_class not in self._allowed_checks:
            return ScopeDecision(
                False,
                f"check class {check_class!r} not in authorized set",
                code="check_not_authorized",
            )
        rec_intensity = _coerce_intensity(self.record.intensity)
        if _INTENSITY_RANK[intensity] > _INTENSITY_RANK[rec_intensity]:
            return ScopeDecision(
                False,
                f"check intensity {intensity.value} exceeds authorized {rec_intensity.value}",
                code="intensity_exceeded",
            )
        # Invasive/state-changing only where environment + flag permit.
        env = _coerce_env(self.record.environment)
        if intensity == TestIntensity.INVASIVE and env == Environment.PRODUCTION:
            return ScopeDecision(
                False,
                "invasive checks are forbidden in production",
                code="invasive_in_prod",
            )
        return ScopeDecision(True, "check class permitted")

    # ------------------------------------------------------------------ #
    # Request-level authorization (network boundary) — the core gate
    # ------------------------------------------------------------------ #
    def check_request(
        self, method: str, url: str, *, is_redirect: bool = False
    ) -> ScopeDecision:
        method = (method or "").upper()
        try:
            scheme, host, port, path = parse_url(url)
        except NetGuardError as exc:
            return ScopeDecision(False, str(exc), code="malformed_url")

        # method
        if self._allowed_methods and method not in self._allowed_methods:
            return ScopeDecision(
                False, f"method {method} not authorized", code="method_denied"
            )
        if method in STATE_CHANGING_METHODS and not self.record.allow_state_changing:
            return ScopeDecision(
                False,
                f"state-changing method {method} not authorized",
                code="state_change_denied",
            )

        # host (exact or explicit wildcard entry like *.example.com)
        if not self._host_in_scope(host):
            return ScopeDecision(
                False,
                f"host {host!r} not in authorized scope (deny-by-default)"
                + (" [via redirect]" if is_redirect else ""),
                code="host_out_of_scope",
                details={"host": host, "redirect": is_redirect},
            )

        # port
        allowed_ports = self._allowed_ports or {default_port_for_scheme(scheme)}
        if port not in allowed_ports:
            return ScopeDecision(
                False,
                f"port {port} not authorized (allowed={sorted(allowed_ports)})",
                code="port_denied",
            )

        # path allow/deny
        pd = self._path_decision(path)
        if not pd.allowed:
            return pd

        # network classification / SSRF
        try:
            info = resolve_host(host, port, allow_dns=True)
        except NetGuardError as exc:
            return ScopeDecision(False, str(exc), code="resolution_failed")
        if info.is_hard_blocked:
            return ScopeDecision(
                False,
                f"{host} hits a hard-blocked metadata endpoint",
                code="metadata_blocked",
            )
        if (info.is_private or info.is_loopback) and not self._private_allowed():
            return ScopeDecision(
                False,
                f"{host} resolves to a private/loopback address; not permitted for this environment",
                code="private_network_denied",
                details={"ips": info.resolved_ips},
            )
        return ScopeDecision(
            True,
            "request in scope",
            details={"host": host, "port": port, "ips": info.resolved_ips},
        )

    # ------------------------------------------------------------------ #
    # Newly discovered asset — always requires explicit re-authorization
    # ------------------------------------------------------------------ #
    def evaluate_new_asset(self, host: str) -> ScopeDecision:
        if self._host_in_scope(host.lower()):
            return ScopeDecision(True, "asset already in scope")
        return ScopeDecision(
            False,
            f"newly discovered asset {host!r} requires a separate authorization record",
            code="new_asset_unauthorized",
            details={"host": host},
        )

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _host_in_scope(self, host: str) -> bool:
        if host in self._allowed_hosts:
            return True
        for entry in self._allowed_hosts:
            if entry.startswith("*.") and fnmatch.fnmatch(host, entry):
                return True
        return False

    def _path_decision(self, path: str) -> ScopeDecision:
        for deny in self._path_deny:
            if path.startswith(deny) or fnmatch.fnmatch(path, deny):
                return ScopeDecision(
                    False,
                    f"path {path!r} matches denylist entry {deny!r}",
                    code="path_denied",
                )
        if self._path_allow:
            for allow in self._path_allow:
                if path.startswith(allow) or fnmatch.fnmatch(path, allow):
                    return ScopeDecision(True, "path allowed")
            return ScopeDecision(
                False, f"path {path!r} not in path allowlist", code="path_not_allowed"
            )
        return ScopeDecision(True, "path allowed (no allowlist restriction)")

    def _private_allowed(self) -> bool:
        env = _coerce_env(self.record.environment)
        if env == Environment.LAB:
            return True  # bundled controlled apps run on loopback
        # staging/dev may live on private networks if the operator enabled it globally
        if env in (Environment.STAGING, Environment.DEVELOPMENT):
            return self._settings.allow_private_networks
        return False  # production must be a public, owned host


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _coerce_env(value: str) -> Environment:
    try:
        return Environment(value)
    except ValueError:
        return Environment.PRODUCTION  # safest default


def _coerce_intensity(value: str) -> TestIntensity:
    try:
        return TestIntensity(value)
    except ValueError:
        return TestIntensity.PASSIVE
