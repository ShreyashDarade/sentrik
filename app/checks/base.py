"""Typed check contracts + a registry.

A check is a deterministic security probe with a declared class, intensity, and CWE.
It receives a CheckContext (guarded client, endpoint, accounts) and returns
RawFindings with attached RawEvidence (redacted request/response exchanges).

Checks NEVER see the authorization record or secrets they were not given; the
GuardedHttpClient is the only egress. A check that raises CheckError is recorded as
an errored plan step, not a crash of the assessment.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.core.enums import CheckClass, Confidence, Severity, TestIntensity

if TYPE_CHECKING:
    from app.checks.context import CheckContext  # re-exported below


@dataclass
class RawEvidence:
    kind: str
    request: dict
    response: dict
    note: str = ""


@dataclass
class RawFinding:
    check_class: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    description: str
    remediation: str
    evidence: list[RawEvidence] = field(default_factory=list)
    reproduction: dict = field(default_factory=dict)  # replayable sequence
    dedup_seed: str = ""  # stable per (endpoint, injection point); fingerprinted below
    endpoint_url: str = ""

    def dedup_key(self, endpoint_fp: str) -> str:
        seed = self.dedup_seed or f"{self.check_class}:{self.endpoint_url}:{self.title}"
        return hashlib.sha1(f"{endpoint_fp}:{seed}".encode()).hexdigest()


class CheckError(RuntimeError):
    """Raised by a check when it cannot complete (target error, malformed endpoint)."""


class BaseCheck:
    name: str = "base"
    check_class: CheckClass = CheckClass.INFO_DISCLOSURE
    intensity: TestIntensity = TestIntensity.PASSIVE
    cwe: str = ""
    # Whether this check mutates state (informs policy gating).
    state_changing: bool = False

    async def applies_to(self, ctx: CheckContext) -> bool:  # pragma: no cover - default
        return True

    async def run(self, ctx: CheckContext) -> list[RawFinding]:
        raise NotImplementedError


class _Registry:
    def __init__(self):
        self._checks: dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck) -> BaseCheck:
        self._checks[check.name] = check
        return check

    def all(self) -> list[BaseCheck]:
        return list(self._checks.values())

    def by_class(self, check_class: str) -> list[BaseCheck]:
        return [c for c in self._checks.values() if c.check_class.value == check_class]

    def get(self, name: str) -> BaseCheck | None:
        return self._checks.get(name)

    def classes(self) -> list[str]:
        return sorted({c.check_class.value for c in self._checks.values()})


registry = _Registry()

# Re-export CheckContext from context module to avoid import cycle at type level.
from app.checks.context import CheckContext
