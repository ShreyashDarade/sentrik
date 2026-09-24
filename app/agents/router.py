"""Capability-based agent routing (AG-04).

Agents declare `capabilities` (a tuple of capability tags). The `CapabilityRouter`
maps a required capability to the agent class that advertises it, so the orchestrator
selects an agent for a unit of work by *capability* rather than hard-coding a class.
This is the seam that lets new agent types be slotted in: register a class advertising
a capability and the router will pick it.
"""

from __future__ import annotations

from app.agents.base import Agent
from app.agents.specialists import (
    CoordinatorAgent,
    DiscoveryAgent,
    PlannerAgent,
    ReporterAgent,
    SpecialistCheckAgent,
    ValidationAgent,
)


class CapabilityRouter:
    def __init__(self):
        self._by_capability: dict[str, type[Agent]] = {}

    def register(self, agent_cls: type[Agent]) -> None:
        for cap in getattr(agent_cls, "capabilities", ()):  # type: ignore[attr-defined]
            self._by_capability.setdefault(cap, agent_cls)

    def select(self, capability: str) -> type[Agent] | None:
        return self._by_capability.get(capability)

    def capabilities(self) -> list[str]:
        return sorted(self._by_capability)

    def build(self, capability: str, *args, **kwargs) -> Agent | None:
        cls = self.select(capability)
        if cls is None:
            return None
        return cls(*args, **kwargs)


def default_router() -> CapabilityRouter:
    r = CapabilityRouter()
    for cls in (
        SpecialistCheckAgent,
        DiscoveryAgent,
        PlannerAgent,
        CoordinatorAgent,
        ValidationAgent,
        ReporterAgent,
    ):
        r.register(cls)
    return r


# process-wide default router
router = default_router()
