"""Concrete agents. Each is a capability-tagged unit with an LLM brain.

  * SpecialistCheckAgent — wraps one security check; brain ranks injection points,
    the deterministic check performs the scope-enforced probing.
  * DiscoveryAgent       — brain decides discovery emphasis; parsing/crawl are tools.
  * PlannerAgent         — brain picks a prioritization strategy over the plan.
  * ValidationAgent      — independently re-proves a finding (controlled evidence).
  * CoordinatorAgent     — brain decides continue/stop/replan under budget.

The pool instantiates a fresh specialist agent per (endpoint, check) plan step, so a
realistic assessment naturally runs 100+ agent instances, each brain-driven.
"""

from __future__ import annotations

from app.agents.base import Agent, AgentContext, AgentResult
from app.agents.brain import Brain, BrainDecision, BrainTask
from app.checks.base import BaseCheck, RawFinding
from app.checks.context import CheckContext


class SpecialistCheckAgent(Agent):
    capabilities = ("security-check",)

    def __init__(
        self,
        check: BaseCheck,
        check_ctx: CheckContext,
        brain: Brain | None = None,
        **kw,
    ):
        self.role = f"{check.check_class.value}-specialist"
        super().__init__(brain=brain, **kw)
        self.check = check
        self.check_ctx = check_ctx

    def _instruction(self, ctx: AgentContext) -> str:
        return (
            f"Prioritize injection points for a {self.check.check_class.value} probe on "
            f"{self.check_ctx.endpoint.method} {self.check_ctx.endpoint.path_template}. "
            f"Choose 'probe' to run or 'skip' if clearly inapplicable."
        )

    def _inspect(self, ctx: AgentContext) -> dict:
        ep = self.check_ctx.endpoint
        return {
            "check_class": self.check.check_class.value,
            "method": ep.method,
            "path_template": ep.path_template,
            "parameters": ep.parameters,
            "auth_required": ep.auth_required,
            "budget_remaining": ctx.budget_remaining(),
        }

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["probe", "skip"]

    async def _act(
        self, ctx: AgentContext, decision: BrainDecision
    ) -> list[RawFinding]:
        if decision.action == "skip":
            return []
        # Apply the brain's parameter ranking (bounded influence: reorder only).
        order = decision.params.get("param_order")
        if isinstance(order, list) and order:
            rank = {name: i for i, name in enumerate(order)}
            self.check_ctx.endpoint.parameters.sort(
                key=lambda p: rank.get(p.get("name", ""), 999)
            )
        if not await self.check.applies_to(self.check_ctx):
            return []
        return await self.check.run(self.check_ctx)

    async def _verify(
        self, ctx: AgentContext, findings: list[RawFinding]
    ) -> list[RawFinding]:
        # Specialist self-check: drop findings with no evidence (defensive).
        return [
            f
            for f in findings
            if f.evidence or f.check_class in ("security_headers", "info_disclosure")
        ]


class DiscoveryAgent(Agent):
    role = "discovery"
    capabilities = ("discovery",)

    def __init__(self, runner, brain: Brain | None = None, **kw):
        super().__init__(brain=brain, **kw)
        self._runner = runner  # async callable performing the actual discovery tools

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["discover", "skip"]

    async def _act(
        self, ctx: AgentContext, decision: BrainDecision
    ) -> list[RawFinding]:
        if self._runner and decision.action != "skip":
            await self._runner()
        return []


class PlannerAgent(Agent):
    role = "planner"
    capabilities = ("planning",)

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["coverage-first", "risk-first", "balanced"]


class CoordinatorAgent(Agent):
    role = "coordinator"
    capabilities = ("coordination",)

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["continue", "stop", "replan"]

    async def decide_continuation(
        self, ctx: AgentContext, signals: dict
    ) -> BrainDecision:
        return await self._consult(
            BrainTask(
                role=self.role,
                instruction="Decide whether to continue, stop, or replan.",
                context={**signals, "budget_remaining": ctx.budget_remaining()},
                allowed_actions=self._allowed_actions(ctx),
            ),
            phase="coordinate",
        )


class ValidationAgent(Agent):
    role = "validator"
    capabilities = ("validation",)

    def __init__(self, validator_coro, brain: Brain | None = None, **kw):
        super().__init__(brain=brain, **kw)
        self._validator_coro = validator_coro  # async callable -> ValidationOutcome

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["validate", "skip"]

    async def validate(self, ctx: AgentContext):
        await self._consult(
            BrainTask(
                role=self.role,
                instruction="Independently re-prove the suspected finding.",
                context={"assessment_id": ctx.assessment_id},
                allowed_actions=["validate"],
            ),
            phase="validate",
        )
        return await self._validator_coro()


class ReporterAgent(Agent):
    role = "reporter"
    capabilities = ("reporting",)

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["render"]
