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

from app.agents.base import Agent, AgentContext, DecisionRecord
from app.agents.brain import Brain, BrainDecision, BrainTask
from app.checks.base import BaseCheck, RawFinding
from app.checks.context import CheckContext
from app.orchestration.hooks import hooks


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
        self._probes = 0

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
        # On a revise pass (F-08), deepen the probe: try more injection payloads.
        if self._probes > 0:
            self.check_ctx.max_payloads = min(self.check_ctx.max_payloads * 2, 48)
        self._probes += 1
        if not await self.check.applies_to(self.check_ctx):
            return []
        # CC-02: pre/post tool hooks around the check execution. A pre_tool veto is
        # recorded in the decision trail (and hence the audit log) and nothing runs.
        ep = self.check_ctx.endpoint
        payload = {
            "assessment_id": ctx.assessment_id,
            "agent_id": self.id,
            "tool": self.check.name,
            "check_class": self.check.check_class.value,
            "method": ep.method,
            "path": ep.path_template,
        }
        outcome = await hooks.run("pre_tool", payload)
        if outcome.vetoed:
            self._decisions.append(
                DecisionRecord(
                    agent_id=self.id,
                    role=self.role,
                    phase="act",
                    action="vetoed",
                    brain_source="hook",
                    reasoning=outcome.reason[:280],
                )
            )
            return []
        findings = await self.check.run(self.check_ctx)
        await hooks.run("post_tool", {**payload, "findings": len(findings)})
        return findings

    def _can_revise(self, ctx: AgentContext, step: int) -> bool:
        # Bounded observe→revise (F-08): one deeper pass when the first found nothing and
        # the endpoint actually has parameters worth re-probing.
        return step == 0 and bool(self.check_ctx.injectable_params())

    async def _verify(
        self, ctx: AgentContext, findings: list[RawFinding]
    ) -> list[RawFinding]:
        # Specialist self-check: drop findings with no evidence (defensive).
        verified = [
            f
            for f in findings
            if f.evidence or f.check_class in ("security_headers", "info_disclosure")
        ]
        # Publish finding signals on the A2A bus for coordinator-side aggregation (F-05).
        bus = (ctx.extra or {}).get("bus")
        if bus is not None:
            from app.agents.a2a import AgentMessage

            for f in verified:
                await bus.publish(
                    AgentMessage(
                        topic="findings",
                        sender=self.id,
                        payload={
                            "check_class": f.check_class,
                            "severity": getattr(f.severity, "value", str(f.severity)),
                            "title": f.title,
                        },
                    )
                )
        return verified


class DiscoveryAgent(Agent):
    """Decides whether to actively crawl beyond supplied artifacts, then runs the crawl.

    ``runner`` is the scope-enforced crawl tool (an async callable). The brain only
    chooses ``discover``/``skip``; the runner is the deterministic tool that acts.
    """

    role = "discovery"
    capabilities = ("discovery",)

    def __init__(self, runner, brain: Brain | None = None, **kw):
        if runner is None or not callable(runner):
            raise ValueError("DiscoveryAgent requires an async crawl runner")
        super().__init__(brain=brain, **kw)
        self._runner = runner  # async callable performing the actual discovery tools
        self.ran = False

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["discover", "skip"]

    async def act(self, ctx: AgentContext, decision: BrainDecision) -> None:
        """Carry out the brain's decision: run the crawl tool unless it elected to skip."""
        await self._act(ctx, decision)

    async def _act(
        self, ctx: AgentContext, decision: BrainDecision
    ) -> list[RawFinding]:
        if decision.action != "skip":
            await self._runner()
            self.ran = True
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
        # "validate" re-proves now; "defer" leaves the finding suspected/inconclusive
        # (e.g. budget exhausted or the recipe cannot be re-run safely). Deferring never
        # confirms anything — it is the conservative choice.
        return ["validate", "defer"]

    async def validate(self, ctx: AgentContext):
        from app.core.enums import FindingStatus
        from app.services.validation import ValidationOutcome

        decision = await self._consult(
            BrainTask(
                role=self.role,
                instruction=(
                    "Independently re-prove the suspected finding now ('validate'), or "
                    "'defer' if re-execution is not currently appropriate."
                ),
                context={
                    "assessment_id": ctx.assessment_id,
                    "budget_remaining": ctx.budget_remaining(),
                    **(ctx.extra or {}),
                },
                allowed_actions=self._allowed_actions(ctx),
            ),
            phase="validate",
        )
        if decision.action == "defer":
            return ValidationOutcome(
                FindingStatus.INCONCLUSIVE,
                "deferred",
                f"validator deferred independent re-proof: {decision.reasoning}"[:280],
            )
        return await self._validator_coro()


class ReporterAgent(Agent):
    """Chooses the report emphasis; rendering itself is deterministic."""

    role = "reporter"
    capabilities = ("reporting",)
    EMPHASES = ("risk-first", "coverage-first")

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        # A real choice that changes the rendered report: lead with confirmed risk, or
        # lead with coverage/untested surface (useful when few findings were confirmed).
        return list(self.EMPHASES)
