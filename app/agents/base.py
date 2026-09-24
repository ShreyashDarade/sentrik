"""Agent base class implementing a bounded Claude Code-style reasoning loop.

Loop phases: inspect → hypothesize → plan → act → observe → verify → revise.
Each agent consults its brain (LLM or deterministic) to make bounded decisions, then
acts through deterministic, scope-enforced tools. Every decision is recorded to a
decision trail for the audit log (agent id, phase, brain source, reasoning).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from app.agents.brain import Brain, BrainDecision, BrainTask, get_brain
from app.checks.base import RawFinding


@dataclass
class DecisionRecord:
    agent_id: str
    role: str
    phase: str
    action: str
    brain_source: str
    reasoning: str
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "phase": self.phase,
            "action": self.action,
            "brain_source": self.brain_source,
            "reasoning": self.reasoning,
            "at": self.at,
        }


@dataclass
class AgentContext:
    """Shared, read-mostly context handed to an agent. No authorization record here."""

    assessment_id: str
    budget_remaining_getter: object = None  # callable -> int
    extra: dict = field(default_factory=dict)

    def budget_remaining(self) -> int:
        if callable(self.budget_remaining_getter):
            try:
                return int(self.budget_remaining_getter())
            except Exception:  # noqa: BLE001
                return 1
        return 1


@dataclass
class AgentResult:
    agent_id: str
    role: str
    findings: list[RawFinding] = field(default_factory=list)
    decisions: list[DecisionRecord] = field(default_factory=list)
    error: str = ""
    steps_used: int = 0


class Agent:
    """Base agent. Subclasses implement `_act` (the tool-using body of the loop)."""

    role: str = "agent"
    capabilities: tuple[str, ...] = ()

    def __init__(
        self,
        brain: Brain | None = None,
        agent_id: str | None = None,
        max_steps: int = 6,
    ):
        self.id = agent_id or f"{self.role}-{uuid.uuid4().hex[:8]}"
        self.brain = brain or get_brain()
        self.max_steps = max_steps
        self._decisions: list[DecisionRecord] = []

    async def _consult(self, task: BrainTask, phase: str) -> BrainDecision:
        decision = await self.brain.decide(task)
        self._decisions.append(
            DecisionRecord(
                agent_id=self.id,
                role=self.role,
                phase=phase,
                action=decision.action,
                brain_source=decision.source,
                reasoning=decision.reasoning,
            )
        )
        return decision

    async def run(self, ctx: AgentContext) -> AgentResult:
        """Bounded inspect→hypothesize→plan→act→observe→verify→revise loop.

        Iterates up to `max_steps`. Each step consults the brain (carrying the previous
        step's observation), acts, and verifies. It stops as soon as findings are produced
        or the brain elects to skip/stop — so the happy path is a single pass, while a
        barren endpoint may get one bounded 'revise' step with an adjusted strategy.
        """
        result = AgentResult(agent_id=self.id, role=self.role)
        observation: dict = {}
        try:
            for step in range(self.max_steps):
                phase = "inspect_plan" if step == 0 else "revise"
                context = self._inspect(ctx)
                if observation:
                    context = {**context, "observation": observation}
                decision = await self._consult(
                    BrainTask(
                        role=self.role,
                        instruction=self._instruction(ctx),
                        context=context,
                        allowed_actions=self._allowed_actions(ctx),
                    ),
                    phase=phase,
                )
                if decision.action in ("skip", "stop"):
                    break
                findings = await self._act(ctx, decision)
                verified = await self._verify(ctx, findings)
                if verified:
                    result.findings = verified
                    break  # observation satisfied — no need to revise
                # observe → revise: record what happened and let the brain decide to retry
                observation = {
                    "step": step,
                    "findings": 0,
                    "note": "no findings; consider an alternate strategy",
                }
                if not self._can_revise(ctx, step):
                    break
            result.steps_used = len([d for d in self._decisions])
        except Exception as exc:  # noqa: BLE001  — an agent failure must not crash the pool
            result.error = f"{type(exc).__name__}: {exc}"
        result.decisions = list(self._decisions)
        return result

    def _can_revise(self, ctx: AgentContext, step: int) -> bool:
        """Whether a revise iteration is worthwhile. Base agents do not revise."""
        return False

    # ---- overridable hooks ----
    def _instruction(self, ctx: AgentContext) -> str:
        return f"Decide how to proceed for role {self.role}."

    def _inspect(self, ctx: AgentContext) -> dict:
        return {
            "assessment_id": ctx.assessment_id,
            "budget_remaining": ctx.budget_remaining(),
        }

    def _allowed_actions(self, ctx: AgentContext) -> list[str]:
        return ["proceed", "skip"]

    async def _act(
        self, ctx: AgentContext, decision: BrainDecision
    ) -> list[RawFinding]:
        return []

    async def _verify(
        self, ctx: AgentContext, findings: list[RawFinding]
    ) -> list[RawFinding]:
        # Base verify is a no-op; specialists may self-filter low-signal findings.
        return findings
