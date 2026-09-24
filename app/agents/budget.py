"""Per-assessment LLM token / cost budget ledger (F-09).

A single :class:`LlmBudget` accumulates the input/output tokens reported by every brain
call made during one assessment and derives an estimated USD cost. The active ledger is
carried in a :class:`contextvars.ContextVar`, so the shared brain singleton can record
usage against the *current* assessment without threading the ledger through every call
site. ``asyncio.create_task`` copies the context, so ledgers set at the top of an
assessment coroutine are inherited by the concurrency-pool child tasks.

Enforcement is degrade-then-stop:

* While the budget is exceeded, :class:`~app.agents.brain.LLMBrain` skips the network
  call and returns a deterministic decision (``source="budget_exceeded"``) — spend stops
  immediately but the assessment still completes with the deterministic brain.
* The engine also surfaces :meth:`LlmBudget.exceeded` into the coordinator's context so
  the LLM-brained coordinator can elect to stop dispatching further work.

A limit of ``0`` means "unbounded" for that dimension.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass


@dataclass
class LlmBudget:
    """Accumulates token usage and enforces token/cost ceilings for one assessment."""

    max_tokens: int = 0  # 0 => unbounded
    max_cost_usd: float = 0.0  # 0 => unbounded
    cost_per_1k_tokens_usd: float = 0.015
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    llm_calls: int = 0  # calls that actually hit the network

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cost_usd(self) -> float:
        return (self.total_tokens / 1000.0) * self.cost_per_1k_tokens_usd

    def exceeded(self) -> bool:
        """True once either ceiling is reached (checked *before* the next call)."""
        if self.max_tokens and self.total_tokens >= self.max_tokens:
            return True
        if self.max_cost_usd and self.cost_usd >= self.max_cost_usd:
            return True
        return False

    def record(self, input_tokens: int, output_tokens: int) -> None:
        """Add the token usage from one completed network LLM call (brain-level)."""
        self.input_tokens += max(0, int(input_tokens or 0))
        self.output_tokens += max(0, int(output_tokens or 0))
        self.llm_calls += 1

    def note_consult(self) -> None:
        """Count one agent brain consult, however it was served (agent-level).

        ``calls`` therefore counts every decision (LLM, deterministic, fallback or
        budget-degraded) while ``llm_calls`` counts only those that hit the network.
        """
        self.calls += 1

    def snapshot(self) -> dict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "calls": self.calls,
            "llm_calls": self.llm_calls,
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd,
            "exceeded": self.exceeded(),
        }


_current: contextvars.ContextVar[LlmBudget | None] = contextvars.ContextVar(
    "llm_budget", default=None
)


def set_current_budget(budget: LlmBudget | None) -> contextvars.Token:
    """Install ``budget`` as the active ledger; returns a token for :func:`reset`."""
    return _current.set(budget)


def reset_current_budget(token: contextvars.Token) -> None:
    _current.reset(token)


def get_current_budget() -> LlmBudget | None:
    """The ledger for the current assessment coroutine, or ``None`` when unbudgeted."""
    return _current.get()
