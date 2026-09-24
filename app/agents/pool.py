"""Capability-based agent pool with bounded concurrency, fair scheduling, cancellation.

The pool runs many agent instances (100+ in a realistic assessment) under a concurrency
limit, checking a cancel predicate between dispatches (emergency cancellation), and
aggregates results and decision trails. Backpressure is provided by the semaphore; a
per-agent timeout prevents a stuck agent from stalling the pool.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from app.agents.base import Agent, AgentContext, AgentResult


@dataclass
class PoolStats:
    instantiated: int = 0
    completed: int = 0
    errored: int = 0
    skipped_cancelled: int = 0
    findings: int = 0
    decisions: int = 0
    by_role: dict = field(default_factory=dict)
    brain_sources: dict = field(default_factory=dict)


class AgentPool:
    def __init__(
        self,
        *,
        max_concurrency: int = 8,
        per_agent_timeout: float = 60.0,
        cancel_predicate=None,
    ):
        self.max_concurrency = max(1, max_concurrency)
        self.per_agent_timeout = per_agent_timeout
        self._cancel_predicate = cancel_predicate
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self.stats = PoolStats()

    def _cancelled(self) -> bool:
        if self._cancel_predicate is None:
            return False
        try:
            return bool(self._cancel_predicate())
        except Exception:  # noqa: BLE001
            return False

    async def _run_one(self, agent: Agent, ctx: AgentContext) -> AgentResult:
        async with self._sem:
            if self._cancelled():
                self.stats.skipped_cancelled += 1
                return AgentResult(
                    agent_id=agent.id, role=agent.role, error="cancelled"
                )
            try:
                result = await asyncio.wait_for(
                    agent.run(ctx), timeout=self.per_agent_timeout
                )
            except TimeoutError:
                self.stats.errored += 1
                return AgentResult(agent_id=agent.id, role=agent.role, error="timeout")
            except Exception as exc:  # noqa: BLE001
                self.stats.errored += 1
                return AgentResult(agent_id=agent.id, role=agent.role, error=str(exc))
            self._tally(result)
            return result

    def _tally(self, result: AgentResult) -> None:
        self.stats.completed += 1
        if result.error:
            self.stats.errored += 1
        self.stats.findings += len(result.findings)
        self.stats.decisions += len(result.decisions)
        self.stats.by_role[result.role] = self.stats.by_role.get(result.role, 0) + 1
        for d in result.decisions:
            self.stats.brain_sources[d.brain_source] = (
                self.stats.brain_sources.get(d.brain_source, 0) + 1
            )

    async def run(self, agents: list[Agent], ctx: AgentContext) -> list[AgentResult]:
        """Dispatch all agents under the concurrency limit; return results in order."""
        self.stats.instantiated += len(agents)
        if not agents:
            return []
        tasks = [asyncio.create_task(self._run_one(a, ctx)) for a in agents]
        results: list[AgentResult] = []
        for t in tasks:
            results.append(await t)
        return results

    async def run_streaming(self, agents: list[Agent], ctx: AgentContext):
        """Yield results as they complete (for live progress)."""
        self.stats.instantiated += len(agents)
        pending = {asyncio.create_task(self._run_one(a, ctx)) for a in agents}
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for d in done:
                yield d.result()
