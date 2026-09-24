"""Assessment lifecycle engine.

Drives one assessment through:
  CREATED → AUTHORIZED → DISCOVERING → PLANNING → POLICY_CHECK → EXECUTING →
  VALIDATING → SCORING → REPORTING → COMPLETED   (or FAILED / CANCELLED)

Guarantees:
  * Authorization is re-checked at the scheduler and before every outbound request
    (via ScopeGuard + GuardedHttpClient). Nothing runs on an unverified record.
  * A durable Checkpoint is written after each phase so a crashed run can resume.
  * Emergency cancellation is honored between phases and between plan steps.
  * Global concurrency is bounded by a semaphore (max_concurrent_assessments).
  * Findings pass through independent validation before scoring/reporting.
  * All checks execute inside LLM-brained agents from the capability-based pool.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import Agent, AgentContext
from app.agents.brain import BrainTask, get_brain
from app.agents.pool import AgentPool
from app.agents.registry import load_declarative_checks
from app.agents.router import router as capability_router
from app.agents.specialists import (
    CoordinatorAgent,
    DiscoveryAgent,
    PlannerAgent,
    ReporterAgent,
    SpecialistCheckAgent,
    ValidationAgent,
)
from app.checks.base import RawFinding
from app.checks.base import registry as check_registry
from app.checks.context import CheckContext, EndpointView
from app.core.config import get_settings
from app.core.db import get_sessionmaker
from app.core.enums import (
    TERMINAL_STATES,
    AssessmentState,
    FindingStatus,
    JobState,
    TestIntensity,
)
from app.discovery.crawler import crawl
from app.discovery.normalize import DiscoveredEndpoint, merge_endpoints
from app.discovery.parsers import parse_artifact
from app.models import (
    Assessment,
    AuthorizationRecord,
    Checkpoint,
    Coverage,
    DiscoveryArtifact,
    Endpoint,
    Evidence,
    Finding,
    Job,
    PlanStep,
    Target,
    TestAccount,
    ValidationResult,
)
from app.security.http_client import GuardedHttpClient
from app.security.scope import ScopeGuard, ScopeViolation
from app.services import scoring
from app.services.audit import write_audit
from app.services.planning import build_plan
from app.services.remediation import build_remediation
from app.services.sessions import establish_session
from app.services.validation import validate_finding

log = logging.getLogger("sentinel.orchestrator")

# --------------------------------------------------------------------------- #
# Run registry (in-process). A production deployment swaps this for a queue.
# --------------------------------------------------------------------------- #
_running: dict[str, asyncio.Task] = {}
_global_sem: asyncio.Semaphore | None = None
_org_sems: dict[str, asyncio.Semaphore] = {}


def _sem() -> asyncio.Semaphore:
    global _global_sem
    if _global_sem is None:
        _global_sem = asyncio.Semaphore(get_settings().max_concurrent_assessments)
    return _global_sem


def _org_sem(org_id: str) -> asyncio.Semaphore:
    """Per-tenant concurrency quota so one org cannot starve others (EX-04)."""
    sem = _org_sems.get(org_id)
    if sem is None:
        sem = asyncio.Semaphore(get_settings().max_concurrent_assessments_per_org)
        _org_sems[org_id] = sem
    return sem


async def _org_id_of(assessment_id: str) -> str | None:
    async with get_sessionmaker()() as session:
        a = await session.get(Assessment, assessment_id)
        return a.org_id if a else None


def start_assessment(assessment_id: str) -> None:
    """Fire-and-forget launch. Idempotent: ignores an already-running assessment."""
    if assessment_id in _running and not _running[assessment_id].done():
        return
    task = asyncio.create_task(_supervise(assessment_id))
    _running[assessment_id] = task


async def _supervise(assessment_id: str) -> None:
    # Per-tenant quota (EX-04): acquire the org slot first, then a global slot. This
    # bounds any single org's concurrency and keeps global scheduling fair across orgs.
    org_id = await _org_id_of(assessment_id)
    org_sem = _org_sem(org_id) if org_id else None
    if org_sem is not None:
        await org_sem.acquire()
    from app.core.observability import span

    try:
        async with _sem():
            engine = AssessmentEngine(assessment_id)
            try:
                settings = get_settings()
                with span(
                    "assessment.run", assessment_id=assessment_id, org_id=org_id or ""
                ):
                    if settings.use_langgraph:
                        from app.orchestration.graph import (
                            LANGGRAPH_AVAILABLE,
                            run_via_langgraph,
                        )

                        if LANGGRAPH_AVAILABLE:
                            log.info(
                                "running assessment %s via LangGraph", assessment_id
                            )
                            await run_via_langgraph(assessment_id)
                        else:
                            log.warning(
                                "SENTINEL_USE_LANGGRAPH set but langgraph unavailable; using inline engine"
                            )
                            await engine.run()
                    else:
                        await engine.run()
            except Exception as exc:
                log.exception("assessment %s crashed", assessment_id)
                await engine.mark_failed(f"engine crash: {type(exc).__name__}: {exc}")
            finally:
                _running.pop(assessment_id, None)
    finally:
        if org_sem is not None:
            org_sem.release()


async def wait_for(assessment_id: str, timeout: float = 120.0) -> None:
    """Test/utility helper: await a running assessment's completion."""
    task = _running.get(assessment_id)
    if task:
        await asyncio.wait_for(asyncio.shield(task), timeout=timeout)


async def resume_incomplete_assessments() -> list[str]:
    """Recover assessments interrupted mid-run via an **idempotent restart** (not a
    phase-resume): for each non-terminal, not-currently-running assessment, clear its
    partial per-run artifacts, reset to CREATED, and re-enqueue a fresh run. The durable
    `Checkpoint` is read to record which phase was interrupted (audit `from_checkpoint`),
    but the run restarts from the beginning — this is deterministic and safe. True
    resume-from-phase (skipping completed phases, preserving findings) is a future
    enhancement and would pair with a durable LangGraph checkpointer. Returns the list of
    restarted assessment ids. Safe to call on startup.
    """
    sm = get_sessionmaker()
    resumed: list[str] = []
    async with sm() as session:
        stuck = (
            (
                await session.execute(
                    select(Assessment).where(
                        Assessment.state.notin_([s.value for s in TERMINAL_STATES]),
                        Assessment.started_at.isnot(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        targets = [(a.id, a.org_id) for a in stuck if a.id not in _running]

    for aid, org_id in targets:
        async with sm() as session:
            cp = (
                await session.execute(
                    select(Checkpoint).where(Checkpoint.assessment_id == aid)
                )
            ).scalar_one_or_none()
            last_phase = cp.state if cp else "unknown"
            # idempotent restart: clear partial per-run data
            for model in (
                Finding,
                Evidence,
                ValidationResult,
                Coverage,
                PlanStep,
                Job,
                Endpoint,
            ):
                rows = (
                    (
                        await session.execute(
                            select(model).where(model.assessment_id == aid)
                        )
                    )
                    .scalars()
                    .all()
                )
                for r in rows:
                    await session.delete(r)
            a = await session.get(Assessment, aid)
            a.state = AssessmentState.CREATED.value
            a.cancel_requested = False
            a.requests_made = 0
            await write_audit(
                session,
                org_id=org_id,
                assessment_id=aid,
                event="assessment.resumed",
                data={"from_checkpoint": last_phase},
            )
            await session.commit()
        start_assessment(aid)
        resumed.append(aid)
    return resumed


class AssessmentEngine:
    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.settings = get_settings()
        self._sm = get_sessionmaker()

    # ------------------------------------------------------------------ #
    # Phase driver
    # ------------------------------------------------------------------ #
    async def run(self) -> None:
        state = await self._load_state()
        if state is None:
            log.error("assessment %s not found", self.assessment_id)
            return

        await self._set_state(AssessmentState.AUTHORIZED, started=True)
        if await self._cancelled():
            return await self._finish_cancelled()

        # Build a single ScopeGuard + client shared across discovery/exec/validation so
        # budgets and rate limits apply across the whole assessment.
        guard = await self._make_guard()
        precheck = guard.check_record_active()
        if not precheck.allowed:
            return await self.mark_failed(
                f"authorization not usable: {precheck.reason}"
            )

        async with GuardedHttpClient(
            guard, on_request=self._persist_request_count
        ) as client:
            try:
                await self._checkpoint(AssessmentState.DISCOVERING)
                await self._set_state(AssessmentState.DISCOVERING)
                endpoints = await self._phase_discovery(client, guard)
                if await self._cancelled():
                    return await self._finish_cancelled()

                await self._checkpoint(AssessmentState.PLANNING)
                await self._set_state(AssessmentState.PLANNING)
                plan = await self._phase_planning(endpoints)
                if await self._cancelled():
                    return await self._finish_cancelled()

                await self._checkpoint(AssessmentState.POLICY_CHECK)
                await self._set_state(AssessmentState.POLICY_CHECK)
                allowed_steps = await self._phase_policy(guard, plan)
                if await self._cancelled():
                    return await self._finish_cancelled()

                await self._checkpoint(AssessmentState.EXECUTING)
                await self._set_state(AssessmentState.EXECUTING)
                await self._phase_execute(client, guard, allowed_steps)
                if await self._cancelled():
                    return await self._finish_cancelled()

                await self._checkpoint(AssessmentState.VALIDATING)
                await self._set_state(AssessmentState.VALIDATING)
                await self._phase_validate(client, guard)

                await self._checkpoint(AssessmentState.SCORING)
                await self._set_state(AssessmentState.SCORING)
                await self._phase_score()

                await self._checkpoint(AssessmentState.REPORTING)
                await self._set_state(AssessmentState.REPORTING)
                await self._phase_report()

                await self._set_state(AssessmentState.COMPLETED, finished=True)
            except ScopeViolation as exc:
                await self.mark_failed(
                    f"scope violation halted assessment: {exc.reason}"
                )
            except Exception as exc:  # noqa: BLE001
                await self.mark_failed(f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------ #
    # Agent helper: run a single coordinating agent and persist its decisions
    # ------------------------------------------------------------------ #
    async def _run_agent(
        self, agent: Agent, org_id: str, ctx: AgentContext | None = None
    ):
        ctx = ctx or AgentContext(assessment_id=self.assessment_id)
        result = await agent.run(ctx)
        async with self._sm() as session:
            for d in result.decisions:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    actor=agent.id,
                    event="agent.decision",
                    data=d.to_dict(),
                )
            await session.commit()
        return result

    async def _agent_decision(
        self, agent: Agent, org_id: str, task: BrainTask, phase: str
    ):
        """Consult an agent's brain for a single decision and record it to the audit log."""
        decision = await agent._consult(task, phase=phase)
        async with self._sm() as session:
            await write_audit(
                session,
                org_id=org_id,
                assessment_id=self.assessment_id,
                actor=agent.id,
                event="agent.decision",
                data={
                    "phase": phase,
                    "action": decision.action,
                    "brain_source": decision.source,
                    "reasoning": decision.reasoning,
                },
            )
            await session.commit()
        return decision

    # ------------------------------------------------------------------ #
    # Phase: discovery
    # ------------------------------------------------------------------ #
    async def _phase_discovery(
        self, client: GuardedHttpClient, guard: ScopeGuard
    ) -> list[Endpoint]:
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            target = await session.get(Target, assessment.target_id)
            artifacts = (
                (
                    await session.execute(
                        select(DiscoveryArtifact).where(
                            DiscoveryArtifact.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            in_scope_hosts = set(guard.record.allowed_hosts or [])

            discovered: list[DiscoveredEndpoint] = []
            warnings: list[str] = []
            for art in artifacts:
                res = parse_artifact(
                    art.kind,
                    art.content,
                    base_url=target.base_url,
                    in_scope_hosts=in_scope_hosts,
                    endpoint_url=art.endpoint_url or target.base_url,
                )
                discovered.extend(res.endpoints)
                art.parsed = True
                art.warnings = res.warnings
                warnings.extend(res.warnings)
            org_id = assessment.org_id

        # DiscoveryAgent (LLM-brained) decides whether to actively crawl beyond artifacts.
        discovery_agent = DiscoveryAgent(runner=None, brain=get_brain())
        crawl_decision = await self._agent_decision(
            discovery_agent,
            org_id,
            BrainTask(
                role="discovery",
                instruction="Decide whether to actively crawl the target for more endpoints.",
                context={
                    "artifacts": len(artifacts),
                    "endpoints_from_artifacts": len(discovered),
                },
                allowed_actions=["discover", "skip"],
            ),
            phase="discovery",
        )

        # passive crawl (best-effort, scope-enforced) — gated by the discovery agent
        if crawl_decision.action == "skip":
            warnings.append("discovery agent elected to skip active crawl")
        else:
            async with self._sm() as session:
                assessment = await session.get(Assessment, self.assessment_id)
                target = await session.get(Target, assessment.target_id)
                base_url = target.base_url
            try:
                crawl_eps, crawl_warn = await crawl(
                    client, base_url, max_pages=15, max_depth=2
                )
                discovered.extend(crawl_eps)
                warnings.extend(crawl_warn)
            except ScopeViolation as exc:
                warnings.append(f"crawl blocked: {exc.reason}")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"crawl error: {exc}")

        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            # mark artifacts parsed (persist across the split session boundary)
            for art in (
                (
                    await session.execute(
                        select(DiscoveryArtifact).where(
                            DiscoveryArtifact.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            ):
                art.parsed = True
            # Deny-by-default: drop any discovered endpoint whose host is out of scope.
            in_scope: list[DiscoveredEndpoint] = []
            for ep in discovered:
                decision = guard.check_request(ep.method, ep.url)
                # Only host/scope matters for inventory; method/state-change checked at exec.
                host_ok = guard.evaluate_new_asset(_host(ep.url)).allowed
                if host_ok:
                    in_scope.append(ep)
                elif decision.code == "host_out_of_scope":
                    warnings.append(f"excluded out-of-scope asset: {_host(ep.url)}")

            merged = merge_endpoints(in_scope)
            # persist — dedup against any endpoints already present (e.g. traffic ingested
            # before the run via the live-traffic connector, BE-03).
            saved: list[Endpoint] = []
            existing_fps = {
                fp
                for (fp,) in (
                    await session.execute(
                        select(Endpoint.fingerprint).where(
                            Endpoint.assessment_id == self.assessment_id
                        )
                    )
                ).all()
            }
            for ep in merged:
                if ep.fingerprint in existing_fps:
                    continue
                existing_fps.add(ep.fingerprint)
                row = Endpoint(
                    org_id=assessment.org_id,
                    assessment_id=self.assessment_id,
                    method=ep.method,
                    url=ep.url,
                    path_template=ep.path_template,
                    parameters=ep.parameters,
                    request_body_schema=ep.request_body_schema,
                    auth_required=ep.auth_required,
                    roles=ep.roles,
                    api_version=ep.api_version,
                    provenance=ep.provenance.value,
                    confidence=ep.confidence,
                    fingerprint=ep.fingerprint,
                )
                session.add(row)
                saved.append(row)
            await write_audit(
                session,
                org_id=assessment.org_id,
                assessment_id=self.assessment_id,
                event="discovery.completed",
                data={"endpoints": len(saved), "warnings": warnings[:50]},
            )
            await session.commit()
            for r in saved:
                await session.refresh(r)
            return saved

    # ------------------------------------------------------------------ #
    # Phase: planning
    # ------------------------------------------------------------------ #
    async def _phase_planning(self, endpoints: list[Endpoint]) -> list[PlanStep]:
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            record = await session.get(AuthorizationRecord, assessment.authorization_id)
            n_sessions = (
                (
                    await session.execute(
                        select(TestAccount).where(
                            TestAccount.target_id == assessment.target_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            has_multi = len(n_sessions) >= 2

            requested = set(assessment.requested_check_classes or [])
            authorized = set(record.allowed_check_classes or [])
            effective = (requested & authorized) if requested else authorized

            plan_endpoints = endpoints
            incremental_skipped = 0
            # Incremental scan (BE-10): a retest with incremental=true only tests the
            # surface that is NEW or CHANGED vs the previous assessment (by fingerprint).
            if assessment.incremental and assessment.previous_assessment_id:
                prev_fps = {
                    fp
                    for (fp,) in (
                        await session.execute(
                            select(Endpoint.fingerprint).where(
                                Endpoint.assessment_id
                                == assessment.previous_assessment_id
                            )
                        )
                    ).all()
                }
                filtered = [e for e in endpoints if e.fingerprint not in prev_fps]
                incremental_skipped = len(endpoints) - len(filtered)
                plan_endpoints = filtered

            views = [_endpoint_view(e) for e in plan_endpoints]
            org_id = assessment.org_id
            # Runtime-registered declarative checks (AG-09) participate alongside builtins.
            declaratives = await load_declarative_checks(session, org_id)
            planned = await build_plan(
                views,
                authorized_check_classes=effective,
                max_intensity=_coerce_intensity(record.intensity),
                has_multiple_sessions=has_multi,
                extra_checks=declaratives,
            )

        # PlannerAgent (LLM-brained) picks a prioritization strategy over the plan.
        planner = PlannerAgent(brain=get_brain())
        strat = await self._agent_decision(
            planner,
            org_id,
            BrainTask(
                role="planner",
                instruction="Choose a prioritization strategy for the assessment plan.",
                context={"steps": len(planned), "check_classes": sorted(effective)},
                allowed_actions=["coverage-first", "risk-first", "balanced"],
            ),
            phase="planning",
        )
        planned = _apply_strategy(planned, strat.action)

        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            steps: list[PlanStep] = []
            for p in planned:
                step = PlanStep(
                    org_id=assessment.org_id,
                    assessment_id=self.assessment_id,
                    endpoint_id=p.endpoint_id,
                    check_class=p.check_class,
                    check_name=p.check_name,
                    rationale=p.rationale,
                    priority=p.priority,
                    intensity=p.intensity,
                    status="planned",
                )
                session.add(step)
                steps.append(step)
            await write_audit(
                session,
                org_id=assessment.org_id,
                assessment_id=self.assessment_id,
                event="planning.completed",
                data={
                    "steps": len(steps),
                    "incremental_skipped_endpoints": incremental_skipped,
                },
            )
            await session.commit()
            for s in steps:
                await session.refresh(s)
            return steps

    # ------------------------------------------------------------------ #
    # Phase: policy — evaluate each planned step against the authorization record
    # ------------------------------------------------------------------ #
    async def _phase_policy(
        self, guard: ScopeGuard, steps: list[PlanStep]
    ) -> list[PlanStep]:
        allowed: list[PlanStep] = []
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            declaratives = await load_declarative_checks(session, assessment.org_id)
            for step in steps:
                s = await session.get(PlanStep, step.id)
                check = _resolve_check(s.check_name, s.check_class, declaratives)
                if check is None:
                    s.status = "skipped"
                    s.policy_decision = {
                        "allowed": False,
                        "reason": "no check implementation",
                    }
                    continue
                decision = guard.check_class_allowed(s.check_class, check.intensity)
                s.policy_decision = {
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "code": decision.code,
                }
                if decision.allowed:
                    s.status = "approved"
                    allowed.append(s)
                else:
                    s.status = "denied"
            await write_audit(
                session,
                org_id=assessment.org_id,
                assessment_id=self.assessment_id,
                event="policy.evaluated",
                data={"approved": len(allowed), "total": len(steps)},
            )
            await session.commit()
            # reload approved steps detached
            ids = [s.id for s in allowed]
        return await self._reload_steps(ids)

    # ------------------------------------------------------------------ #
    # Phase: execute — run approved steps via LLM-brained specialist agents
    # ------------------------------------------------------------------ #
    async def _phase_execute(
        self, client: GuardedHttpClient, guard: ScopeGuard, steps: list[PlanStep]
    ) -> None:
        if not steps:
            return
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            org_id0 = assessment.org_id

        # CoordinatorAgent (LLM-brained) decides whether to proceed with execution.
        coordinator = CoordinatorAgent(brain=get_brain())
        coord_ctx = AgentContext(
            assessment_id=self.assessment_id,
            budget_remaining_getter=lambda: max(
                0, guard.record.max_requests - guard.requests_made
            ),
        )
        coord_decision = await self._agent_decision(
            coordinator,
            org_id0,
            BrainTask(
                role="coordinator",
                instruction="Decide whether to continue into execution, stop, or replan.",
                context={
                    "approved_steps": len(steps),
                    "budget_remaining": coord_ctx.budget_remaining(),
                },
                allowed_actions=["continue", "stop", "replan"],
            ),
            phase="coordinate",
        )
        if coord_decision.action == "stop":
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id0,
                    assessment_id=self.assessment_id,
                    event="execution.skipped",
                    data={"reason": "coordinator elected to stop"},
                )
                await session.commit()
            return

        sessions = await self._build_sessions()

        # Execution controller: wall-clock deadline (EX-05) + target-health (AU-08) + cancel.
        deadline = time.monotonic() + min(
            guard.record.max_duration_seconds or self.settings.max_assessment_seconds,
            self.settings.max_assessment_seconds,
        )
        controller = _ExecController(deadline=deadline, client=client)
        pool = AgentPool(
            # Bounded true parallelism (AG-04); httpx AsyncClient is concurrency-safe and
            # the rate limiter + budget guard still bound total load.
            max_concurrency=max(1, self.settings.execution_concurrency),
            per_agent_timeout=self.settings.max_assessment_seconds,
            cancel_predicate=controller.should_stop,
        )
        brain = get_brain()

        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            org_id = assessment.org_id
            declaratives = await load_declarative_checks(session, org_id)

        # Build one agent per approved step. This is where 100+ agents materialize.
        agents = []
        step_by_agent: dict[str, PlanStep] = {}
        endpoint_cache: dict[str, EndpointView] = {}
        for step in steps:
            ev = endpoint_cache.get(step.endpoint_id)
            if ev is None:
                ev = await self._endpoint_view_by_id(step.endpoint_id)
                endpoint_cache[step.endpoint_id] = ev
            if ev is None:
                continue
            check = _resolve_check(step.check_name, step.check_class, declaratives)
            if check is None:
                continue
            cctx = CheckContext(
                client=client,
                endpoint=_clone_view(ev),
                intensity=check.intensity,
                base_url=ev.url,
                sessions=sessions,
            )
            # Capability-based routing (AG-04): select the agent advertising the
            # 'security-check' capability rather than hard-coding the class.
            agent_cls = (
                capability_router.select("security-check") or SpecialistCheckAgent
            )
            agent = agent_cls(
                check, cctx, brain=brain, max_steps=self.settings.max_recursion_depth
            )
            agents.append(agent)
            step_by_agent[agent.id] = step

        # A2A bus (used in the live path): specialists publish finding signals; the
        # coordinator consumes them below to inform replanning.
        from app.agents.a2a import MessageBus

        bus = MessageBus()
        findings_queue = await bus.subscribe("findings")
        ctx = AgentContext(
            assessment_id=self.assessment_id,
            budget_remaining_getter=lambda: max(
                0, guard.record.max_requests - guard.requests_made
            ),
            extra={"bus": bus},
        )

        # Stream results so we can honor cancellation/deadline/health mid-execution.
        errored: list[str] = []
        stop_reason = ""
        async for result in pool.run_streaming(agents, ctx):
            if await self._cancelled():
                controller.cancelled = True
                stop_reason = "cancelled"
                break
            if time.monotonic() > deadline:
                controller.cancelled = True
                stop_reason = "deadline_exceeded"
                break
            if client.unhealthy:
                controller.cancelled = True
                stop_reason = "target_unhealthy"
                break
            step = step_by_agent.get(result.agent_id)
            await self._persist_agent_result(org_id, step, result, attempts=1)
            if result.error:
                errored.append(result.agent_id)

        # Bounded retries with backoff for transient step failures (EX-09).
        agent_by_id = {a.id: a for a in agents}
        for attempt in range(2, self.settings.max_step_retries + 2):
            if not errored or controller.should_stop() or await self._cancelled():
                break
            retry_ids, errored = errored, []
            for aid in retry_ids:
                agent = agent_by_id.get(aid)
                if agent is None:
                    continue
                await asyncio.sleep(0.05 * attempt)  # linear backoff
                res = await agent.run(ctx)
                await self._persist_agent_result(
                    org_id, step_by_agent.get(aid), res, attempts=attempt
                )
                if res.error:
                    errored.append(aid)

        if stop_reason:
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    event="execution.stopped",
                    data={
                        "reason": stop_reason,
                        "health_errors": client.consecutive_errors,
                    },
                )
                await session.commit()

        # Consume the A2A bus: coordinator-side aggregation of finding signals (F-05).
        signals = []
        while not findings_queue.empty():
            try:
                signals.append(findings_queue.get_nowait())
            except Exception:  # noqa: BLE001
                break
        if signals:
            sev_counts: dict[str, int] = {}
            for m in signals:
                sev = str(m.payload.get("severity", "unknown"))
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    actor="coordinator",
                    event="a2a.finding_signals",
                    data={"messages": len(signals), "by_severity": sev_counts},
                )
                await session.commit()

        # Progress-aware replanning (EX-09): bounded extra passes to close coverage gaps.
        if not stop_reason:
            await self._maybe_replan(
                client, guard, sessions, brain, org_id, declaratives, controller
            )

        async with self._sm() as session:
            await write_audit(
                session,
                org_id=org_id,
                assessment_id=self.assessment_id,
                event="execution.completed",
                data={
                    "agents": pool.stats.instantiated,
                    "findings": pool.stats.findings,
                    "brain_sources": pool.stats.brain_sources,
                    "by_role": pool.stats.by_role,
                },
            )
            assessment = await session.get(Assessment, self.assessment_id)
            summary = dict(assessment.summary or {})
            summary["agents_instantiated"] = pool.stats.instantiated
            summary["brain_sources"] = pool.stats.brain_sources
            assessment.summary = summary
            await session.commit()

    async def _maybe_replan(
        self, client, guard, sessions, brain, org_id, declaratives, controller
    ) -> None:
        """Bounded, coverage-gap-driven replanning with a clear stop condition (EX-09).

        After the main pass, if authorized (endpoint × check) pairs remain untested and
        budget/time allow, the coordinator is consulted and a bounded batch of the gaps is
        scheduled and executed — progressively increasing coverage instead of leaving
        untested pairs (which must never read as 'secure')."""
        for iteration in range(self.settings.max_replans):
            if controller.should_stop() or await self._cancelled():
                return
            if (
                guard.record.max_requests
                and guard.requests_made >= guard.record.max_requests
            ):
                return

            async with self._sm() as session:
                assessment = await session.get(Assessment, self.assessment_id)
                record = await session.get(
                    AuthorizationRecord, assessment.authorization_id
                )
                endpoints = (
                    (
                        await session.execute(
                            select(Endpoint).where(
                                Endpoint.assessment_id == self.assessment_id
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                done_pairs = {
                    (s.endpoint_id, s.check_class)
                    for s in (
                        await session.execute(
                            select(PlanStep).where(
                                PlanStep.assessment_id == self.assessment_id,
                                PlanStep.status == "done",
                            )
                        )
                    )
                    .scalars()
                    .all()
                }
                authorized = set(record.allowed_check_classes or [])
                endpoint_views = {e.id: _endpoint_view(e) for e in endpoints}

            # compute authorized+applicable coverage gaps
            gaps: list[tuple[str, str, str]] = []
            for eid, ev in endpoint_views.items():
                for cclass in authorized:
                    if (eid, cclass) in done_pairs:
                        continue
                    check = _resolve_check("", cclass, declaratives)
                    if check is None:
                        continue
                    if not guard.check_class_allowed(cclass, check.intensity).allowed:
                        continue
                    gaps.append((eid, cclass, check.name))
            if not gaps:
                return

            coordinator = CoordinatorAgent(brain=brain)
            decision = await self._agent_decision(
                coordinator,
                org_id,
                BrainTask(
                    role="coordinator",
                    instruction="Replan to close coverage gaps, or stop.",
                    context={
                        "gaps": len(gaps),
                        "budget_remaining": max(
                            0, guard.record.max_requests - guard.requests_made
                        ),
                    },
                    allowed_actions=["replan", "stop"],
                ),
                phase="replan",
            )
            if (
                decision.action == "stop"
                and not self.settings.auto_replan_on_coverage_gap
            ):
                return

            batch = gaps[: self.settings.replan_batch]
            async with self._sm() as session:
                new_steps: list[PlanStep] = []
                for eid, cclass, cname in batch:
                    resolved = _resolve_check(cname, cclass, declaratives)
                    step_intensity = resolved.intensity.value if resolved else "passive"
                    s = PlanStep(
                        org_id=org_id,
                        assessment_id=self.assessment_id,
                        endpoint_id=eid,
                        check_class=cclass,
                        check_name=cname,
                        rationale="replan: coverage gap",
                        priority=1,
                        intensity=step_intensity,
                        status="approved",
                    )
                    session.add(s)
                    new_steps.append(s)
                await session.commit()
                for s in new_steps:
                    await session.refresh(s)
                    session.expunge(s)

            found = await self._execute_step_batch(
                client,
                guard,
                new_steps,
                sessions,
                brain,
                org_id,
                declaratives,
                controller,
            )
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    event="execution.replanned",
                    data={
                        "iteration": iteration + 1,
                        "gap_steps": len(batch),
                        "new_findings": found,
                    },
                )
                await session.commit()

    async def _execute_step_batch(
        self, client, guard, steps, sessions, brain, org_id, declaratives, controller
    ) -> int:
        """Build agents for a batch of steps, run them under the pool, persist results.
        Returns the number of findings produced."""
        agents = []
        step_by_agent: dict[str, PlanStep] = {}
        cache: dict[str, EndpointView] = {}
        for step in steps:
            ev = cache.get(step.endpoint_id)
            if ev is None:
                ev = await self._endpoint_view_by_id(step.endpoint_id)
                cache[step.endpoint_id] = ev
            if ev is None:
                continue
            check = _resolve_check(step.check_name, step.check_class, declaratives)
            if check is None:
                continue
            cctx = CheckContext(
                client=client,
                endpoint=_clone_view(ev),
                intensity=check.intensity,
                base_url=ev.url,
                sessions=sessions,
            )
            agent_cls = (
                capability_router.select("security-check") or SpecialistCheckAgent
            )
            agents.append(
                agent_cls(
                    check,
                    cctx,
                    brain=brain,
                    max_steps=self.settings.max_recursion_depth,
                )
            )
            step_by_agent[agents[-1].id] = step
        if not agents:
            return 0
        pool = AgentPool(
            max_concurrency=max(1, self.settings.execution_concurrency),
            per_agent_timeout=self.settings.max_assessment_seconds,
            cancel_predicate=controller.should_stop,
        )
        ctx = AgentContext(
            assessment_id=self.assessment_id,
            budget_remaining_getter=lambda: max(
                0, guard.record.max_requests - guard.requests_made
            ),
        )
        async for result in pool.run_streaming(agents, ctx):
            if controller.should_stop() or await self._cancelled():
                break
            await self._persist_agent_result(
                org_id, step_by_agent.get(result.agent_id), result, attempts=1
            )
        return pool.stats.findings

    async def _persist_agent_result(
        self, org_id: str, step: PlanStep | None, result, attempts: int = 1
    ) -> None:
        async with self._sm() as session:
            job = Job(
                org_id=org_id,
                assessment_id=self.assessment_id,
                plan_step_id=step.id if step else "",
                idempotency_key=f"{self.assessment_id}:{result.agent_id}:{attempts}",
                state=JobState.FAILED.value
                if result.error
                else JobState.SUCCEEDED.value,
                attempts=attempts,
                error=result.error,
                result={
                    "findings": len(result.findings),
                    "decisions": [d.to_dict() for d in result.decisions],
                },
            )
            session.add(job)
            if step:
                s = await session.get(PlanStep, step.id)
                if s:
                    s.status = "errored" if result.error else "done"
            # decisions → audit lineage
            for d in result.decisions:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    actor=result.agent_id,
                    event="agent.decision",
                    data=d.to_dict(),
                )
            for rf in result.findings:
                await self._persist_finding(session, org_id, step, rf)
            await session.commit()

    async def _persist_finding(
        self, session: AsyncSession, org_id: str, step: PlanStep | None, rf: RawFinding
    ) -> None:
        endpoint_id = step.endpoint_id if step else None
        endpoint_fp = ""
        if endpoint_id:
            ep = await session.get(Endpoint, endpoint_id)
            endpoint_fp = ep.fingerprint if ep else ""
        dedup_key = rf.dedup_key(endpoint_fp)
        # dedup within assessment
        existing = (
            await session.execute(
                select(Finding).where(
                    Finding.assessment_id == self.assessment_id,
                    Finding.dedup_key == dedup_key,
                )
            )
        ).scalar_one_or_none()
        if existing:
            return
        finding = Finding(
            org_id=org_id,
            assessment_id=self.assessment_id,
            endpoint_id=endpoint_id,
            check_class=rf.check_class,
            title=rf.title,
            severity=rf.severity.value,
            confidence=rf.confidence.value,
            status=FindingStatus.SUSPECTED.value,
            cwe=rf.cwe,
            description=rf.description,
            remediation=rf.remediation,
            dedup_key=dedup_key,
            reproduction=rf.reproduction,
        )
        session.add(finding)
        await session.flush()
        for ev in rf.evidence:
            session.add(
                Evidence(
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    finding_id=finding.id,
                    kind=ev.kind,
                    request=ev.request,
                    response=ev.response,
                    note=ev.note,
                    lineage={
                        "agent_step": step.id if step else None,
                        "check_class": rf.check_class,
                    },
                )
            )

    # ------------------------------------------------------------------ #
    # Phase: validate — independent re-proof via ValidationAgents
    # ------------------------------------------------------------------ #
    async def _phase_validate(
        self, client: GuardedHttpClient, guard: ScopeGuard
    ) -> None:
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            org_id = assessment.org_id
            findings = (
                (
                    await session.execute(
                        select(Finding).where(
                            Finding.assessment_id == self.assessment_id,
                            Finding.status == FindingStatus.SUSPECTED.value,
                        )
                    )
                )
                .scalars()
                .all()
            )
            finding_data = [
                (f.id, f.check_class, dict(f.reproduction or {})) for f in findings
            ]

        brain = get_brain()
        for fid, cclass, repro in finding_data:
            if await self._cancelled():
                break
            agent = ValidationAgent(
                validator_coro=lambda c=cclass, r=repro: validate_finding(
                    client, check_class=c, reproduction=r
                ),
                brain=brain,
            )
            ctx = AgentContext(assessment_id=self.assessment_id)
            try:
                outcome = await agent.validate(ctx)
            except Exception as exc:  # noqa: BLE001
                outcome = None
                log.warning("validation error for %s: %s", fid, exc)
            async with self._sm() as session:
                finding = await session.get(Finding, fid)
                if outcome is None:
                    finding.status = FindingStatus.INCONCLUSIVE.value
                    detail = "validator raised an error"
                    ev_id = None
                    method = "error"
                    outcome_val = FindingStatus.INCONCLUSIVE.value
                else:
                    finding.status = outcome.outcome.value
                    detail = outcome.detail
                    method = outcome.method
                    outcome_val = outcome.outcome.value
                    ev_id = None
                    if outcome.evidence:
                        ev = Evidence(
                            org_id=org_id,
                            assessment_id=self.assessment_id,
                            finding_id=fid,
                            kind="validation",
                            request=outcome.evidence.get("request", {}),
                            response=outcome.evidence.get("response", {}),
                            note=f"independent validation: {method}",
                            lineage={"phase": "validation", "agent": agent.id},
                        )
                        session.add(ev)
                        await session.flush()
                        ev_id = ev.id
                session.add(
                    ValidationResult(
                        org_id=org_id,
                        assessment_id=self.assessment_id,
                        finding_id=fid,
                        outcome=outcome_val,
                        method=method,
                        detail=detail,
                        evidence_id=ev_id,
                    )
                )
                for d in agent._decisions:
                    await write_audit(
                        session,
                        org_id=org_id,
                        assessment_id=self.assessment_id,
                        actor=agent.id,
                        event="agent.decision",
                        data=d.to_dict(),
                    )
                await session.commit()

    # ------------------------------------------------------------------ #
    # Phase: score — per-finding + assessment risk, plus coverage
    # ------------------------------------------------------------------ #
    async def _apply_known_false_positives(self) -> int:
        """Read project memory (AG-MEM) and auto-reject findings a prior assessment marked
        as false positives for this target (matched by dedup_key). Returns the count."""
        from app.models import ProjectMemory

        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            fp_rows = (
                (
                    await session.execute(
                        select(ProjectMemory).where(
                            ProjectMemory.org_id == assessment.org_id,
                            ProjectMemory.target_id == assessment.target_id,
                            ProjectMemory.kind == "false_positive",
                        )
                    )
                )
                .scalars()
                .all()
            )
            known_keys = {
                r.key[len("known_fp:") :]
                for r in fp_rows
                if r.key.startswith("known_fp:")
            }
            if not known_keys:
                return 0
            findings = (
                (
                    await session.execute(
                        select(Finding).where(
                            Finding.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            suppressed = 0
            for f in findings:
                if (
                    f.dedup_key in known_keys
                    and f.status != FindingStatus.REJECTED.value
                ):
                    f.status = FindingStatus.REJECTED.value
                    suppressed += 1
            if suppressed:
                await write_audit(
                    session,
                    org_id=assessment.org_id,
                    assessment_id=self.assessment_id,
                    event="findings.known_fp_suppressed",
                    data={"count": suppressed},
                )
            await session.commit()
            return suppressed

    async def _phase_score(self) -> None:
        await self._apply_known_false_positives()
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            record = await session.get(AuthorizationRecord, assessment.authorization_id)
            org_id = assessment.org_id
            endpoints = (
                (
                    await session.execute(
                        select(Endpoint).where(
                            Endpoint.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            findings = (
                (
                    await session.execute(
                        select(Finding).where(
                            Finding.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            steps = (
                (
                    await session.execute(
                        select(PlanStep).where(
                            PlanStep.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )

            ep_by_id = {e.id: e for e in endpoints}
            for f in findings:
                ep = ep_by_id.get(f.endpoint_id)
                res = scoring.score_finding(
                    severity=f.severity,
                    confidence=f.confidence,
                    status=f.status,
                    auth_required=ep.auth_required if ep else False,
                    exposure_env=record.environment,
                )
                # drop rejected/fixed to floor
                f.risk_score = res.score
                f.risk_breakdown = res.breakdown
                r = build_remediation(f.check_class, f.severity)
                if not f.remediation:
                    f.remediation = r.summary

            # coverage: endpoint × approved-check pairs
            approved_pairs = {
                (s.endpoint_id, s.check_class)
                for s in steps
                if s.status in ("done", "approved", "errored")
            }
            done_pairs = {
                (s.endpoint_id, s.check_class) for s in steps if s.status == "done"
            }
            # denominator: every endpoint × every authorized check class
            authorized = set(record.allowed_check_classes or []) or set(
                check_registry.classes()
            )
            existing_cov = (
                (
                    await session.execute(
                        select(Coverage).where(
                            Coverage.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            if not existing_cov:
                for e in endpoints:
                    for cclass in authorized:
                        tested = (e.id, cclass) in done_pairs
                        session.add(
                            Coverage(
                                org_id=org_id,
                                assessment_id=self.assessment_id,
                                endpoint_id=e.id,
                                check_class=cclass,
                                tested=tested,
                                reason_untested=""
                                if tested
                                else _untested_reason(e.id, cclass, approved_pairs),
                            )
                        )

            tested_endpoints = len({eid for (eid, _c) in done_pairs})
            risk = scoring.score_assessment(
                finding_scores=[
                    f.risk_score
                    for f in findings
                    if f.status in ("confirmed", "suspected", "regressed")
                ],
                finding_statuses=[f.status for f in findings],
                tested_endpoints=tested_endpoints,
                total_endpoints=len(endpoints),
            )
            summary = dict(assessment.summary or {})
            summary["risk"] = {
                "overall_score": risk.overall_score,
                "grade": risk.grade,
                "coverage_ratio": risk.coverage_ratio,
                "uncertainty": risk.uncertainty,
                "tested_endpoints": risk.tested_endpoints,
                "total_endpoints": risk.total_endpoints,
                "confirmed": risk.confirmed,
                "suspected": risk.suspected,
                "breakdown": risk.breakdown,
            }
            assessment.summary = summary
            await write_audit(
                session,
                org_id=org_id,
                assessment_id=self.assessment_id,
                event="scoring.completed",
                data=summary["risk"],
            )
            await session.commit()

    async def _phase_report(self) -> None:
        # Report is generated on-demand by the reporting router from persisted state;
        # a ReporterAgent records the render decision, then we mark report-ready.
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            org_id = assessment.org_id
        reporter = ReporterAgent(brain=get_brain())
        await self._agent_decision(
            reporter,
            org_id,
            BrainTask(
                role="reporter",
                instruction="Render the assessment report.",
                context={"assessment_id": self.assessment_id},
                allowed_actions=["render"],
            ),
            phase="report",
        )
        async with self._sm() as session:
            await write_audit(
                session,
                org_id=org_id,
                assessment_id=self.assessment_id,
                event="reporting.ready",
                data={},
            )
            await session.commit()

    # ------------------------------------------------------------------ #
    # helpers: state, checkpoints, cancellation, guard, sessions
    # ------------------------------------------------------------------ #
    async def _load_state(self) -> Assessment | None:
        async with self._sm() as session:
            return await session.get(Assessment, self.assessment_id)

    async def _set_state(
        self, state: AssessmentState, *, started: bool = False, finished: bool = False
    ) -> None:
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            if a is None:
                return
            a.state = state.value
            if started and a.started_at is None:
                a.started_at = datetime.now(UTC)
            if finished:
                a.finished_at = datetime.now(UTC)
            await write_audit(
                session,
                org_id=a.org_id,
                assessment_id=self.assessment_id,
                event="state.transition",
                data={"state": state.value},
            )
            await session.commit()

    async def _checkpoint(
        self, next_state: AssessmentState, cursor: dict | None = None
    ) -> None:
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            cp = (
                await session.execute(
                    select(Checkpoint).where(
                        Checkpoint.assessment_id == self.assessment_id
                    )
                )
            ).scalar_one_or_none()
            if cp is None:
                cp = Checkpoint(
                    org_id=a.org_id,
                    assessment_id=self.assessment_id,
                    state=next_state.value,
                    cursor=cursor or {},
                )
                session.add(cp)
            else:
                cp.state = next_state.value
                cp.cursor = cursor or {}
            await session.commit()

    async def _cancelled(self) -> bool:
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            return bool(a and a.cancel_requested)

    async def _finish_cancelled(self) -> None:
        await self._set_state(AssessmentState.CANCELLED, finished=True)
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            await write_audit(
                session,
                org_id=a.org_id,
                assessment_id=self.assessment_id,
                event="assessment.cancelled",
                data={},
            )
            await session.commit()

    async def mark_failed(self, error: str) -> None:
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            if a is None:
                return
            a.state = AssessmentState.FAILED.value
            a.error = error
            a.finished_at = datetime.now(UTC)
            await write_audit(
                session,
                org_id=a.org_id,
                assessment_id=self.assessment_id,
                event="assessment.failed",
                data={"error": error},
            )
            await session.commit()

    async def _make_guard(self) -> ScopeGuard:
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            record = await session.get(AuthorizationRecord, a.authorization_id)
            return ScopeGuard(record, requests_made=a.requests_made or 0)

    async def _persist_request_count(self, count: int) -> None:
        # lightweight periodic persistence of the running request counter
        if count % 10 != 0:
            return
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            if a:
                a.requests_made = count
                await session.commit()

    async def _persist_exact_count(self, count: int) -> None:
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            if a:
                a.requests_made = count
                await session.commit()

    # ------------------------------------------------------------------ #
    # Graph-friendly node wrappers: each network phase manages its own
    # short-lived guarded client (budget reloaded from / persisted to the DB).
    # These are what the LangGraph runner (app/graph.py) invokes as nodes.
    # ------------------------------------------------------------------ #
    async def node_authorize(self) -> str:
        await self._set_state(AssessmentState.AUTHORIZED, started=True)
        guard = await self._make_guard()
        precheck = guard.check_record_active()
        return "ok" if precheck.allowed else precheck.reason

    async def node_discover(self) -> None:
        await self._checkpoint(AssessmentState.DISCOVERING)
        await self._set_state(AssessmentState.DISCOVERING)
        guard = await self._make_guard()
        async with GuardedHttpClient(
            guard, on_request=self._persist_request_count
        ) as client:
            await self._phase_discovery(client, guard)
        await self._persist_exact_count(guard.requests_made)

    async def node_plan(self) -> None:
        await self._checkpoint(AssessmentState.PLANNING)
        await self._set_state(AssessmentState.PLANNING)
        async with self._sm() as session:
            endpoints = (
                (
                    await session.execute(
                        select(Endpoint).where(
                            Endpoint.assessment_id == self.assessment_id
                        )
                    )
                )
                .scalars()
                .all()
            )
            for e in endpoints:
                session.expunge(e)
        await self._phase_planning(endpoints)

    async def node_policy(self) -> None:
        await self._checkpoint(AssessmentState.POLICY_CHECK)
        await self._set_state(AssessmentState.POLICY_CHECK)
        guard = await self._make_guard()
        async with self._sm() as session:
            steps = (
                (
                    await session.execute(
                        select(PlanStep).where(
                            PlanStep.assessment_id == self.assessment_id,
                            PlanStep.status == "planned",
                        )
                    )
                )
                .scalars()
                .all()
            )
            for s in steps:
                session.expunge(s)
        await self._phase_policy(guard, steps)

    async def node_execute(self) -> None:
        await self._checkpoint(AssessmentState.EXECUTING)
        await self._set_state(AssessmentState.EXECUTING)
        guard = await self._make_guard()
        async with self._sm() as session:
            steps = (
                (
                    await session.execute(
                        select(PlanStep).where(
                            PlanStep.assessment_id == self.assessment_id,
                            PlanStep.status == "approved",
                        )
                    )
                )
                .scalars()
                .all()
            )
            for s in steps:
                session.expunge(s)
        async with GuardedHttpClient(
            guard, on_request=self._persist_request_count
        ) as client:
            await self._phase_execute(client, guard, steps)
        await self._persist_exact_count(guard.requests_made)

    async def node_validate(self) -> None:
        await self._checkpoint(AssessmentState.VALIDATING)
        await self._set_state(AssessmentState.VALIDATING)
        guard = await self._make_guard()
        async with GuardedHttpClient(
            guard, on_request=self._persist_request_count
        ) as client:
            await self._phase_validate(client, guard)
        await self._persist_exact_count(guard.requests_made)

    async def node_score(self) -> None:
        await self._checkpoint(AssessmentState.SCORING)
        await self._set_state(AssessmentState.SCORING)
        await self._phase_score()

    async def node_report(self) -> None:
        await self._checkpoint(AssessmentState.REPORTING)
        await self._set_state(AssessmentState.REPORTING)
        await self._phase_report()
        await self._set_state(AssessmentState.COMPLETED, finished=True)

    async def _build_sessions(self):
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            accounts = (
                (
                    await session.execute(
                        select(TestAccount).where(TestAccount.target_id == a.target_id)
                    )
                )
                .scalars()
                .all()
            )
        out = []
        for acc in accounts:
            state = await establish_session(acc)
            auth = state.to_auth_session()
            # BE-06: if the session came back already expired/failed, attempt one renewal.
            if auth.expired and state.status != "pending_mfa":
                renewed = await establish_session(acc)
                renewed_auth = renewed.to_auth_session()
                if not renewed_auth.expired:
                    auth = renewed_auth
                    async with self._sm() as session:
                        a = await session.get(Assessment, self.assessment_id)
                        await write_audit(
                            session,
                            org_id=a.org_id,
                            assessment_id=self.assessment_id,
                            event="session.renewed",
                            data={"role": acc.role_name, "label": acc.label},
                        )
                        await session.commit()
            out.append(auth)
        return out

    async def _reload_steps(self, ids: list[str]) -> list[PlanStep]:
        if not ids:
            return []
        async with self._sm() as session:
            rows = (
                (await session.execute(select(PlanStep).where(PlanStep.id.in_(ids))))
                .scalars()
                .all()
            )
            # detach copies with needed attrs
            for r in rows:
                session.expunge(r)
            return list(rows)

    async def _endpoint_view_by_id(self, endpoint_id: str) -> EndpointView | None:
        async with self._sm() as session:
            e = await session.get(Endpoint, endpoint_id)
            return _endpoint_view(e) if e else None


# --------------------------------------------------------------------------- #
# module helpers
# --------------------------------------------------------------------------- #
def _endpoint_view(e: Endpoint) -> EndpointView:
    return EndpointView(
        id=e.id,
        method=e.method,
        url=e.url,
        path_template=e.path_template,
        parameters=list(e.parameters or []),
        request_body_schema=dict(e.request_body_schema or {}),
        auth_required=e.auth_required,
        fingerprint=e.fingerprint,
    )


def _clone_view(ev: EndpointView) -> EndpointView:
    return EndpointView(
        id=ev.id,
        method=ev.method,
        url=ev.url,
        path_template=ev.path_template,
        parameters=[dict(p) for p in ev.parameters],
        request_body_schema=dict(ev.request_body_schema),
        auth_required=ev.auth_required,
        fingerprint=ev.fingerprint,
    )


@dataclass
class _ExecController:
    """Sync stop-predicate source for the agent pool: deadline + health + cancel flag."""

    deadline: float
    client: GuardedHttpClient
    cancelled: bool = False

    def should_stop(self) -> bool:
        if self.cancelled:
            return True
        if time.monotonic() > self.deadline:
            return True
        return self.client.unhealthy


def _pick_check(check_class: str):
    checks = check_registry.by_class(check_class)
    return checks[0] if checks else None


def _resolve_check(check_name: str, check_class: str, declaratives: list):
    """Resolve the exact check to run for a plan step: by name (built-in or declarative),
    falling back to the first built-in of the class."""
    if check_name:
        builtin = check_registry.get(check_name)
        if builtin is not None:
            return builtin
        for d in declaratives:
            if getattr(d, "name", None) == check_name:
                return d
    return _pick_check(check_class)


def _apply_strategy(planned, strategy: str):
    """Re-order the deterministic plan per the planner agent's chosen strategy.

    The strategy can only reorder among already-authorized steps; it cannot add steps
    or change scope. 'risk-first' pushes high-impact classes up; 'coverage-first' keeps
    the breadth-oriented default; 'balanced' interleaves.
    """
    risk_weight = {
        "sqli": 5,
        "bola": 5,
        "xss": 4,
        "open_redirect": 3,
        "security_headers": 1,
        "info_disclosure": 1,
    }
    if strategy == "risk-first":
        return sorted(
            planned,
            key=lambda s: (risk_weight.get(s.check_class, 2), s.priority),
            reverse=True,
        )
    if strategy == "coverage-first":
        return sorted(planned, key=lambda s: (s.endpoint_id, -s.priority))
    return sorted(planned, key=lambda s: s.priority, reverse=True)  # balanced/default


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or "").lower()


def _coerce_intensity(value: str) -> TestIntensity:
    try:
        return TestIntensity(value)
    except ValueError:
        return TestIntensity.PASSIVE


def _untested_reason(endpoint_id: str, cclass: str, approved_pairs: set) -> str:
    if (endpoint_id, cclass) in approved_pairs:
        return "planned but not completed"
    return "not planned (heuristics/scope) — UNKNOWN risk, not confirmed-safe"
