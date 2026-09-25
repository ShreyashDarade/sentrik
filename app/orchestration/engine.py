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

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import Agent, AgentContext
from app.agents.brain import BrainTask, get_brain
from app.agents.budget import (
    LlmBudget,
    reset_current_budget,
    set_current_budget,
)
from app.agents.pool import AgentPool
from app.agents.registry import (
    checks_from_snapshot,
    load_declarative_checks,
    snapshot_specs,
)
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
from app.discovery.normalize import (
    DiscoveredEndpoint,
    endpoint_surface_signature,
    merge_endpoints,
)
from app.discovery.parsers import parse_artifact
from app.orchestration.hooks import hooks
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
from app.security.scope import ScopeDecision, ScopeGuard, ScopeViolation
from app.services import scoring
from app.services.audit import write_audit
from app.services.planning import build_plan
from app.services.remediation import build_remediation
from app.services.sessions import establish_session
from app.services.validation import validate_finding

log = logging.getLogger("sentrik.orchestrator")

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
    """Fire-and-forget launch. Idempotent: ignores an already-running assessment.

    In LangGraph mode this also *resumes* a parked or interrupted thread (B-03/B-04):
    ``run_via_langgraph`` inspects the checkpointer and continues from the pending node.
    """
    if assessment_id in _running and not _running[assessment_id].done():
        return
    task = asyncio.create_task(_supervise(assessment_id))
    _running[assessment_id] = task


def is_running(assessment_id: str) -> bool:
    task = _running.get(assessment_id)
    return bool(task and not task.done())


def start_approved_steps(assessment_id: str, step_ids: list[str]) -> None:
    """Fire-and-forget execution of steps approved *after* the run finished (CP-03)."""
    key = f"{assessment_id}:steps:{','.join(sorted(step_ids))}"
    if key in _running and not _running[key].done():
        return

    async def _go() -> None:
        try:
            async with _sem():
                await AssessmentEngine(assessment_id).execute_approved_steps(step_ids)
        except Exception:  # noqa: BLE001
            log.exception("approved-step execution failed for %s", assessment_id)
        finally:
            _running.pop(key, None)

    _running[key] = asyncio.create_task(_go())


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

    # B-03: LangGraph mode — a thread with pending nodes (crash mid-run, or parked on
    # an approval interrupt) is *continued* from its checkpoint, data intact.
    settings = get_settings()
    if settings.use_langgraph:
        from app.orchestration.graph import LANGGRAPH_AVAILABLE, pending_nodes

        if LANGGRAPH_AVAILABLE:
            remaining = []
            for aid, org_id in targets:
                pending = await pending_nodes(aid)
                if not pending:
                    remaining.append((aid, org_id))
                    continue
                async with sm() as session:
                    await write_audit(
                        session,
                        org_id=org_id,
                        assessment_id=aid,
                        event="assessment.resumed",
                        data={"mode": "checkpoint", "next": pending},
                    )
                    await session.commit()
                start_assessment(aid)
                resumed.append(aid)
            targets = remaining

    for aid, org_id in targets:
        async with sm() as session:
            cp = (
                await session.execute(
                    select(Checkpoint).where(Checkpoint.assessment_id == aid)
                )
            ).scalar_one_or_none()
            last_phase = cp.state if cp else "unknown"
            # idempotent restart: clear partial per-run data
            # Delete FK children before parents (SQLite runs with foreign_keys=ON and the
            # ORM delete does not cascade): Evidence/ValidationResult reference Finding;
            # Finding/PlanStep/Coverage reference Endpoint.
            for model in (
                Evidence,
                ValidationResult,
                Coverage,
                Job,
                PlanStep,
                Finding,
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
                data={"mode": "restart", "from_checkpoint": last_phase},
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
        # F-09: per-assessment LLM token/cost ledger. 0 ⇒ unbounded for that dimension.
        self.llm_budget = LlmBudget(
            max_tokens=self.settings.max_llm_tokens_per_assessment,
            max_cost_usd=self.settings.max_llm_cost_usd_per_assessment,
            cost_per_1k_tokens_usd=self.settings.llm_cost_per_1k_tokens_usd,
        )
        # E-03: why execution did (not) happen; folded into `completion_reason`.
        self._exec_note = ""
        # H-02: check_name -> skill_ref for the declarative checks this run executes.
        self._skill_refs: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # H-02: declarative checks are frozen per run
    # ------------------------------------------------------------------ #
    async def _declaratives(self, session: AsyncSession, org_id: str | None):
        """Return the declarative checks this run executes.

        The first call (planning) loads the registry and freezes the runnable specs on
        the assessment (`skill_snapshot`); every later phase — including approved-step
        execution after completion and a resumed run — rebuilds the checks from that
        snapshot, so a registry change mid-run cannot alter a running assessment.
        """
        assessment = await session.get(Assessment, self.assessment_id)
        snapshot = list(assessment.skill_snapshot or []) if assessment else []
        if snapshot:
            checks = checks_from_snapshot(snapshot)
        else:
            checks = await load_declarative_checks(session, org_id)
            if assessment is not None:
                assessment.skill_snapshot = snapshot_specs(checks)
                # Commit now: the calling phase may otherwise close its session
                # without committing (planning is read-mostly).
                await session.commit()
        self._skill_refs = {
            c.name: str(c.manifest.get("skill_ref", "")) for c in checks
        }
        return checks

    def _skill_ref_for(self, check_name: str) -> str:
        if not check_name:
            return ""
        if check_registry.get(check_name) is not None:
            return f"{check_name}@builtin#{__import__('app').__version__}"
        return self._skill_refs.get(check_name, f"{check_name}@?#unknown")

    # ------------------------------------------------------------------ #
    # Phase driver
    # ------------------------------------------------------------------ #
    async def run(self) -> None:
        # F-09: install this assessment's token/cost ledger for the whole coroutine tree.
        # asyncio.create_task copies the context, so pool child tasks inherit the ledger.
        budget_token = set_current_budget(self.llm_budget)
        try:
            await self._run_inner()
        finally:
            reset_current_budget(budget_token)
            await self._persist_llm_budget()

    async def _run_inner(self) -> None:
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
            guard, on_request=self._persist_request_count, sandbox=self._make_sandbox(guard)
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

    async def _persist_llm_budget(self) -> None:
        """Record the assessment's final LLM token/cost usage to the audit log (F-09)."""
        snapshot = self.llm_budget.snapshot()
        if snapshot["calls"] == 0:
            return  # no brain consults at all (e.g. pure deterministic short-circuit)
        try:
            org_id = await _org_id_of(self.assessment_id)
            if not org_id:
                return
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    event="llm.budget",
                    data=snapshot,
                )
                await session.commit()
        except Exception:  # noqa: BLE001  accounting must never fail the assessment
            log.debug("could not persist llm budget snapshot", exc_info=True)

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

        # DiscoveryAgent (LLM-brained) decides whether to actively crawl beyond artifacts;
        # the crawl itself is its deterministic, scope-enforced tool (runner).
        async def _crawl_runner() -> None:
            async with self._sm() as session:
                assessment = await session.get(Assessment, self.assessment_id)
                target = await session.get(Target, assessment.target_id)
                base_url = target.base_url
            try:
                crawl_eps, crawl_warn = await crawl(
                    client,
                    base_url,
                    max_pages=self.settings.crawl_max_pages,
                    max_depth=self.settings.crawl_max_depth,
                )
                discovered.extend(crawl_eps)
                warnings.extend(crawl_warn)
            except ScopeViolation as exc:
                warnings.append(f"crawl blocked: {exc.reason}")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"crawl error: {exc}")

        discovery_agent = DiscoveryAgent(runner=_crawl_runner, brain=get_brain())
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

        # passive crawl (best-effort, scope-enforced) — the agent acts on its decision
        if crawl_decision.action == "skip":
            warnings.append("discovery agent elected to skip active crawl")
        await discovery_agent.act(
            AgentContext(assessment_id=self.assessment_id), crawl_decision
        )

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
            # Incremental scan (BE-10 / F-14): a retest with incremental=true tests the
            # surface that is NEW *or CHANGED* vs the previous assessment. "Changed" is
            # detected by a surface signature that includes parameters, auth, roles, body
            # schema, and API version — not just the location fingerprint — so an endpoint
            # that gained a parameter or flipped auth is re-tested, not silently skipped.
            if assessment.incremental and assessment.previous_assessment_id:
                prev_rows = (
                    await session.execute(
                        select(Endpoint).where(
                            Endpoint.assessment_id
                            == assessment.previous_assessment_id
                        )
                    )
                ).scalars().all()
                prev_signatures = {_endpoint_signature(e) for e in prev_rows}
                filtered = [
                    e
                    for e in endpoints
                    if _endpoint_signature(e) not in prev_signatures
                ]
                incremental_skipped = len(endpoints) - len(filtered)
                plan_endpoints = filtered

            views = [_endpoint_view(e) for e in plan_endpoints]
            org_id = assessment.org_id
            # Runtime-registered declarative checks (AG-09) participate alongside builtins.
            declaratives = await self._declaratives(session, org_id)
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
        # Optional Deep Agents re-ranker (pure reorder; no-op unless enabled + key set).
        from app.agents.deepagents_planner import rerank_plan

        planned = await rerank_plan(
            planned, {"assessment_id": self.assessment_id, "classes": sorted(effective)}
        )

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
        self, guard: ScopeGuard, steps: list[PlanStep], *, wait: bool = True
    ) -> list[PlanStep]:
        """Deterministic policy gate. ``wait=False`` (graph mode) returns immediately
        with held steps left ``awaiting_approval``; the graph parks on an interrupt
        instead of polling (B-04)."""
        allowed: list[PlanStep] = []
        held: list[str] = []  # CP-03: steps waiting for per-action operator approval
        async with self._sm() as session:
            assessment = await session.get(Assessment, self.assessment_id)
            declaratives = await self._declaratives(session, assessment.org_id)
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
                # F-11: enforce declarative policy (allowed environments + state-changing)
                # in the deterministic policy layer, beneath the LLM. A declarative check
                # may narrow — never widen — what the authorization record already permits.
                policy_reason, policy_code = _declarative_policy_block(check, guard.record)
                if decision.allowed and policy_reason:
                    decision = ScopeDecision(False, policy_reason, code=policy_code)
                s.policy_decision = {
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "code": decision.code,
                }
                if not decision.allowed:
                    s.status = "denied"
                    continue
                # CP-03: per-action approval. Steps that mutate state or are invasive are
                # policy-permitted but still held until an operator approves *that step*.
                if self.settings.step_approval_required and _step_needs_approval(check):
                    s.status = "awaiting_approval"
                    s.policy_decision["requires_approval"] = True
                    s.policy_decision["approval_reason"] = (
                        "state-changing check"
                        if getattr(check, "state_changing", False)
                        else "invasive intensity"
                    )
                    held.append(s.id)
                    continue
                s.status = "approved"
                allowed.append(s)
            await write_audit(
                session,
                org_id=assessment.org_id,
                assessment_id=self.assessment_id,
                event="policy.evaluated",
                data={
                    "approved": len(allowed),
                    "awaiting_approval": len(held),
                    "total": len(steps),
                },
            )
            await session.commit()
            # reload approved steps detached
            ids = [s.id for s in allowed]
        if held and wait:
            ids.extend(await self._await_step_approvals(held))
        return await self._reload_steps(ids)

    async def held_step_ids(self) -> list[str]:
        """Plan steps still awaiting per-action approval (CP-03 / B-04)."""
        async with self._sm() as session:
            rows = (
                await session.execute(
                    select(PlanStep.id).where(
                        PlanStep.assessment_id == self.assessment_id,
                        PlanStep.status == "awaiting_approval",
                    )
                )
            ).all()
        return [r[0] for r in rows]

    async def _await_step_approvals(self, step_ids: list[str]) -> list[str]:
        """Bounded wait for operator decisions on held steps (CP-03).

        Polls the plan steps until each is approved/denied, the wait budget expires, or
        the assessment is cancelled. Returns the ids that became ``approved`` in time;
        steps still awaiting approval are left as-is (they can be executed later via the
        approve endpoint, which runs them under a fresh scope-guarded client).
        """
        wait = max(0, int(self.settings.step_approval_wait_seconds))
        approved: list[str] = []
        pending = set(step_ids)
        deadline = time.monotonic() + wait
        while pending:
            async with self._sm() as session:
                rows = (
                    (
                        await session.execute(
                            select(PlanStep).where(PlanStep.id.in_(list(pending)))
                        )
                    )
                    .scalars()
                    .all()
                )
            for row in rows:
                if row.status == "approved":
                    approved.append(row.id)
                    pending.discard(row.id)
                elif row.status in ("denied", "skipped"):
                    pending.discard(row.id)
            if not pending or time.monotonic() >= deadline or await self._cancelled():
                break
            await asyncio.sleep(max(0.05, self.settings.step_approval_poll_seconds))
        return approved

    # ------------------------------------------------------------------ #
    # Phase: execute — run approved steps via LLM-brained specialist agents
    # ------------------------------------------------------------------ #
    async def _phase_execute(
        self, client: GuardedHttpClient, guard: ScopeGuard, steps: list[PlanStep]
    ) -> None:
        if not steps:
            self._exec_note = "no_execution:no_approved_steps"
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
                    "llm_budget_exceeded": self.llm_budget.exceeded(),
                    "llm_tokens_used": self.llm_budget.total_tokens,
                },
                allowed_actions=["continue", "stop", "replan"],
            ),
            phase="coordinate",
        )
        if coord_decision.action == "stop":
            self._exec_note = "no_execution:coordinator_stop"
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id0,
                    assessment_id=self.assessment_id,
                    event="execution.skipped",
                    data={
                        "reason": "coordinator elected to stop",
                        "brain_reasoning": coord_decision.reasoning,
                    },
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
            declaratives = await self._declaratives(session, org_id)

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
                # linear backoff, base from settings (H-02)
                await asyncio.sleep(self.settings.retry_backoff_seconds * attempt)
                res = await agent.run(ctx)
                await self._persist_agent_result(
                    org_id, step_by_agent.get(aid), res, attempts=attempt
                )
                if res.error:
                    errored.append(aid)

        if stop_reason:
            self._exec_note = f"partial:{stop_reason}"
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

    async def execute_approved_steps(self, step_ids: list[str]) -> int:
        """Run steps an operator approved after the assessment completed (CP-03).

        Uses the *same* authorization record via a fresh ScopeGuard/GuardedHttpClient (so
        budgets, rate limits, sandbox egress rules and the testing window still apply),
        then independently validates any new findings and re-scores. Returns the number
        of findings produced.
        """
        steps = [
            s for s in await self._reload_steps(step_ids) if s.status == "approved"
        ]
        if not steps:
            return 0
        guard = await self._make_guard()
        precheck = guard.check_record_active()
        org_id = await _org_id_of(self.assessment_id)
        if not precheck.allowed or not org_id:
            async with self._sm() as session:
                for s in steps:
                    row = await session.get(PlanStep, s.id)
                    row.status = "skipped"
                    row.policy_decision = {
                        **(row.policy_decision or {}),
                        "post_approval_block": precheck.reason,
                    }
                await session.commit()
            return 0
        budget_token = set_current_budget(self.llm_budget)
        found = 0
        try:
            async with GuardedHttpClient(
                guard,
                on_request=self._persist_request_count,
                sandbox=self._make_sandbox(guard),
            ) as client:
                sessions = await self._build_sessions()
                deadline = time.monotonic() + min(
                    guard.record.max_duration_seconds
                    or self.settings.max_assessment_seconds,
                    self.settings.max_assessment_seconds,
                )
                controller = _ExecController(deadline=deadline, client=client)
                async with self._sm() as session:
                    declaratives = await self._declaratives(session, org_id)
                found = await self._execute_step_batch(
                    client,
                    guard,
                    steps,
                    sessions,
                    get_brain(),
                    org_id,
                    declaratives,
                    controller,
                )
                await self._phase_validate(client, guard)
            await self._phase_score()
            async with self._sm() as session:
                await write_audit(
                    session,
                    org_id=org_id,
                    assessment_id=self.assessment_id,
                    event="execution.approved_steps",
                    data={"steps": [s.id for s in steps], "new_findings": found},
                )
                await session.commit()
        except ScopeViolation as exc:
            log.warning("approved-step execution halted by scope: %s", exc.reason)
        finally:
            reset_current_budget(budget_token)
        return found

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
            skill_ref=self._skill_ref_for(step.check_name if step else ""),
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
        # CP-04: session-relative proofs (BOLA) need the assessment's own test-account
        # sessions. Built once, lazily, only if such a finding exists.
        sessions = None
        if any(c == "bola" for _, c, _ in finding_data):
            sessions = await self._build_sessions()
        for fid, cclass, repro in finding_data:
            if await self._cancelled():
                break
            agent = ValidationAgent(
                validator_coro=lambda c=cclass, r=repro: validate_finding(
                    client, check_class=c, reproduction=r, sessions=sessions
                ),
                brain=brain,
            )
            ctx = AgentContext(
                assessment_id=self.assessment_id,
                budget_remaining_getter=lambda: max(
                    0, guard.record.max_requests - guard.requests_made
                ),
                extra={"check_class": cclass, "detector": repro.get("detector", "")},
            )
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
        async with self._sm() as session:
            n_confirmed = (
                await session.execute(
                    select(func.count(Finding.id)).where(
                        Finding.assessment_id == self.assessment_id,
                        Finding.status == FindingStatus.CONFIRMED.value,
                    )
                )
            ).scalar_one()
            n_total = (
                await session.execute(
                    select(func.count(Finding.id)).where(
                        Finding.assessment_id == self.assessment_id
                    )
                )
            ).scalar_one()
        reporter = ReporterAgent(brain=get_brain())
        decision = await self._agent_decision(
            reporter,
            org_id,
            BrainTask(
                role="reporter",
                instruction=(
                    "Choose the report emphasis: 'risk-first' leads with confirmed "
                    "findings; 'coverage-first' leads with tested/untested surface."
                ),
                context={
                    "assessment_id": self.assessment_id,
                    "confirmed_findings": n_confirmed,
                    "total_findings": n_total,
                },
                allowed_actions=list(ReporterAgent.EMPHASES),
            ),
            phase="report",
        )
        emphasis = (
            decision.action
            if decision.action in ReporterAgent.EMPHASES
            else ReporterAgent.EMPHASES[0]
        )
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            # The renderer reads this to order report sections (see services/reporting).
            a.summary = {**(a.summary or {}), "report_emphasis": emphasis}
            await write_audit(
                session,
                org_id=org_id,
                assessment_id=self.assessment_id,
                event="reporting.ready",
                data={"emphasis": emphasis},
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
            previous = a.state
            a.state = state.value
            if started and a.started_at is None:
                a.started_at = datetime.now(UTC)
            if finished:
                a.finished_at = datetime.now(UTC)
            if state is AssessmentState.COMPLETED:
                a.completion_reason = await self._completion_reason(session)
            await write_audit(
                session,
                org_id=a.org_id,
                assessment_id=self.assessment_id,
                event="state.transition",
                data={"state": state.value, "completion_reason": a.completion_reason or ""},
            )
            await session.commit()
        await hooks.run(
            "post_phase",
            {"assessment_id": self.assessment_id, "from": previous, "to": state.value},
        )

    async def _completion_reason(self, session: AsyncSession) -> str:
        """Evidence-based completion (E-03): a run only counts as 'executed' when at
        least one job actually ran; otherwise the state carries *why* nothing ran."""
        jobs = (
            await session.execute(
                select(func.count(Job.id)).where(Job.assessment_id == self.assessment_id)
            )
        ).scalar_one()
        if jobs == 0:
            return self._exec_note or "no_execution:no_jobs"
        if self._exec_note.startswith("partial:"):
            return self._exec_note
        return "executed"

    async def _checkpoint(
        self, next_state: AssessmentState, cursor: dict | None = None
    ) -> None:
        await hooks.run(
            "pre_phase", {"assessment_id": self.assessment_id, "phase": next_state.value}
        )
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

    async def mark_parked(self, held: list[str]) -> None:
        """Audit that the graph parked this run on per-action approvals (B-04)."""
        async with self._sm() as session:
            a = await session.get(Assessment, self.assessment_id)
            if a is None:
                return
            await write_audit(
                session,
                org_id=a.org_id,
                assessment_id=self.assessment_id,
                event="assessment.parked",
                data={"awaiting_approval": list(held)},
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

    def _make_sandbox(self, guard: ScopeGuard):
        """Build a per-run Sandbox (defense-in-depth egress allowlist) when enabled."""
        if self.settings.sandbox_mode == "none":
            return None
        from app.security.sandbox import sandbox_for

        return sandbox_for(guard.record, self.settings)

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
            guard, on_request=self._persist_request_count, sandbox=self._make_sandbox(guard)
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
        # B-04: never poll in graph mode — the graph parks on an interrupt when steps
        # are held (see graph.py) and resumes once an operator decides.
        await self._phase_policy(guard, steps, wait=False)
        return await self.held_step_ids()

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
            guard, on_request=self._persist_request_count, sandbox=self._make_sandbox(guard)
        ) as client:
            await self._phase_execute(client, guard, steps)
        await self._persist_exact_count(guard.requests_made)

    async def node_validate(self) -> None:
        await self._checkpoint(AssessmentState.VALIDATING)
        await self._set_state(AssessmentState.VALIDATING)
        guard = await self._make_guard()
        async with GuardedHttpClient(
            guard, on_request=self._persist_request_count, sandbox=self._make_sandbox(guard)
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
def _step_needs_approval(check) -> bool:
    """CP-03: a step needs explicit per-action approval if it may change target state
    or is invasive; everything else (passive / safe-active, read-only) does not."""
    if getattr(check, "state_changing", False):
        return True
    intensity = getattr(check, "intensity", None)
    return intensity == TestIntensity.INVASIVE


def _declarative_policy_block(check, record) -> tuple[str | None, str | None]:
    """Enforce a declarative check's declared policy against the authorization record (F-11).

    A registered declarative skill may carry ``policy.state_changing`` and
    ``policy.environments``. These can only *narrow* what the record already permits:

    * a state-changing declarative check is denied unless the record allows state-changing
      tests (the same rule the network gate applies to unsafe HTTP methods), and
    * a check that names an allowed-environment list is denied outside those environments.

    Returns ``(reason, code)`` when the step must be denied, else ``(None, None)``.
    Non-declarative built-in checks are unaffected (they carry no declarative policy).
    """
    from app.checks.declarative import DeclarativeCheck

    if not isinstance(check, DeclarativeCheck):
        return (None, None)
    if getattr(check, "state_changing", False) and not record.allow_state_changing:
        return (
            "declarative check is state-changing but the authorization record does not "
            "permit state-changing tests",
            "declarative_state_change_denied",
        )
    envs = getattr(check, "allowed_environments", []) or []
    if envs and (record.environment or "").lower() not in envs:
        return (
            f"declarative check restricted to environments {envs}; "
            f"authorization environment is {record.environment!r}",
            "declarative_environment_denied",
        )
    return (None, None)


def _endpoint_signature(e: Endpoint) -> str:
    """Change-sensitive surface signature of a persisted endpoint row (F-14)."""
    return endpoint_surface_signature(
        e.method,
        e.url,
        e.path_template,
        parameters=list(e.parameters or []),
        auth_required=bool(e.auth_required),
        roles=list(e.roles or []),
        request_body_schema=dict(e.request_body_schema or {}),
        api_version=e.api_version or "",
    )


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
