"""Assessment planner — maps the endpoint inventory to prioritized check steps.

Deterministic by default: for each endpoint, every registered check whose class is
authorized and whose `applies_to` heuristics match becomes a candidate plan step,
ranked by a priority heuristic (auth-bearing + parameterized endpoints first).

An optional LLM adapter (`enable_llm_planner`) can re-rank / add rationale, but the
deterministic plan is always the source of truth and the fallback — the LLM can never
introduce a step for an unauthorized check class or endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.checks.base import registry
from app.checks.context import EndpointView
from app.core.enums import TestIntensity


@dataclass
class PlannedStep:
    endpoint_id: str
    endpoint_url: str
    check_class: str
    check_name: str
    intensity: str
    priority: int
    rationale: str


_INTENSITY_RANK = {
    TestIntensity.PASSIVE: 0,
    TestIntensity.SAFE_ACTIVE: 1,
    TestIntensity.INVASIVE: 2,
}


def _endpoint_priority(ev: EndpointView) -> int:
    """Higher = more interesting. Auth + params + write methods raise priority."""
    score = 5
    if ev.parameters:
        score += min(len(ev.parameters), 4)
    if ev.auth_required:
        score += 2
    if ev.method in ("POST", "PUT", "PATCH", "DELETE"):
        score += 1
    if "{id}" in ev.path_template:
        score += 2
    return score


async def build_plan(
    endpoints: list[EndpointView],
    *,
    authorized_check_classes: set[str],
    max_intensity: TestIntensity,
    has_multiple_sessions: bool,
    extra_checks: list | None = None,
) -> list[PlannedStep]:
    """Produce the deterministic plan. Pure function of inputs (easy to test).

    `extra_checks` are additional BaseCheck-compatible checks (e.g. runtime-registered
    DeclarativeChecks) considered alongside the built-in registry.
    """
    steps: list[PlannedStep] = []
    max_rank = _INTENSITY_RANK[max_intensity]
    all_checks = list(registry.all()) + list(extra_checks or [])

    for ev in endpoints:
        ep_prio = _endpoint_priority(ev)
        for check in all_checks:
            cclass = check.check_class.value
            if authorized_check_classes and cclass not in authorized_check_classes:
                continue
            if _INTENSITY_RANK[check.intensity] > max_rank:
                continue
            # BOLA needs >=2 sessions; skip if unavailable to avoid dead steps.
            if cclass == "bola" and not has_multiple_sessions:
                continue
            # lightweight applicability gate (mirrors check.applies_to heuristics)
            if not _quick_applies(check, ev, has_multiple_sessions):
                continue
            steps.append(
                PlannedStep(
                    endpoint_id=ev.id,
                    endpoint_url=ev.url,
                    check_class=cclass,
                    check_name=check.name,
                    intensity=check.intensity.value,
                    priority=ep_prio + _class_bonus(cclass),
                    rationale=_rationale(check, ev),
                )
            )

    steps.sort(key=lambda s: s.priority, reverse=True)
    return steps


def _quick_applies(check, ev: EndpointView, multi: bool) -> bool:
    cclass = check.check_class.value
    if cclass in ("sqli", "xss"):
        return bool(ev.parameters) or "{id}" in ev.path_template
    if cclass == "open_redirect":
        return any(
            "redirect" in p.get("name", "").lower()
            or "url" in p.get("name", "").lower()
            or "return" in p.get("name", "").lower()
            or "next" in p.get("name", "").lower()
            for p in ev.parameters
        )
    if cclass == "bola":
        return (
            multi
            and (ev.method == "GET")
            and (
                "{id}" in ev.path_template
                or any("id" in p.get("name", "").lower() for p in ev.parameters)
            )
        )
    if cclass in ("security_headers", "info_disclosure"):
        return ev.method == "GET"
    return True


def _class_bonus(cclass: str) -> int:
    return {
        "sqli": 4,
        "bola": 4,
        "xss": 3,
        "open_redirect": 2,
        "security_headers": 0,
        "info_disclosure": 0,
    }.get(cclass, 1)


def _rationale(check, ev: EndpointView) -> str:
    return (
        f"{check.check_class.value} probe on {ev.method} {ev.path_template} "
        f"({'auth' if ev.auth_required else 'unauth'}, {len(ev.parameters)} params)"
    )


# NOTE: LLM-driven prioritization now runs through the PlannerAgent's brain in the
# orchestrator (app/orchestrator._phase_planning -> _apply_strategy), which makes a real
# brain call (Anthropic when a key is configured, deterministic fallback otherwise).
# The previous placeholder `maybe_llm_rerank` was removed as dead code.
