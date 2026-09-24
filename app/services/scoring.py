"""Versioned risk scoring.

A finding's risk score is an explainable composite of severity, confidence, exposure
(auth-required endpoints are less exposed than anonymous ones), and validation state.
Coverage & uncertainty are surfaced at the assessment level so untested assets are
never presented as "secure".

The scoring model is versioned (SCORER_VERSION); the version + full breakdown is stored
on each finding so scores are reproducible and comparable across releases.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import Confidence, FindingStatus, Severity

SCORER_VERSION = "1.1.0"

_SEVERITY_BASE = {
    Severity.INFO: 5.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 95.0,
}
_CONFIDENCE_FACTOR = {
    Confidence.LOW: 0.55,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 0.9,
    Confidence.CERTAIN: 1.0,
}
_STATUS_FACTOR = {
    FindingStatus.CONFIRMED: 1.0,
    FindingStatus.SUSPECTED: 0.8,
    FindingStatus.INCONCLUSIVE: 0.5,
    FindingStatus.REJECTED: 0.0,
    FindingStatus.FIXED: 0.0,
    FindingStatus.REGRESSED: 1.0,
}


@dataclass
class ScoreResult:
    score: float
    breakdown: dict


def score_finding(
    *,
    severity: str,
    confidence: str,
    status: str,
    auth_required: bool,
    exposure_env: str,
) -> ScoreResult:
    sev = _coerce(Severity, severity, Severity.MEDIUM)
    conf = _coerce(Confidence, confidence, Confidence.MEDIUM)
    stat = _coerce(FindingStatus, status, FindingStatus.SUSPECTED)

    base = _SEVERITY_BASE[sev]
    conf_factor = _CONFIDENCE_FACTOR[conf]
    status_factor = _STATUS_FACTOR[stat]
    # exposure: anonymous + production endpoints are more exposed
    exposure = 1.0
    if not auth_required:
        exposure += 0.15
    if exposure_env == "production":
        exposure += 0.1
    elif exposure_env in ("lab", "development"):
        exposure -= 0.1
    exposure = max(0.7, min(exposure, 1.3))

    raw = base * conf_factor * status_factor * exposure
    score = round(max(0.0, min(raw, 100.0)), 2)
    return ScoreResult(
        score=score,
        breakdown={
            "scorer_version": SCORER_VERSION,
            "severity": sev.value,
            "severity_base": base,
            "confidence": conf.value,
            "confidence_factor": conf_factor,
            "status": stat.value,
            "status_factor": status_factor,
            "exposure_factor": round(exposure, 3),
            "auth_required": auth_required,
            "exposure_env": exposure_env,
            "formula": "base * confidence_factor * status_factor * exposure_factor",
        },
    )


@dataclass
class AssessmentRisk:
    overall_score: float
    grade: str
    coverage_ratio: float
    tested_endpoints: int
    total_endpoints: int
    confirmed: int
    suspected: int
    uncertainty: float
    breakdown: dict


def score_assessment(
    *,
    finding_scores: list[float],
    finding_statuses: list[str],
    tested_endpoints: int,
    total_endpoints: int,
) -> AssessmentRisk:
    confirmed = sum(1 for s in finding_statuses if s == FindingStatus.CONFIRMED.value)
    suspected = sum(1 for s in finding_statuses if s == FindingStatus.SUSPECTED.value)
    coverage = (tested_endpoints / total_endpoints) if total_endpoints else 0.0

    # Overall risk driven by the worst confirmed issues, not the average, so a single
    # critical is not diluted. Uncertainty grows as coverage shrinks.
    top = sorted(finding_scores, reverse=True)[:5]
    overall = round(sum(top) / len(top), 2) if top else 0.0
    uncertainty = round(1.0 - coverage, 3)

    # Never present low-coverage assessments as "secure".
    if total_endpoints == 0:
        grade = "unknown"
    elif coverage < 0.5:
        grade = "insufficient-coverage"
    elif overall >= 75:
        grade = "critical"
    elif overall >= 50:
        grade = "at-risk"
    elif overall >= 25:
        grade = "needs-attention"
    elif confirmed == 0 and suspected == 0:
        grade = "no-confirmed-issues"  # deliberately NOT "secure"
    else:
        grade = "low-risk"

    return AssessmentRisk(
        overall_score=overall,
        grade=grade,
        coverage_ratio=round(coverage, 3),
        tested_endpoints=tested_endpoints,
        total_endpoints=total_endpoints,
        confirmed=confirmed,
        suspected=suspected,
        uncertainty=uncertainty,
        breakdown={
            "scorer_version": SCORER_VERSION,
            "method": "mean of top-5 finding scores; grade floored by coverage",
            "coverage_ratio": round(coverage, 3),
            "note": "grade of 'no-confirmed-issues' means tested-and-clean, not proven secure; "
            "untested endpoints remain unknown risk.",
        },
    )


def _coerce(enum_cls, value, default):
    try:
        return enum_cls(value)
    except ValueError:
        return default
