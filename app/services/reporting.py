"""Report generation — structured JSON and human-readable Markdown.

Reports include: assessment metadata, authorization provenance, coverage (with its
denominator), risk scoring with uncertainty, findings with evidence lineage and
validation outcomes, and remediation. Untested endpoints are listed explicitly so the
report never implies unscanned assets are secure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def build_report_payload(
    *,
    assessment: dict,
    target: dict,
    authorization: dict,
    endpoints: list[dict],
    findings: list[dict],
    coverage: list[dict],
    risk: dict,
) -> dict:
    tested = [c for c in coverage if c["tested"]]
    untested = [c for c in coverage if not c["tested"]]
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in findings:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "assessment": assessment,
        "target": target,
        "authorization": {
            "id": authorization.get("id"),
            "status": authorization.get("status"),
            "environment": authorization.get("environment"),
            "intensity": authorization.get("intensity"),
            "authorized_by": authorization.get("authorized_by"),
            "window": [
                authorization.get("window_start"),
                authorization.get("window_end"),
            ],
        },
        "risk": risk,
        "summary": {
            "endpoints_discovered": len(endpoints),
            "endpoints_tested": len({c["endpoint_id"] for c in tested}),
            "findings_total": len(findings),
            "findings_by_status": by_status,
            "findings_by_severity": by_severity,
        },
        "findings": findings,
        "coverage": {
            "denominator": len(coverage),
            "tested": len(tested),
            "untested_count": len(untested),
            "untested": untested[:200],
            "note": "Untested endpoint/check pairs are UNKNOWN risk, not confirmed-safe.",
        },
        "endpoints": endpoints,
    }


def render_markdown(payload: dict) -> str:
    a = payload["assessment"]
    r = payload["risk"]
    s = payload["summary"]
    lines: list[str] = []
    lines.append(f"# Security Assessment Report — {payload['target'].get('name', '')}")
    lines.append("")
    lines.append(f"- **Assessment ID:** `{a.get('id')}`")
    lines.append(f"- **Generated:** {payload['generated_at']}")
    lines.append(
        f"- **Target:** {payload['target'].get('base_url')} "
        f"({payload['target'].get('environment')})"
    )
    lines.append(
        f"- **Authorization:** {payload['authorization'].get('status')} "
        f"/ intensity `{payload['authorization'].get('intensity')}`"
    )
    lines.append("")
    lines.append("## Risk")
    lines.append(
        f"- **Overall score:** {r.get('overall_score')} / 100 — **grade: {r.get('grade')}**"
    )
    lines.append(
        f"- **Coverage:** {r.get('tested_endpoints')}/{r.get('total_endpoints')} "
        f"endpoints ({round((r.get('coverage_ratio') or 0) * 100)}%), "
        f"uncertainty {r.get('uncertainty')}"
    )
    lines.append(
        f"- **Confirmed:** {r.get('confirmed')} · **Suspected:** {r.get('suspected')}"
    )
    lines.append("")
    lines.append("> " + str(r.get("breakdown", {}).get("note", "")))
    lines.append("")
    lines.append("## Summary")
    lines.append(
        f"- Endpoints discovered: **{s['endpoints_discovered']}**, "
        f"tested: **{s['endpoints_tested']}**"
    )
    lines.append(
        f"- Findings: **{s['findings_total']}** "
        f"(by severity: {s['findings_by_severity']})"
    )
    lines.append(f"- By validation status: {s['findings_by_status']}")
    lines.append("")
    lines.append("## Findings")
    if not payload["findings"]:
        lines.append("_No findings recorded._")
    for i, f in enumerate(
        sorted(payload["findings"], key=lambda x: x.get("risk_score", 0), reverse=True),
        1,
    ):
        lines.append("")
        lines.append(f"### {i}. {f['title']}  ")
        lines.append(
            f"**Severity:** {f['severity']} · **Confidence:** {f['confidence']} · "
            f"**Status:** {f['status']} · **Risk:** {f.get('risk_score')} · "
            f"**CWE:** {f.get('cwe', '')}"
        )
        lines.append("")
        lines.append(f"{f.get('description', '')}")
        if f.get("remediation"):
            lines.append("")
            lines.append(f"**Remediation:** {f['remediation']}")
        repro = f.get("reproduction") or {}
        if repro:
            lines.append("")
            lines.append("**Reproduction:**")
            lines.append("```json")
            lines.append(_pretty(repro))
            lines.append("```")
    lines.append("")
    lines.append("## Coverage")
    cov = payload["coverage"]
    lines.append(f"- Denominator (endpoint×check pairs): **{cov['denominator']}**")
    lines.append(
        f"- Tested: **{cov['tested']}**, Untested: **{cov['untested_count']}**"
    )
    lines.append(f"- {cov['note']}")
    lines.append("")
    return "\n".join(lines)


def _pretty(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, indent=2, default=str)
    except (TypeError, ValueError):
        return str(obj)
