"""Remediation-PR adapter (BS-14).

Turns confirmed findings into a remediation change set behind a provider-agnostic interface.
The bundled ``LocalGitProvider`` materializes a branch directory containing a human-readable
``REMEDIATION.md`` (KB guidance per finding, prioritized) and a ``remediation.patch`` stub, so
the flow is fully exercised offline. A ``GitHubProvider`` / ``GitLabProvider`` can implement the
same ``RemediationPRProvider`` interface later without touching callers.

We open a *proposal*, never an auto-merge: the change set is advisory and must be reviewed —
consistent with the platform's "propose, human decides" stance.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.services.remediation import build_remediation

_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


@dataclass
class RemediationPR:
    provider: str
    branch: str
    title: str
    body: str
    files: dict[str, str]  # path -> content
    location: str = ""  # where the provider materialized it (dir / URL)


def build_pr_content(assessment_id: str, findings: list[dict]) -> RemediationPR:
    """Assemble the remediation branch content from confirmed findings."""
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    lines = [
        f"# Remediation plan for assessment {assessment_id}",
        "",
        f"{len(confirmed)} confirmed finding(s). Guidance is generated from Sentrik's "
        "remediation knowledge base; review before applying.",
        "",
    ]
    patch_blocks = ["# Remediation patch (advisory stub — apply the guidance in REMEDIATION.md)", ""]
    enriched = []
    for f in confirmed:
        rem = build_remediation(f.get("check_class", ""), f.get("severity", "medium"))
        enriched.append((rem.priority, f, rem))
    enriched.sort(key=lambda t: _PRIORITY_ORDER.get(t[0], 9))
    for priority, f, rem in enriched:
        title = f.get("title", f.get("check_class", "finding"))
        lines += [
            f"## [{priority}] {title}",
            "",
            f"- **Class:** `{f.get('check_class', '')}`  **CWE:** {f.get('cwe', '')}  "
            f"**Severity:** {f.get('severity', '')}",
            f"- **Endpoint:** {(f.get('reproduction') or {}).get('url', 'n/a')}",
            f"- **Provenance:** `{f.get('skill_ref', '')}`",
            "",
            f"**Fix:** {rem.summary}",
            "",
            *[f"  {i + 1}. {step}" for i, step in enumerate(rem.steps)],
            "",
            "References: " + ", ".join(rem.references),
            "",
        ]
        patch_blocks += [
            f"### {f.get('check_class', '')} @ {(f.get('reproduction') or {}).get('url', 'n/a')}",
            "# " + rem.summary,
            "",
        ]
    branch = f"sentrik/remediation-{assessment_id[:8]}"
    return RemediationPR(
        provider="",
        branch=branch,
        title=f"Sentrik remediation: {len(confirmed)} finding(s) in {assessment_id[:8]}",
        body="\n".join(lines),
        files={"REMEDIATION.md": "\n".join(lines), "remediation.patch": "\n".join(patch_blocks)},
    )


class RemediationPRProvider(ABC):
    name = "base"

    @abstractmethod
    async def open_pr(self, pr: RemediationPR) -> RemediationPR: ...


class LocalGitProvider(RemediationPRProvider):
    """Materialize the branch as files under a local directory (git repo fixture-friendly)."""

    name = "local"

    def __init__(self, root: str):
        self.root = root

    async def open_pr(self, pr: RemediationPR) -> RemediationPR:
        branch_dir = os.path.join(self.root, pr.branch.replace("/", "__"))
        os.makedirs(branch_dir, exist_ok=True)
        for rel, content in pr.files.items():
            path = os.path.join(branch_dir, rel)
            os.makedirs(os.path.dirname(path) or branch_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        pr.provider = self.name
        pr.location = branch_dir
        return pr


def get_provider(kind: str, *, local_root: str) -> RemediationPRProvider:
    if kind == "local":
        return LocalGitProvider(local_root)
    raise ValueError(f"unknown remediation-PR provider {kind!r} (available: local)")
