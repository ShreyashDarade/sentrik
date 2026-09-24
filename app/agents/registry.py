"""Agent/skill registry — persistent record of check-agents and their manifests.

New agent types register from versioned SKILL.md files (YAML frontmatter). A manifest
is *executable* when it either (a) matches a built-in check by name, or (b) carries a
valid declarative `detector` block (see app/checks/declarative.py) — in which case a
`DeclarativeCheck` runs it at runtime with NO code deploy. Manifests without either are
stored but flagged `needs_code` (honest boundary).

Per-tool testing/permission model (EX-03): every declarative manifest is validated on
registration (schema + detector-specific required fields). The result is stored as
`validation` and a boolean `tested`; an invalid manifest is registered disabled. A
`permissions` block (allowed_tools + policy: environments/state_changing) travels with
the manifest and is enforced at plan/execution time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.checks.base import registry as check_registry
from app.checks.declarative import (
    DETECTOR_TYPES,
    DeclarativeCheck,
    build_declarative_check,
    manifest_is_executable,
)
from app.models import AgentSkill

# Required detector fields per type — used for validation (EX-03).
_DETECTOR_REQUIRED = {
    "error_signature": ["signatures"],
    "reflection": [],
    "status_code": [],
    "header_missing": ["headers"],
    "header_present": ["headers"],
    "header_reflects": ["request_header", "response_header"],
}


@dataclass
class SkillManifest:
    name: str
    version: str
    check_class: str
    intensity: str
    allowed_tools: list[str]
    policy: dict
    body: str
    needs_code: bool
    spec: dict = field(
        default_factory=dict
    )  # full declarative manifest (detector, etc.)
    validation: dict = field(default_factory=dict)
    tested: bool = False


def validate_declarative(spec: dict) -> dict:
    """Validate a declarative manifest. Returns {ok, errors:[...], detector_type}."""
    errors: list[str] = []
    det = spec.get("detector")
    if not isinstance(det, dict):
        return {
            "ok": False,
            "errors": ["missing 'detector' object"],
            "detector_type": None,
        }
    dtype = det.get("type")
    if dtype not in DETECTOR_TYPES:
        return {
            "ok": False,
            "errors": [f"detector.type must be one of {sorted(DETECTOR_TYPES)}"],
            "detector_type": dtype,
        }
    for req in _DETECTOR_REQUIRED.get(dtype, []):
        if not det.get(req):
            errors.append(f"detector.{req} is required for type '{dtype}'")
    # A registrable executable skill must have a real identity (P-10).
    name = spec.get("name")
    if not name or name == "unnamed-skill":
        errors.append("a named 'name' is required")
    if not spec.get("version"):
        errors.append("a 'version' is required")
    if not spec.get("check_class"):
        errors.append("check_class is required")
    if spec.get("intensity") not in ("passive", "safe_active", "invasive"):
        errors.append("intensity must be passive|safe_active|invasive")
    # regex compilability for signature-based detectors
    if dtype == "error_signature":
        import re as _re

        for sig in det.get("signatures", []):
            try:
                _re.compile(sig)
            except _re.error as exc:
                errors.append(f"invalid signature regex {sig!r}: {exc}")
    return {"ok": not errors, "errors": errors, "detector_type": dtype}


def parse_skill_md(text: str) -> SkillManifest:
    """Parse a SKILL.md with YAML frontmatter. Defensive against malformed input."""
    fm, body = _split_frontmatter(text)
    try:
        import yaml

        meta = yaml.safe_load(fm) or {}
    except Exception:  # noqa: BLE001
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    name = str(meta.get("name", "unnamed-skill"))
    version = str(meta.get("version", "1.0.0"))
    check_class = str(meta.get("check_class", ""))
    intensity = str(meta.get("intensity", "passive"))
    tools = meta.get("allowed_tools", [])
    tools = [str(t) for t in tools] if isinstance(tools, list) else []
    policy = meta.get("policy", {}) if isinstance(meta.get("policy"), dict) else {}

    has_impl = check_registry.get(name) is not None
    executable_declarative = manifest_is_executable(meta)
    validation = (
        validate_declarative(meta) if isinstance(meta.get("detector"), dict) else {}
    )
    tested = bool(validation.get("ok")) if validation else has_impl
    # executable when a built-in backs it OR it is a *valid* declarative manifest
    executable = has_impl or (executable_declarative and validation.get("ok", False))

    return SkillManifest(
        name=name,
        version=version,
        check_class=check_class,
        intensity=intensity,
        allowed_tools=tools,
        policy=policy,
        body=body.strip(),
        needs_code=not executable,
        spec=meta,
        validation=validation,
        tested=tested,
    )


def _split_frontmatter(text: str) -> tuple[str, str]:
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n(.*)$", text, re.DOTALL)
    if m:
        return m.group(1), m.group(2)
    return "", text


async def register_manifest(
    session: AsyncSession,
    manifest: SkillManifest,
    provenance: str = "skill_md",
    org_id: str | None = None,
) -> AgentSkill:
    existing = (
        await session.execute(
            select(AgentSkill).where(
                AgentSkill.name == manifest.name,
                AgentSkill.version == manifest.version,
                AgentSkill.org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    # Store the full declarative spec so a DeclarativeCheck can be reconstructed later.
    payload = {
        "intensity": manifest.intensity,
        "allowed_tools": manifest.allowed_tools,
        "policy": manifest.policy,
        "needs_code": manifest.needs_code,
        "executable": not manifest.needs_code,
        "declarative": manifest_is_executable(manifest.spec),
        "detector": manifest.spec.get("detector"),
        "cwe": manifest.spec.get("cwe", ""),
        "severity": manifest.spec.get("severity", "medium"),
        "confidence": manifest.spec.get("confidence", "medium"),
        "title": manifest.spec.get("title", manifest.name),
        "description": manifest.spec.get("description", ""),
        "remediation": manifest.spec.get("remediation", ""),
        "validation": manifest.validation,
        "tested": manifest.tested,
        "body_preview": manifest.body[:500],
    }
    enabled = not manifest.needs_code
    if existing:
        existing.manifest = payload
        existing.check_class = manifest.check_class
        existing.enabled = enabled
        existing.provenance = provenance
        return existing
    row = AgentSkill(
        org_id=org_id,
        name=manifest.name,
        version=manifest.version,
        check_class=manifest.check_class,
        manifest=payload,
        enabled=enabled,
        provenance=provenance,
    )
    session.add(row)
    await session.flush()
    return row


def _manifest_to_check(row: AgentSkill) -> DeclarativeCheck | None:
    """Reconstruct a runnable DeclarativeCheck from a stored AgentSkill, if declarative."""
    m = row.manifest or {}
    if not m.get("declarative") or not row.enabled:
        return None
    spec = {
        "name": row.name,
        "version": row.version,
        "check_class": row.check_class,
        "intensity": m.get("intensity", "passive"),
        "cwe": m.get("cwe", ""),
        "severity": m.get("severity", "medium"),
        "confidence": m.get("confidence", "medium"),
        "title": m.get("title", row.name),
        "description": m.get("description", ""),
        "remediation": m.get("remediation", ""),
        "detector": m.get("detector"),
        "state_changing": (m.get("policy") or {}).get("state_changing", False),
        # F-11: carry the declared environment allow-list into the runnable check so the
        # policy phase can enforce it (e.g. a check that must only run in staging/dev).
        "allowed_environments": (m.get("policy") or {}).get("environments", []),
    }
    return build_declarative_check(spec)


async def load_declarative_checks(
    session: AsyncSession, org_id: str | None
) -> list[DeclarativeCheck]:
    """Load enabled declarative checks visible to an org (shared built-in-declarative
    skills with org_id NULL, plus the org's own registered ones)."""
    rows = (
        (
            await session.execute(
                select(AgentSkill).where(
                    (AgentSkill.org_id.is_(None)) | (AgentSkill.org_id == org_id)
                )
            )
        )
        .scalars()
        .all()
    )
    out: list[DeclarativeCheck] = []
    for row in rows:
        check = _manifest_to_check(row)
        if check is not None:
            out.append(check)
    return out


async def seed_builtin_skills(session: AsyncSession) -> int:
    """Register the built-in checks as agent skills (idempotent)."""
    count = 0
    for check in check_registry.all():
        name = check.name
        existing = (
            await session.execute(
                select(AgentSkill).where(
                    AgentSkill.name == name, AgentSkill.org_id.is_(None)
                )
            )
        ).scalar_one_or_none()
        manifest = {
            "intensity": check.intensity.value,
            "cwe": check.cwe,
            "state_changing": check.state_changing,
            "needs_code": False,
            "executable": True,
            "declarative": False,
        }
        if existing:
            existing.manifest = manifest
            existing.check_class = check.check_class.value
            existing.enabled = True
        else:
            session.add(
                AgentSkill(
                    name=name,
                    version="1.0.0",
                    check_class=check.check_class.value,
                    manifest=manifest,
                    enabled=True,
                    provenance="builtin",
                )
            )
            count += 1
    await session.flush()
    return count
