"""SQLAlchemy ORM models — the persistent backbone of the assessment lifecycle.

Every tenant-scoped row carries org_id. Assessments carry a shared assessment_id
threaded through discovery, planning, execution, evidence, findings, validation,
scoring, reporting, and regression retesting.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


# --------------------------------------------------------------------------- #
# Tenancy & identity
# --------------------------------------------------------------------------- #
class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255), unique=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)

    users: Mapped[list["User"]] = relationship(
        back_populates="org", cascade="all, delete-orphan"
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="operator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    org: Mapped[Organization] = relationship(back_populates="users")


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255), default="default")
    prefix: Mapped[str] = mapped_column(String(16), index=True)  # lookup key
    secret_hash: Mapped[str] = mapped_column(String(255))  # bcrypt of full key
    role: Mapped[str] = mapped_column(String(32), default="operator")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


# --------------------------------------------------------------------------- #
# Targets & authorization
# --------------------------------------------------------------------------- #
class Target(Base, TimestampMixin):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    base_url: Mapped[str] = mapped_column(String(1024))
    environment: Mapped[str] = mapped_column(String(32), default="lab")
    description: Mapped[str] = mapped_column(Text, default="")


class OwnershipVerification(Base, TimestampMixin):
    __tablename__ = "ownership_verifications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(32))
    token: Mapped[str] = mapped_column(String(255))
    host: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    detail: Mapped[str] = mapped_column(Text, default="")


class AuthorizationRecord(Base, TimestampMixin):
    """The explicit authorization bound to every assessment. Enforced outside the LLM."""

    __tablename__ = "authorization_records"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending")
    environment: Mapped[str] = mapped_column(String(32), default="lab")
    intensity: Mapped[str] = mapped_column(String(32), default="passive")
    # scope
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)  # exact hostnames
    allowed_ports: Mapped[list] = mapped_column(
        JSON, default=list
    )  # ints; [] => 80,443
    allowed_methods: Mapped[list] = mapped_column(
        JSON, default=list
    )  # HTTP verbs allowed
    allowed_check_classes: Mapped[list] = mapped_column(JSON, default=list)
    path_allowlist: Mapped[list] = mapped_column(
        JSON, default=list
    )  # path prefixes ([] => all)
    path_denylist: Mapped[list] = mapped_column(JSON, default=list)
    # limits / budgets
    max_requests: Mapped[int] = mapped_column(Integer, default=2000)
    rate_limit_per_sec: Mapped[float] = mapped_column(Float, default=10.0)
    max_duration_seconds: Mapped[int] = mapped_column(Integer, default=900)
    # window
    window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    window_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    allow_state_changing: Mapped[bool] = mapped_column(Boolean, default=False)
    # provenance of authorization
    ownership_verification_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    authorized_by: Mapped[str] = mapped_column(String(320), default="")
    signature: Mapped[str] = mapped_column(
        Text, default=""
    )  # attestation signature/hash
    notes: Mapped[str] = mapped_column(Text, default="")


class TestAccount(Base, TimestampMixin):
    """Credentials for authenticated testing (encrypted at rest)."""

    __tablename__ = "test_accounts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(255))
    role_name: Mapped[str] = mapped_column(
        String(128), default="user"
    )  # low_priv / admin / ...
    auth_type: Mapped[str] = mapped_column(
        String(32), default="form"
    )  # form | bearer | basic | header
    username: Mapped[str] = mapped_column(String(320), default="")
    secret_enc: Mapped[str] = mapped_column(
        Text, default=""
    )  # encrypted password/token
    login_config: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # login url, field names, etc.
    owns_object_ids: Mapped[list] = mapped_column(
        JSON, default=list
    )  # object ids this acct owns (BOLA)
    secret_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    secret_ttl_days: Mapped[int] = mapped_column(Integer, default=0)  # 0 = no expiry


# --------------------------------------------------------------------------- #
# Assessments & discovery
# --------------------------------------------------------------------------- #
class Assessment(Base, TimestampMixin):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    authorization_id: Mapped[str] = mapped_column(
        ForeignKey("authorization_records.id"), index=True
    )
    state: Mapped[str] = mapped_column(String(32), default="created", index=True)
    previous_assessment_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )  # retest lineage
    is_retest: Mapped[bool] = mapped_column(Boolean, default=False)
    incremental: Mapped[bool] = mapped_column(
        Boolean, default=False
    )  # test only new/changed surface
    requested_check_classes: Mapped[list] = mapped_column(JSON, default=list)
    # runtime accounting
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class DiscoveryArtifact(Base, TimestampMixin):
    """A supplied discovery input (OpenAPI/HAR/Postman/GraphQL) awaiting/after parse."""

    __tablename__ = "discovery_artifacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32))  # openapi|har|postman|graphql
    filename: Mapped[str] = mapped_column(String(512), default="")
    content: Mapped[str] = mapped_column(Text)  # raw artifact text
    endpoint_url: Mapped[str] = mapped_column(String(1024), default="")  # for graphql
    parsed: Mapped[bool] = mapped_column(Boolean, default=False)
    warnings: Mapped[list] = mapped_column(JSON, default=list)


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(String(2048))
    path_template: Mapped[str] = mapped_column(String(2048), default="")
    parameters: Mapped[list] = mapped_column(
        JSON, default=list
    )  # [{name,in,type,required}]
    request_body_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    roles: Mapped[list] = mapped_column(JSON, default=list)
    api_version: Mapped[str] = mapped_column(String(64), default="")
    provenance: Mapped[str] = mapped_column(String(32), default="manual")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # dedup key


class PlanStep(Base, TimestampMixin):
    __tablename__ = "plan_steps"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("endpoints.id"), nullable=True
    )
    check_class: Mapped[str] = mapped_column(String(32))
    check_name: Mapped[str] = mapped_column(
        String(128), default=""
    )  # exact check to run
    rationale: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[int] = mapped_column(Integer, default=5)
    intensity: Mapped[str] = mapped_column(String(32), default="passive")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    policy_decision: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # allow/deny + reason


class Job(Base, TimestampMixin):
    """Durable execution unit for one plan step. Enables checkpoint/replay/idempotency."""

    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    plan_step_id: Mapped[str] = mapped_column(
        ForeignKey("plan_steps.id", ondelete="CASCADE")
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), index=True)
    state: Mapped[str] = mapped_column(String(32), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------- #
# Evidence, findings, validation
# --------------------------------------------------------------------------- #
class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(32), default="http_exchange")
    request: Mapped[dict] = mapped_column(JSON, default=dict)  # redacted
    response: Mapped[dict] = mapped_column(JSON, default=dict)  # redacted, truncated
    note: Mapped[str] = mapped_column(Text, default="")
    lineage: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # job_id, plan_step_id, check_class
    redacted: Mapped[bool] = mapped_column(Boolean, default=True)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("endpoints.id"), nullable=True
    )
    check_class: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="suspected", index=True)
    cwe: Mapped[str] = mapped_column(String(32), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    dedup_key: Mapped[str] = mapped_column(String(128), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    reproduction: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # replayable request sequence


class ValidationResult(Base, TimestampMixin):
    __tablename__ = "validation_results"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    outcome: Mapped[str] = mapped_column(
        String(32)
    )  # confirmed/suspected/inconclusive/rejected
    method: Mapped[str] = mapped_column(String(64), default="independent_replay")
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Coverage(Base, TimestampMixin):
    __tablename__ = "coverage"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE")
    )
    check_class: Mapped[str] = mapped_column(String(32))
    tested: Mapped[bool] = mapped_column(Boolean, default=False)
    reason_untested: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------- #
# Regression, chat, audit, checkpoints
# --------------------------------------------------------------------------- #
class RegressionTest(Base, TimestampMixin):
    __tablename__ = "regression_tests"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    origin_finding_id: Mapped[str] = mapped_column(String(32))
    check_class: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512))
    definition: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # replayable request + assertion
    last_status: Mapped[str] = mapped_column(String(32), default="unknown")
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ChatSession(Base, TimestampMixin):
    __tablename__ = "chat_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(255), default="session")


class ChatMessage(Base, TimestampMixin):
    __tablename__ = "chat_messages"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(16))  # user | assistant | system
    content: Mapped[str] = mapped_column(Text)
    actions: Mapped[list] = mapped_column(
        JSON, default=list
    )  # structured tool actions taken


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    actor: Mapped[str] = mapped_column(String(128), default="system")
    event: Mapped[str] = mapped_column(String(128), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class ProjectMemory(Base, TimestampMixin):
    """Durable, tenant-isolated project memory (facts an assessment can carry forward).

    Keyed by (org_id, target_id, key). Examples: learned auth flows, known false
    positives, stable object ids, notes. Retrieval is always org-scoped.
    """

    __tablename__ = "project_memory"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    key: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    kind: Mapped[str] = mapped_column(String(64), default="note")


class Checkpoint(Base, TimestampMixin):
    """Durable orchestrator checkpoint enabling crash recovery / resume."""

    __tablename__ = "checkpoints"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True, unique=True
    )
    state: Mapped[str] = mapped_column(String(32))
    cursor: Mapped[dict] = mapped_column(
        JSON, default=dict
    )  # phase-local progress cursor


class AgentSkill(Base, TimestampMixin):
    """Registry of check/agent skills registered via versioned SKILL.md manifests.

    org_id is NULL for built-in (shared) skills and set for tenant-registered skills,
    so a tenant only ever sees the built-ins plus its own registrations.
    """

    __tablename__ = "agent_skills"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    org_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    check_class: Mapped[str] = mapped_column(String(32))
    manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    provenance: Mapped[str] = mapped_column(String(64), default="builtin")
