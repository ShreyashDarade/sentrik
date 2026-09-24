"""Pydantic request/response schemas for the public API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Onboarding & identity
# --------------------------------------------------------------------------- #
class OrgSignup(BaseModel):
    org_name: str = Field(min_length=2, max_length=200)
    org_slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    admin_email: str = Field(min_length=3, max_length=320)
    admin_password: str = Field(min_length=8, max_length=200)


class SignupResult(BaseModel):
    org_id: str
    user_id: str
    access_token: str
    api_key: str


class LoginRequest(BaseModel):
    org_slug: str
    email: str
    password: str


class TokenResult(BaseModel):
    access_token: str
    token_type: str = "bearer"
    org_id: str
    role: str


class ApiKeyCreate(BaseModel):
    name: str = "default"
    role: str = "operator"


class ApiKeyResult(BaseModel):
    id: str
    api_key: str
    prefix: str
    role: str


# --------------------------------------------------------------------------- #
# Targets, ownership, authorization
# --------------------------------------------------------------------------- #
class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=3, max_length=1000)
    environment: str = "lab"
    description: str = ""


class TargetOut(BaseModel):
    id: str
    name: str
    base_url: str
    environment: str
    description: str


class OwnershipStart(BaseModel):
    method: str = (
        "lab_bundled"  # dns_txt | http_file | manual_attestation | lab_bundled
    )
    attestation: str | None = None


class OwnershipOut(BaseModel):
    id: str
    method: str
    host: str
    token: str
    status: str
    detail: str
    instructions: str = ""


class AuthorizationCreate(BaseModel):
    environment: str = "lab"
    intensity: str = "safe_active"  # passive | safe_active | invasive
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    allowed_check_classes: list[str] = Field(default_factory=list)
    path_allowlist: list[str] = Field(default_factory=list)
    path_denylist: list[str] = Field(default_factory=list)
    max_requests: int = 2000
    rate_limit_per_sec: float = 10.0
    max_duration_seconds: int = 900
    window_start: datetime | None = None
    window_end: datetime | None = None
    allow_state_changing: bool = False
    authorized_by: str = ""
    notes: str = ""


class AuthorizationOut(BaseModel):
    id: str
    status: str
    environment: str
    intensity: str
    allowed_hosts: list[str]
    allowed_check_classes: list[str]
    max_requests: int
    allow_state_changing: bool


class TestAccountCreate(BaseModel):
    label: str
    role_name: str = "user"
    auth_type: str = "bearer"  # form | bearer | basic | header
    username: str = ""
    secret: str = ""
    login_config: dict = Field(default_factory=dict)
    owns_object_ids: list[Any] = Field(default_factory=list)


class TestAccountOut(BaseModel):
    id: str
    label: str
    role_name: str
    auth_type: str
    username: str


class MfaComplete(BaseModel):
    account_id: str
    code: str


# --------------------------------------------------------------------------- #
# Discovery artifacts
# --------------------------------------------------------------------------- #
class ArtifactUpload(BaseModel):
    kind: str  # openapi | har | postman | graphql
    filename: str = ""
    content: str
    endpoint_url: str = ""


class ArtifactOut(BaseModel):
    id: str
    kind: str
    filename: str
    parsed: bool
    warnings: list[str]


# --------------------------------------------------------------------------- #
# Assessments
# --------------------------------------------------------------------------- #
class AssessmentCreate(BaseModel):
    target_id: str
    authorization_id: str
    requested_check_classes: list[str] = Field(default_factory=list)
    artifacts: list[ArtifactUpload] = Field(default_factory=list)


class AssessmentOut(BaseModel):
    id: str
    target_id: str
    authorization_id: str
    state: str
    is_retest: bool
    incremental: bool = False
    previous_assessment_id: str | None = None
    requests_made: int
    error: str = ""
    summary: dict = Field(default_factory=dict)
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class AssessmentProgress(BaseModel):
    id: str
    state: str
    requests_made: int
    endpoints: int
    plan_steps: int
    findings: int
    findings_by_status: dict
    risk: dict = Field(default_factory=dict)
    agents_instantiated: int = 0


class PlanStepOut(BaseModel):
    id: str
    assessment_id: str
    endpoint_id: str | None = None
    check_class: str
    check_name: str
    intensity: str
    priority: int
    status: str  # planned|approved|awaiting_approval|denied|skipped|done|errored
    rationale: str = ""
    policy_decision: dict = Field(default_factory=dict)


class StepDecision(BaseModel):
    """Operator decision on a held (awaiting_approval) plan step (CP-03)."""

    note: str = Field(default="", max_length=500)


class RetestCreate(BaseModel):
    requested_check_classes: list[str] = Field(default_factory=list)
    incremental: bool = (
        False  # test only endpoints new/changed vs the previous assessment
    )


# --------------------------------------------------------------------------- #
# Findings, evidence, coverage
# --------------------------------------------------------------------------- #
class EvidenceOut(BaseModel):
    id: str
    kind: str
    request: dict
    response: dict
    note: str
    lineage: dict


class FindingOut(BaseModel):
    id: str
    check_class: str
    title: str
    severity: str
    confidence: str
    status: str
    cwe: str
    description: str
    remediation: str
    risk_score: float
    risk_breakdown: dict
    reproduction: dict
    endpoint_id: str | None = None


class EndpointOut(BaseModel):
    id: str
    method: str
    url: str
    path_template: str
    parameters: list[dict]
    auth_required: bool
    api_version: str
    provenance: str
    confidence: float


# --------------------------------------------------------------------------- #
# Chat / connectors
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    assessment_id: str | None = None


class ChatReply(BaseModel):
    session_id: str
    reply: str
    actions: list[dict] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Skills / agents
# --------------------------------------------------------------------------- #
class SkillRegister(BaseModel):
    skill_md: str


class SkillOut(BaseModel):
    id: str
    name: str
    version: str
    check_class: str
    enabled: bool
    provenance: str
    manifest: dict


class ErrorOut(BaseModel):
    detail: str
