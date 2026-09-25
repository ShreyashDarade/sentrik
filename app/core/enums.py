"""Shared enumerations used across models, schemas, and the orchestrator."""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    OPERATOR = "operator"  # can run assessments
    VIEWER = "viewer"  # read-only


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    LAB = "lab"  # bundled controlled vulnerable apps


class OwnershipMethod(str, Enum):
    DNS_TXT = "dns_txt"
    HTTP_FILE = "http_file"
    MANUAL_ATTESTATION = "manual_attestation"  # signed delegated-permission record
    LAB_BUNDLED = "lab_bundled"  # bundled vuln app, auto-trusted


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    REVOKED = "revoked"


class TestIntensity(str, Enum):
    """Graduated testing permission — governs which check classes may run."""

    PASSIVE = "passive"  # discovery + non-invasive read-only checks
    SAFE_ACTIVE = "safe_active"  # non-state-changing active probes
    INVASIVE = "invasive"  # state-changing / destructive (lab/staging only)


class AssessmentState(str, Enum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    DISCOVERING = "discovering"
    PLANNING = "planning"
    POLICY_CHECK = "policy_check"
    EXECUTING = "executing"
    VALIDATING = "validating"
    SCORING = "scoring"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = {
    AssessmentState.COMPLETED,
    AssessmentState.FAILED,
    AssessmentState.CANCELLED,
}


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    """Explicit outcomes after independent validation."""

    SUSPECTED = "suspected"  # detector fired, not yet validated
    CONFIRMED = "confirmed"  # independently validated
    INCONCLUSIVE = "inconclusive"  # validation could not decide
    REJECTED = "rejected"  # validation refuted (false positive)
    FIXED = "fixed"  # regression retest shows resolved
    REGRESSED = "regressed"  # previously fixed, now failing again


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CERTAIN = "certain"


class Provenance(str, Enum):
    OPENAPI = "openapi"
    HAR = "har"
    POSTMAN = "postman"
    GRAPHQL = "graphql"
    CRAWL = "crawl"
    TRAFFIC = "traffic"
    MANUAL = "manual"


class CheckClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    BOLA = "bola"
    AUTHZ = "authz"
    SECURITY_HEADERS = "security_headers"
    INFO_DISCLOSURE = "info_disclosure"
    OPEN_REDIRECT = "open_redirect"
    BUSINESS_LOGIC = "business_logic"
    BUSINESS_FLOW = "business_flow"  # multi-step flow invariants (BS-15)
    LLM_PROMPT_INJECTION = "llm_prompt_injection"  # AI red-team (BS-16)
