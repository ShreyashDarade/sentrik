"""Central configuration.

Values come from env vars. The env prefix is ``SENTINEL_`` — kept for backward
compatibility even though the product is branded **Sentrik** (e.g. ``SENTINEL_JWT_SECRET``).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_", env_file=".env", extra="ignore"
    )

    # --- core ---
    database_url: str = "sqlite+aiosqlite:///./sentrik.db"
    jwt_secret: str = (
        "dev-insecure-change-me"  # override in prod via SENTINEL_JWT_SECRET
    )
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 720
    # 32-byte urlsafe key for encrypting secrets at rest (test accounts, tokens).
    # Override in prod; a random per-process key is generated if left default.
    secret_encryption_key: str = ""

    # --- execution harness budgets (global ceilings; per-assessment can be lower) ---
    max_concurrent_assessments: int = 4
    # Per-tenant fairness: max simultaneous assessments a single org may run (EX-04).
    max_concurrent_assessments_per_org: int = 2
    max_requests_per_assessment: int = 5000
    max_assessment_seconds: int = 1800
    max_recursion_depth: int = 6
    default_rate_limit_per_sec: float = 20.0
    # Bounded true parallelism for specialist agents within one assessment (AG-04).
    execution_concurrency: int = 4
    # Bounded retries per plan step on transient target errors (EX-09).
    max_step_retries: int = 2
    # Progress-aware replanning (EX-09): bounded extra passes to close coverage gaps.
    max_replans: int = 1
    replan_batch: int = 15
    auto_replan_on_coverage_gap: bool = True
    # Target-health: consecutive connection failures that auto-stop an assessment (AU-08).
    target_health_max_consecutive_errors: int = 8
    # Discovery crawl bounds (H-01).
    crawl_max_pages: int = 25
    crawl_max_depth: int = 3
    # Retry backoff base seconds (H-02).
    retry_backoff_seconds: float = 0.05
    # LLM token / cost budgets per assessment (F-09; 0 = unbounded). Cost is estimated
    # from token usage at `llm_cost_per_1k_tokens_usd`.
    max_llm_tokens_per_assessment: int = 0
    max_llm_cost_usd_per_assessment: float = 0.0
    llm_cost_per_1k_tokens_usd: float = 0.015

    # --- network boundary ---
    # Deny-by-default. Even loopback must be explicitly allowed by an authorization record.
    allow_private_networks: bool = True  # gate for on-prem/staging targets on RFC1918
    outbound_connect_timeout: float = 8.0

    # --- ownership verification ---
    ownership_dns_token_prefix: str = "sentrik-site-verification"
    ownership_http_well_known_path: str = "/.well-known/sentrik-verification.txt"

    # --- per-action approval gating (CP-03) ---
    # State-changing or invasive plan steps are held as "awaiting_approval" and are only
    # executed once an operator approves them (POST .../steps/{id}/approve). The engine
    # waits up to `step_approval_wait_seconds` for approvals during the run (0 = do not
    # wait; approved steps can still be executed afterwards via the approve endpoint).
    step_approval_required: bool = True
    step_approval_wait_seconds: int = 0
    step_approval_poll_seconds: float = 1.0

    # --- LLM planning (optional; deterministic fallback used when unset) ---
    anthropic_api_key: str = ""
    planner_model: str = "claude-opus-4-8"
    # Prefer LangChain's ChatAnthropic for the brain when available (falls back to raw httpx).
    use_langchain_brain: bool = True
    # Drive the lifecycle through the LangGraph durable workflow engine when available.
    use_langgraph: bool = False
    # SQLite file backing the durable LangGraph checkpointer (crash-recoverable run state).
    # Empty ⇒ derive from the sqlite database_url, else "./sentrik_checkpoints.db".
    langgraph_checkpoint_db: str = ""
    # Deep Agents-backed planner (optional; shell/FS tools disabled, egress via GuardedHttpClient).
    use_deepagents_planner: bool = False

    environment: str = "dev"

    # --- local / self-hosted inference (private deployment) ---
    # An OpenAI-compatible base URL (e.g. vLLM, Ollama, LM Studio) for a local brain.
    local_llm_base_url: str = ""
    local_llm_model: str = ""
    local_llm_api_key: str = "local"

    # --- SSO / OIDC (optional) ---
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""  # if empty, derived from issuer's /.well-known/openid-configuration
    oidc_email_claim: str = "email"

    # --- evidence/report object storage ---
    # "db" (JSON in Postgres/SQLite; default), "local" (filesystem), or "s3" (S3/MinIO).
    storage_backend: str = "db"
    storage_local_dir: str = "./sentrik_storage"
    s3_endpoint_url: str = ""  # e.g. http://minio:9000 ; empty = AWS default
    s3_bucket: str = ""
    s3_region: str = "us-east-1"
    s3_access_key: str = ""
    s3_secret_key: str = ""

    # --- per-run sandbox (egress isolation) ---
    # "none" (guarded egress only), "process" (asyncio-isolated worker), or "container"
    # (documented deploy profile). Egress is always funnelled through GuardedHttpClient.
    sandbox_mode: str = "none"
    sandbox_enforce_egress_allowlist: bool = True

    @staticmethod
    def _is_weak_secret(value: str) -> bool:
        """A secret is weak if it is empty, too short, or looks like a placeholder."""
        if not value or len(value) < 16:
            return True
        low = value.lower()
        placeholders = (
            "change",
            "insecure",
            "please",
            "example",
            "default",
            "changeme",
            "todo",
            "dev-",
            "your-",
            "placeholder",
        )
        return any(tok in low for tok in placeholders)

    def production_secret_problems(self) -> list[str]:
        """Return insecure-config problems that must fail-fast in production (F-02)."""
        problems: list[str] = []
        if self.environment == "production":
            if self._is_weak_secret(self.jwt_secret):
                problems.append(
                    "SENTINEL_JWT_SECRET is unset/placeholder/too-short (need >=16 random chars)"
                )
            if self._is_weak_secret(self.secret_encryption_key):
                problems.append(
                    "SENTINEL_SECRET_ENCRYPTION_KEY is unset/placeholder/too-short "
                    "(need >=16 random chars; secrets would not survive restart)"
                )
            if self.allow_private_networks:
                problems.append(
                    "SENTINEL_ALLOW_PRIVATE_NETWORKS=true in production (should be false)"
                )
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
