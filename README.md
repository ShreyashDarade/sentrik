# Sentrik

**Authorized, autonomous application & API security testing — agentic, with
authorization enforced _outside_ the LLM.**

Sentrik is a **backend-only**, multi-tenant platform that runs the full pentest
lifecycle behind documented HTTP APIs. LLM-brained agents plan and reason, but a
deterministic policy layer beneath them decides what is allowed — so an agent can
never widen its own scope, reach a host it wasn't authorized for, or attack a system
you don't own.

> ⚠️ **Authorized use only.** Sentrik sends real attack traffic. Point it only at
> systems you own or are explicitly authorized in writing to test.

---

## Why Sentrik

- **Authorization outside the LLM.** Every outbound request passes a deterministic
  `ScopeGuard` + guarded HTTP client (allowed hosts/ports/methods/paths, testing
  window, request/rate/time budgets, deny-by-default on redirects and newly discovered
  assets, SSRF/metadata blocks, and **connect-to-pinned-IP** anti-DNS-rebinding).
- **Full lifecycle, one shared assessment id:** onboarding → ownership &
  authorization verification → target connection → scoped discovery → planning →
  policy → sandboxed execution → independent validation → findings & coverage →
  remediation → regression tests → continuous retesting.
- **Real detections, independently validated.** SQL injection (error + boolean),
  reflected XSS, BOLA/IDOR, security headers, open redirect — each re-proved by a
  separate validator (confirmed / suspected / inconclusive / rejected).
- **Agentic, framework-first.** LLM brain per agent (LangChain `ChatAnthropic`),
  durable LangGraph workflow, MCP tool server, A2A message bus, capability-based agent
  pool — all with deterministic fallbacks so it runs and is testable offline.
- **Declarative checks with no code.** Register a new detection at runtime from a
  versioned `SKILL.md` manifest (6 detector types) — validated on registration.
- **Explainable, versioned risk scoring** with coverage and uncertainty. Untested
  assets are never reported as "secure".
- **Production-minded:** RBAC + API keys/JWT, encrypted secrets at rest, structured
  JSON logs + correlation IDs + `/metrics` + OpenTelemetry traces, `/ready`, uniform
  error envelopes, Docker/Compose.

## How it works (30-second tour)

```text
client ──▶ FastAPI (app/api) ──▶ Assessment engine (app/orchestration)
                                      │  state machine + durable checkpoints
                                      ▼
                 LLM-brained agents (app/agents) ── run ──▶ security checks (app/checks)
                                      │                               │
                                      ▼   the ONLY egress path        ▼
        ╔══════════════════════════════════════════════════════════════╗
        ║ DETERMINISTIC AUTHORIZATION LAYER (outside the LLM)           ║
        ║ ScopeGuard + GuardedHttpClient + NetGuard   (app/security)    ║
        ╚══════════════════════════════════════════════════════════════╝
                                      ▼
                              target system (in scope only)
```

---

## Quick start

```bash
python -m venv .venv
. .venv/Scripts/activate          # Windows;  source .venv/bin/activate on macOS/Linux
pip install -r requirements.lock  # reproducible, pinned (what the Docker image installs)
pip install --no-deps -e .        # the app itself; extras: .[agents,postgres,storage,observability,dev]

uvicorn app.main:app --reload     # API + interactive docs at http://127.0.0.1:8000/docs
```

The app creates its own database schema on startup (`init_db` → `create_all`; SQLite
`./sentrik.db` by default, point `SENTINEL_DATABASE_URL` at Postgres for production).
There is no separate migration step. The durable LangGraph checkpointer writes to a
sibling SQLite file (`./sentrik_checkpoints.db`, `SENTINEL_LANGGRAPH_CHECKPOINT_DB`).

Environment variables keep the historical `SENTINEL_` prefix for backward compatibility
with existing deployments even though the product is named Sentrik.

**What this repository contains.** The public repository ships the application
(`app/`), container/compose files, `pyproject.toml` and the pinned `requirements.lock`.
The test suite (134 tests incl. end-to-end runs against a bundled lab target), the
lab target, benchmark harness, Alembic history, SKILL.md examples and the design/audit
documents are maintained in the private development tree and are **not published
here**; statements below about test verification refer to that suite and are not
reproducible from this repository alone. Request access if you need them.

### Docker

```bash
export SENTINEL_JWT_SECRET=$(openssl rand -hex 32)
export SENTINEL_SECRET_ENCRYPTION_KEY=$(openssl rand -hex 32)
docker compose up -d --build          # API on :8000, Postgres on :5432
```

### Enable live LLM agents (optional)

**Default is rule-based, not LLM.** Without an API key every agent uses the
`DeterministicBrain`: a fixed, explainable policy that always picks the first allowed
action and ranks parameters by a heuristic. All checks, scope enforcement, validation and
reporting are fully functional in that mode, but `agent.decision` audit rows will show
`brain_source: deterministic` — they are not model reasoning. With a key, each agent
reasons via Anthropic through LangChain (`brain_source: llm`):

```bash
export SENTINEL_ANTHROPIC_API_KEY=sk-ant-...
# optional per-assessment spend ceilings (0 = unbounded); when reached, agents degrade
# to the deterministic brain for the rest of the run (audit shows `budget_exceeded`)
export SENTINEL_MAX_LLM_TOKENS_PER_ASSESSMENT=200000
export SENTINEL_MAX_LLM_COST_USD_PER_ASSESSMENT=5
# optional Deep Agents plan re-ranker (reorder-only; builtin shell/FS tools denied)
export SENTINEL_USE_DEEPAGENTS_PLANNER=true
```

Private deployments can point the brain at an OpenAI-compatible local endpoint instead
(`SENTINEL_LOCAL_LLM_BASE_URL` + `SENTINEL_LOCAL_LLM_MODEL`).

---

## Configuration

All settings are environment variables prefixed `SENTINEL_` (see `.env.example` and
`app/core/config.py`). Most important:

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_DATABASE_URL` | `sqlite+aiosqlite:///./sentrik.db` | DB (use `postgresql+asyncpg://…` in prod) |
| `SENTINEL_JWT_SECRET` | dev value | JWT signing key — **set in prod** (≥16 chars, no placeholder words) |
| `SENTINEL_SECRET_ENCRYPTION_KEY` | ephemeral | encrypts test-account secrets at rest — **set in prod** |
| `SENTINEL_ALLOW_PRIVATE_NETWORKS` | `true` | allow RFC1918/loopback targets (set `false` in prod) |
| `SENTINEL_MAX_REQUESTS_PER_ASSESSMENT` | `5000` | global request ceiling |
| `SENTINEL_MAX_LLM_TOKENS_PER_ASSESSMENT` / `_MAX_LLM_COST_USD_PER_ASSESSMENT` | `0` (unbounded) | per-run LLM spend ceilings; usage recorded as an `llm.budget` audit event |
| `SENTINEL_STEP_APPROVAL_REQUIRED` | `true` | hold state-changing/invasive plan steps as `awaiting_approval` until an operator approves each one |
| `SENTINEL_STEP_APPROVAL_WAIT_SECONDS` | `0` | how long a run waits for approvals before proceeding without the held steps |
| `SENTINEL_CRAWL_MAX_PAGES` / `_CRAWL_MAX_DEPTH` | `25` / `3` | active-crawl bounds |
| `SENTINEL_ANTHROPIC_API_KEY` | – | enable live LLM brains |
| `SENTINEL_USE_LANGGRAPH` | `false` | drive the lifecycle through LangGraph (durable SQLite checkpointer) |
| `SENTINEL_USE_DEEPAGENTS_PLANNER` | `false` | Deep Agents re-ranker over the authorized plan |
| `SENTINEL_STORAGE_BACKEND` | `db` | evidence/report object store: `db`, `local`, or `s3` (S3/MinIO via `SENTINEL_S3_*`) |
| `SENTINEL_SANDBOX_MODE` | `none` | `none`/`process`/`container` per-run egress sandbox (allow-list independent of ScopeGuard) |
| `SENTINEL_OIDC_ENABLED` + `SENTINEL_OIDC_ISSUER`/`_AUDIENCE` | `false` | SSO: `POST /v1/onboarding/oidc/login` exchanges a provider ID token for a Sentrik JWT |
| `SENTINEL_OTLP_ENDPOINT` | – | ship traces to an OTLP collector |

In `production`, Sentrik **fails to start** on insecure or placeholder secrets.

### Per-action approval (state-changing / invasive steps)

Even when an authorization record permits state-changing tests, each such plan step is
held: `GET /v1/assessments/{id}/steps?status=awaiting_approval` lists them, and
`POST /v1/assessments/{id}/steps/{step_id}/approve|deny` decides. A step approved after
the run finished is executed immediately under a fresh scope-guarded client (same record,
budgets and sandbox), then validated and re-scored.

---

## API reference

Base URL: `http://127.0.0.1:8000`. Interactive docs (OpenAPI/Swagger): **`/docs`**.

**Auth:** call `POST /v1/onboarding/signup` once to get an API key, then send it as
`X-API-Key: sk_...` (or a Bearer JWT from `/v1/onboarding/login`). Roles:
`viewer < operator < admin < owner`.

### Meta / ops (no auth)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | liveness |
| GET | `/ready` | readiness (checks DB) |
| GET | `/metrics` | Prometheus-format metrics |

### Onboarding & identity

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/v1/onboarding/signup` | – | create org + owner, returns API key + JWT |
| POST | `/v1/onboarding/login` | – | email/password → JWT |
| GET | `/v1/me` | any | current principal |
| POST | `/v1/api-keys` | admin | mint an API key |
| DELETE | `/v1/api-keys/{key_id}` | admin | revoke an API key |

### Targets, ownership & authorization

| Method | Path | Role | Description |
|---|---|---|---|
| GET/POST | `/v1/targets` | operator | list / create a target |
| POST | `/v1/targets/{id}/ownership` | operator | start ownership check (dns_txt / http_file / manual_attestation) |
| POST | `/v1/targets/{id}/ownership/{oid}/verify` | operator | verify an ownership challenge |
| GET/POST | `/v1/targets/{id}/authorizations` | operator | list / create the scoped **authorization record** |
| GET/POST | `/v1/targets/{id}/test-accounts` | operator | list / add authenticated-testing accounts |
| POST | `/v1/targets/{id}/test-accounts/{aid}/mfa` | operator | complete an MFA challenge |
| POST | `/v1/targets/{id}/test-accounts/{aid}/rotate-secret` | operator | rotate a stored secret (+ TTL) |
| POST | `/v1/targets/{id}/connectors/spec-url` | operator | ingest an OpenAPI/GraphQL/Postman spec from a URL (SSRF-guarded) |
| POST | `/v1/targets/{id}/connectors/repo` | operator | ingest a spec from a repo raw-file URL |
| POST | `/v1/webhooks/ci/{id}` | operator | CI/CD change-trigger → retest |

### Assessments (the lifecycle)

| Method | Path | Role | Description |
|---|---|---|---|
| GET/POST | `/v1/assessments` | operator | list / create (attach discovery artifacts) |
| POST | `/v1/assessments/{id}/start` | operator | run it (async) |
| GET | `/v1/assessments/{id}` | any | status |
| GET | `/v1/assessments/{id}/progress` | any | progress snapshot |
| GET | `/v1/assessments/{id}/stream` | any | **SSE** live progress stream |
| POST | `/v1/assessments/{id}/cancel` | operator | emergency cancel |
| POST | `/v1/assessments/{id}/traffic` | operator | ingest observed live traffic → endpoints |
| GET | `/v1/assessments/{id}/endpoints` | any | discovered endpoint inventory |
| GET | `/v1/assessments/{id}/findings` | any | findings (`?status=&limit=&offset=`) |
| POST | `/v1/assessments/{id}/findings/{fid}/triage` | operator | confirm / reject (FP) / reopen |
| GET | `/v1/assessments/{id}/findings/{fid}/evidence` | any | redacted request/response evidence |
| GET | `/v1/assessments/{id}/coverage` | any | coverage + its denominator |
| GET | `/v1/assessments/{id}/attack-path` | any | scoped attack-path graph |
| GET | `/v1/assessments/{id}/report` | any | report (`?fmt=json|markdown|pdf`) |
| GET | `/v1/assessments/{id}/audit` | any | full audit trail (agent decisions, policy, lineage) |
| POST | `/v1/assessments/{id}/regression-tests` | operator | generate regression tests from confirmed findings |
| POST | `/v1/assessments/{id}/regression-run` | operator | run regression tests |
| POST | `/v1/assessments/{id}/retest` | operator | retest (`{"incremental": true}` for changed-surface only) |
| GET | `/v1/assessments/{id}/regression-compare` | any | fixed / still-open / newly-introduced |

### Chat, skills & memory

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/v1/chat` | any | conversational connector (list/start/status/summarize) |
| GET/POST | `/v1/skills` | admin (POST) | list / register a `SKILL.md` (built-in + declarative checks) |
| GET/PUT | `/v1/memory` | operator (PUT) | tenant-isolated project memory |
| DELETE | `/v1/memory/{id}` | operator | delete a memory entry |

### End-to-end walkthrough (curl)

```bash
BASE=http://127.0.0.1:8000
TARGET=https://app.example.com          # a target you are authorized to test

# 1) onboard → grab the API key
KEY=$(curl -s $BASE/v1/onboarding/signup -H 'content-type: application/json' -d '{
  "org_name":"Acme","org_slug":"acme","admin_email":"a@acme.test","admin_password":"supersecret1"
}' | python -c 'import sys,json;print(json.load(sys.stdin)["api_key"])')
H="-H x-api-key:$KEY -H content-type:application/json"

# 2) create a target and prove ownership (http_file / dns_txt / manual_attestation)
TID=$(curl -s $BASE/v1/targets $H -d "{\"name\":\"prod\",\"base_url\":\"$TARGET\",\"environment\":\"production\"}" | jq -r .id)
curl -s $BASE/v1/targets/$TID/ownership $H -d '{"method":"http_file"}'          # returns a token to host
# … host the token, then:
# curl -s $BASE/v1/targets/$TID/ownership/<oid>/verify $H

# 3) scoped authorization record (deny-by-default outside this)
AID=$(curl -s $BASE/v1/targets/$TID/authorizations $H -d '{
  "environment":"production","intensity":"safe_active",
  "allowed_hosts":["app.example.com"],"allowed_ports":[443],
  "allowed_methods":["GET","POST"],
  "allowed_check_classes":["sqli","xss","security_headers","open_redirect"],
  "max_requests":4000,"rate_limit_per_sec":10}' | jq -r .id)

# 4) create + start an assessment (feed it an OpenAPI/HAR/Postman artifact)
ASSESS=$(curl -s $BASE/v1/assessments $H -d "{
  \"target_id\":\"$TID\",\"authorization_id\":\"$AID\",
  \"artifacts\":[{\"kind\":\"openapi\",\"content\":\"$(cat openapi.json | python -c 'import json,sys;print(json.dumps(sys.stdin.read())[1:-1])')\"}]
}" | jq -r .id)
curl -s $BASE/v1/assessments/$ASSESS/start $H

# 5) watch it, then read findings + report
curl -s "$BASE/v1/assessments/$ASSESS/stream" $H          # live SSE
curl -s $BASE/v1/assessments/$ASSESS/findings $H | jq
curl -s "$BASE/v1/assessments/$ASSESS/report?fmt=markdown" $H
```

---

## Project layout

```text
app/
  api/            FastAPI routers + Pydantic schemas
  agents/         LLM brains, agent base + specialists, pool, A2A bus, capability router, registry
  checks/         security checks (sqli/xss/bola/headers/open_redirect) + declarative runtime
  core/           config, db, crypto, enums, auth, observability
  discovery/      OpenAPI/HAR/Postman/GraphQL parsers + crawler + normalization
  integrations/   MCP tool server
  models/         SQLAlchemy models
  orchestration/  the assessment engine (state machine) + LangGraph workflow
  security/       ScopeGuard, NetGuard, GuardedHttpClient, redaction  (the authorization layer)
  services/       ownership, sessions, planning, validation, scoring, reporting, remediation, regression, pdf
```

## Security model & scope

A sandbox protects the _execution environment_; it does **not** authorize activity
against external systems. Sentrik binds every assessment to an explicit
`AuthorizationRecord` and enforces it at the scheduler, tool gateway, network boundary,
and evidence store. Agents can never expand their own scope.

## License

[MIT](LICENSE) — with an **authorized-use-only** notice. You are responsible for having
permission to test any target.
