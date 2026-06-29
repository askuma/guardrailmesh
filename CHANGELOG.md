# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

---

## [0.1.0] — 2026-06-29

Initial public release.

### Backends

10 vendor backends with graceful regex fallback when the SDK or credentials are absent:

| Backend | Install extra |
|---|---|
| NeMo Guardrails | `guardrailmesh[nemo]` |
| GuardrailsAI | `guardrailmesh[guardrails_ai]` |
| Microsoft Presidio | `guardrailmesh[presidio]` |
| LlamaFirewall | `guardrailmesh[llamafirewall]` |
| LLM Guard | `guardrailmesh[llm_guard]` |
| AWS Bedrock Guardrails | `guardrailmesh[aws]` |
| Lakera Guard | _(REST API — no extra needed)_ |
| OpenAI Moderation | _(REST API — no extra needed)_ |
| Azure Content Safety | _(REST API — no extra needed)_ |
| Azure Prompt Shields | _(REST API — no extra needed)_ |

### Policy engine

- BLOCK, REDACT, REWRITE, ESCALATE, RATE_LIMIT actions per policy
- Per-policy sensitivity threshold (`low` / `medium` / `high`)
- Allowed and forbidden tool allowlists for agent tool call validation
- A/B testing between two policies with deterministic user-sticky bucket assignment

### Async-native SDK

- `check_input_async`, `check_output_async`, `validate_tool_call_async` — all three are native coroutines safe to `await` from FastAPI route handlers or any async context
- `raise_on_block=True` raises `GuardrailBlocked` (carries full `GuardrailResult`) instead of returning
- REST-backed backends (Lakera, OpenAI Moderation, Azure, Custom HTTP) use `httpx.AsyncClient` — no threads consumed for network I/O
- SDK-backed backends (NeMo, GuardrailsAI, Presidio, LlamaFirewall, LLM Guard, AWS Bedrock) use `loop.run_in_executor` — event loop never blocked
- Per-backend `asyncio.Lock` guards `_inject_policy_rules` + the awaited call, preventing cross-coroutine config contamination under concurrent traffic
- `GuardrailMiddleware` — Starlette/FastAPI ASGI middleware; short-circuits with HTTP 400 on block; configurable `text_field`, `skip_paths`, and `on_block_status`

### REST API

49 endpoints:

- `POST /check/input` — check text before it reaches your model
- `POST /check/output` — check model output before returning to user
- `POST /check/tool` — validate agent tool calls (OWASP LLM07)
- `GET/POST /policies` — full policy CRUD
- `GET /policies/{id}/versions`, `POST /policies/{id}/rollback` — policy versioning
- `GET/POST /abtests` — A/B test two policies against live traffic
- `GET /metrics/prometheus` — Prometheus scrape endpoint _(requires API key)_
- `GET /push/events` — Server-Sent Events for real-time zero-downtime policy updates
- `POST /bundles/import` — OPA-compatible bundle import
- `GET /status` — per-policy health and latency percentiles
- `GET /health`, `GET /ready` — liveness and readiness probes

### Security

- API key authentication on all non-probe endpoints (`GUARDRAIL_API_KEYS`)
- Separate admin key tier (`GUARDRAIL_ADMIN_KEYS`) required for policy mutation, bundle import, and decision-log configuration; regular keys cannot reach destructive endpoints
- Audit log stores `input_hash` (SHA-256 prefix) and `input_length` — never raw input text (GDPR/HIPAA/PCI)
- Dead-letter path strips raw PII spans from `detected_risks` before writing to the audit log
- `GUARDRAIL_AUTH_ENABLED=false` blocked at startup when the database is not SQLite
- CORS defaults to no allowed origins; `*` logs a startup warning
- Input size limit on check endpoints (`GUARDRAIL_MAX_TEXT_LENGTH`, default 32 000 chars)
- `X-Request-ID` echoed on every response for end-to-end trace correlation

### Observability

- Prometheus metrics at `GET /metrics/prometheus`
- Decision log shipping to any HTTP sink (`POST /decision-log/configure`) with chunked upload, exponential backoff, and dead-letter fallback to local audit log
- Per-policy latency percentiles in `GET /status`
- React dashboard with 9 tabs: Overview, Live Test, Policies, Testing, Status, Versions, Alerts, A/B Tests, Audit Log

### Infrastructure

- SQLite by default; PostgreSQL via `GUARDRAIL_DB_URL`
- Redis for cross-replica rate limiting via `GUARDRAIL_REDIS_URL`; without it, rate limits are per-process with a startup warning
- Alembic migrations (`alembic upgrade head`)
- Docker + `docker-compose.yml` included
- GitHub Actions CI: tests on Python 3.9 – 3.12
- GitHub Actions release workflow: builds sdist + wheel on version tag, publishes to PyPI via OIDC trusted publishing, creates GitHub release with changelog notes
