# Changelog

## [Unreleased]

---

## [0.2.1] — 2026-06-28

### Security

- **F1 — Admin key required on decision-log endpoints.** `POST /decision-log/configure` and `POST /decision-log/stop` now require `require_admin_key`. Previously any valid API key could reconfigure or halt the audit shipper, enabling audit trail manipulation.
- **F2 — PII scrubbed from dead-letter store.** `DecisionLogShipper._dead_letter()` now strips the raw `"text"` field from `detected_risks` before writing to the local `audit_log` table, preventing matched PII spans (email addresses, card numbers, SSNs) from leaking into persistent storage.
- **F3 — Admin key required on policy update endpoint.** `PATCH /policies/{policy_id}` now requires `require_admin_key`. Previously regular caller keys could weaken enforcement thresholds on live policies.
- **F4 — Async race condition in `_inject_policy_rules`.** `check_input_async`, `check_output_async`, and `validate_tool_call_async` now acquire a per-backend `asyncio.Lock` around the `_inject_policy_rules` call and the subsequent `await`, eliminating a race where an event-loop yield between config mutation and the actual check allowed another coroutine to overwrite shared backend config.

---

## [0.2.0] — 2026-06-28

### Added

- **Async-native core** — `GuardrailFramework` now exposes `async def check_input_async()`, `async def check_output_async()`, and `async def validate_tool_call_async()`. Safe to `await` from FastAPI route handlers, LangChain callbacks, and any other async context. All three accept an optional `raise_on_block=True` parameter.
- **`GuardrailBlocked` exception** — raised when `raise_on_block=True` and a check fails. Carries the full `GuardrailResult` as `.result` for downstream handling.
- **`GuardrailError` exception** — base class for internal framework errors; available for callers that want to handle guardrail failures separately from other exceptions.
- **True async HTTP for REST-backed backends** — Lakera Guard, OpenAI Moderation, Azure Content Safety, Azure Prompt Shields, and the Custom HTTP adapter now implement `acheck_input` / `acheck_output` using `httpx.AsyncClient` instead of thread-pool offloading. No threads consumed for network I/O on these backends.
- **Thread-pool fallback async for SDK-backed backends** — NeMo Guardrails, GuardrailsAI, Presidio, LlamaFirewall, LLM Guard, and AWS Bedrock backends implement `acheck_input` / `acheck_output` via `loop.run_in_executor(None, ...)`, so awaiting them never blocks the event loop even though the underlying SDK is synchronous.
- **`GuardrailMiddleware`** — Starlette/FastAPI ASGI middleware that runs `check_input_async` before every mutating request (`POST`, `PUT`, `PATCH`). Short-circuits with HTTP 400 when blocked. Configurable `text_field`, `skip_paths`, and `on_block_status`. Available from `guardrail_framework.middleware`.
- `httpx.AsyncClient` is used for all async backend HTTP calls; `httpx>=0.24.0` was already a core dependency.

### Changed

- `__version__` bumped to `0.2.0`.
- `__all__` in `guardrail_framework/__init__.py` extended with `GuardrailBlocked`, `GuardrailError`, `GuardrailMiddleware`.

---

## [0.1.1] — 2026-06-28

### Security / Production hardening

- **Audit log no longer stores raw input text.** `input_preview` replaced with `input_hash` (16-char SHA-256 prefix) and `input_length`. Prevents PII, credentials, and sensitive content from appearing in audit records — required for GDPR/HIPAA/PCI compliance.
- **`/metrics/prometheus` now requires an API key.** Removed from the public-path allowlist; Prometheus scrapers must send `X-API-Key`. Previously, internal topology (policy IDs, backend names, block rates) was exposed to unauthenticated callers.
- **`GUARDRAIL_AUTH_ENABLED=false` blocked in production.** Raises `RuntimeError` at startup when the database is not SQLite. Auth can only be disabled for local development against a local SQLite file.
- **CORS defaults to no origins.** `GUARDRAIL_CORS_ORIGINS` previously defaulted to `*`, allowing any browser origin to call the API. Default is now an empty list (no cross-origin access). Setting `*` explicitly logs a startup warning.
- **Escalation webhook and email are now fire-and-forget.** Both run in daemon threads so a slow or unreachable notification target never adds latency to a guardrail check response.
- **Fixed `GuardrailBackend.GA_GUARD` AttributeError** in `examples.py`. The enum value does not exist; corrected to `GuardrailBackend.CUSTOM` with a comment pointing to the `GA_GUARD_API_URL` env var.

### Added

- **`X-Request-ID` middleware.** Every response now echoes the caller's `X-Request-ID` header (or generates a UUID if absent), enabling end-to-end trace correlation across the LLM application, guardrailmesh, and the audit sink.
- **Real `/ready` readiness probe.** Previously always returned `{"ready": true}`. Now calls `PersistenceLayer.ping()` (`SELECT 1`) and returns `503 {"ready": false, "reason": "db_unavailable"}` when the database is unreachable. Kubernetes will hold replicas out of rotation until the DB recovers.
- **`PersistenceLayer.ping()`** — lightweight `SELECT 1` health check used by `/ready`.
- **Input size limit on check endpoints.** `POST /check/input`, `/check/output`, and `/check/tool` now reject text exceeding `GUARDRAIL_MAX_TEXT_LENGTH` characters (default `32000`) with HTTP 422, preventing OOM from oversized payloads.
- **`sensitivity` enum validation on policy create and update.** Values outside `{low, medium, high}` now return HTTP 422 with a clear error message instead of silently mapping to the `medium` threshold.

### Changed

- **`/health` no longer exposes internal topology.** Response trimmed to `{status, version}`. Backend names and policy count were previously visible on an unauthenticated endpoint.
- **Escalation email** extracted into `_do_email_send()` worker function; `_send_email()` is now a non-blocking launcher.
- **Escalation webhook** extracted into `_do_webhook_post()` worker function; `_send_webhook()` is now a non-blocking launcher.
- Removed 7 unused imports from `server.py` (`Path`, `datetime`, `timezone`, `GuardrailPolicy`, `DecisionEvent`, `PrometheusMetrics`, `WasmReadyScorer`, `StatusReporter`, `DataProviderRegistry`).

---

## [0.1.0] — 2026-06-25

### Added

- Unified guardrail enforcement layer supporting 10 vendor backends: NeMo Guardrails, GuardrailsAI, Microsoft Presidio, Lakera Guard, OpenAI Moderation, Azure Content Safety, Azure Prompt Shields, AWS Bedrock Guardrails, LlamaFirewall, LLM Guard
- Generic HTTP adapter (`CUSTOM` backend) for connecting any internal or third-party guardrail endpoint via `GA_GUARD_API_URL`
- 49 REST endpoints: guardrail checks, policy CRUD, A/B tests, observability, bundle distribution, policy versioning, real-time SSE push, partial evaluation, Prometheus metrics, WASM scorer, data providers
- Policy engine with BLOCK / REDACT / REWRITE / ESCALATE / RATE_LIMIT actions
- Agent tool call validation (`POST /check/tool`) to prevent OWASP LLM07 exploits
- A/B testing between two policies with deterministic user-sticky bucket assignment
- OPA-compatible bundle import/export with `X-Bundle-SHA256` header
- Server-Sent Events stream (`GET /push/events`) for zero-downtime policy updates
- Decision log shipping to any HTTP sink with configurable flush interval
- Policy versioning and rollback (`GET /policies/{id}/versions`, `POST /policies/{id}/rollback`)
- Prometheus metrics at `GET /metrics/prometheus`
- Per-policy health and latency percentiles at `GET /status`
- WASM-ready regex scorer (`POST /score/text`) for edge deployment
- In-memory blocklist data provider (`POST /data-providers/blocklist`)
- Declarative policy test runner (`POST /test/run`)
- React dashboard with 9 tabs: Overview, Live Test, Policies, Testing, Status, Versions, Alerts, A/B Tests, Audit Log
- SQLite persistence with optional PostgreSQL via `GUARDRAIL_DB_URL`
- Optional Redis for cross-replica rate limiting

### Backends

All backends degrade gracefully to the built-in regex/keyword scorer when their SDK or credentials are absent. Install optional extras for real enforcement:

```bash
pip install "guardrailmesh[nemo]"         # NeMo Guardrails
pip install "guardrailmesh[guardrails_ai]" # GuardrailsAI
pip install "guardrailmesh[presidio]"      # Microsoft Presidio
pip install "guardrailmesh[llamafirewall]" # LlamaFirewall
pip install "guardrailmesh[llm_guard]"     # LLM Guard
pip install "guardrailmesh[aws]"           # AWS Bedrock
pip install "guardrailmesh[all]"           # Everything
```
