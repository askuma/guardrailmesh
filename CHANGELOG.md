# Changelog

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
