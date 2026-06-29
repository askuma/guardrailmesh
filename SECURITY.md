# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes — receives security fixes |
| 0.1.x | No — upgrade to 0.2.x |

## Reporting a vulnerability

**Do not open a GitHub issue for security vulnerabilities.** Public issues expose the vulnerability before a fix is available, putting all users at risk.

### Private disclosure

Email **ashuthemaddy@gmail.com** with the subject line `[SECURITY] guardrailmesh — <brief description>`.

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code, curl commands, etc.)
- Affected version(s) and component(s)
- Any mitigations you are already aware of

You will receive an acknowledgment within **48 hours** and a status update within **7 days** indicating whether the report has been accepted or declined with reasoning.

### What to expect

1. We confirm the report and begin investigation (within 48 hours)
2. We determine severity (using CVSS 3.1) and develop a fix
3. We coordinate a release date with you
4. We publish the fix and a GitHub Security Advisory simultaneously
5. We credit you in the advisory unless you prefer to remain anonymous

We ask that you give us a reasonable window (typically 90 days) to release a fix before any public disclosure.

## Scope

### In scope

- Authentication and authorization bypasses in the REST API
- Privilege escalation (regular API key accessing admin endpoints)
- PII or credential leakage through audit logs, decision logs, or error responses
- Prompt injection that bypasses enforcement policies
- Denial-of-service via malformed payloads or resource exhaustion
- Dependencies with known CVEs affecting guardrailmesh functionality

### Out of scope

- Vulnerabilities in optional backend SDKs (NeMo, Presidio, etc.) — report those to the respective upstream projects
- Issues requiring physical access to the host
- Social engineering
- Vulnerabilities in infrastructure you operate (your Kubernetes cluster, database, etc.)

## Security design notes

- All destructive endpoints require a separate admin key (`GUARDRAIL_ADMIN_KEYS`) distinct from regular API keys
- Audit logs store `input_hash` (SHA-256 prefix) and `input_length`, never raw input text
- `GUARDRAIL_AUTH_ENABLED=false` is blocked at startup when the database is not SQLite
- CORS defaults to no allowed origins; `*` logs a startup warning
- Rate limiting uses Redis for cross-replica enforcement when `GUARDRAIL_REDIS_URL` is set
