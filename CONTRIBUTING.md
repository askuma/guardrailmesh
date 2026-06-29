# Contributing to guardrailmesh

Thank you for taking the time to contribute. This document covers everything you need to get from idea to merged pull request.

---

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Before you start](#before-you-start)
- [Development setup](#development-setup)
- [Making changes](#making-changes)
- [Testing](#testing)
- [Submitting a pull request](#submitting-a-pull-request)
- [Reporting security vulnerabilities](#reporting-security-vulnerabilities)

---

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it. Report unacceptable behavior to the maintainers via the email listed in `SECURITY.md`.

---

## Ways to contribute

| Type | Where |
|---|---|
| Bug report | [GitHub Issues](https://github.com/askuma/guardrailmesh/issues/new?template=bug_report.yml) |
| Feature request | [GitHub Issues](https://github.com/askuma/guardrailmesh/issues/new?template=feature_request.yml) |
| Security vulnerability | See [SECURITY.md](SECURITY.md) — **do not open a public issue** |
| Code change | Fork → branch → PR against `main` |
| Documentation fix | Same PR flow as code |
| New backend adapter | Open a feature request first so we can align on the interface |

---

## Before you start

- **Search existing issues and PRs.** Your idea may already be in flight.
- **Open an issue before large changes.** For anything beyond a small bug fix or docs tweak, open an issue to discuss scope and approach before writing code. This saves everyone time.
- **One thing per PR.** PRs that mix unrelated changes take longer to review and are harder to revert if something goes wrong.

---

## Development setup

```bash
git clone https://github.com/askuma/guardrailmesh.git
cd guardrailmesh

# Python 3.9+ required
python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"

# Run database migrations (SQLite by default)
alembic upgrade head
```

Copy the example environment file and fill in any backend credentials you need for testing:

```bash
cp .env.example .env
```

Verify the setup:

```bash
pytest tests/ -v
```

### Optional backend dependencies

Install only the extras you need:

```bash
pip install -e ".[presidio]"      # Microsoft Presidio (PII detection)
pip install -e ".[llamafirewall]" # LlamaFirewall (local prompt injection)
pip install -e ".[llm_guard]"     # LLM Guard (local toxicity + injection)
pip install -e ".[nemo]"          # NVIDIA NeMo Guardrails
pip install -e ".[guardrails_ai]" # GuardrailsAI
pip install -e ".[aws]"           # AWS Bedrock Guardrails
pip install -e ".[all]"           # Everything
```

---

## Making changes

### Branch naming

```
fix/<short-description>       # bug fixes
feat/<short-description>      # new features
docs/<short-description>      # documentation only
refactor/<short-description>  # no behaviour change
```

### Code style

- **Formatter:** `black` with `line-length = 100`
- **Type hints:** required for all public API surface (function signatures, class attributes)
- **Comments:** only when the *why* is non-obvious; never narrate what the code already says
- **No print statements** in library code — use `logging`
- Run before committing:

```bash
black guardrail_framework/ tests/
```

### Adding a new backend

1. Create `guardrail_framework/backends/<name>.py` — subclass `GuardrailBackendInterface`
2. Implement `check_input`, `check_output`, `validate_tool_call`
3. Add async overrides (`acheck_input`, `acheck_output`, `avalidate_tool_call`) — use `httpx.AsyncClient` for HTTP backends, `loop.run_in_executor` for SDK backends
4. Add the backend enum value to `GuardrailBackend` in `core.py`
5. Wire it into `_initialize_backends()` in `GuardrailFramework`
6. Add a row to the backend table in `README.md`
7. Add an optional extras group in `pyproject.toml`
8. Cover it with at least one test in `tests/`

---

## Testing

```bash
# All tests
pytest tests/ -v

# Single file
pytest tests/test_core.py -v

# With async tests
pytest tests/ -v --asyncio-mode=auto
```

All PRs must pass the full test suite and the CI checks (route count assertion, no redteam imports). New behaviour must include tests — patches that reduce coverage will not be merged.

---

## Submitting a pull request

1. Fork the repo and create a branch from `main`
2. Make your changes, add tests, run `pytest` locally
3. Push to your fork and open a PR against `main`
4. Fill in the PR template — description, test plan, related issues
5. A maintainer will review within 5 business days

PRs are merged via **squash merge**. Your commit message will be the PR title, so write a concise, imperative-mood title (e.g. `fix: strip PII from dead-letter events` not `Fixed the bug where PII was stored`).

### PR checklist

- [ ] `pytest tests/` passes locally
- [ ] New public API has type hints
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if behaviour changed
- [ ] `pyproject.toml` version not bumped (maintainers handle releases)
- [ ] No secrets, credentials, or personal data in the diff

---

## Reporting security vulnerabilities

**Do not open a GitHub issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
