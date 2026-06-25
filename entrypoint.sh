#!/bin/bash
set -e

# Install premium GuardrailsAI hub validators when GUARDRAILS_TOKEN is provided.
#
# Free validators (DetectPII, SecretsPresent) are pre-baked into the image at
# build time and need no token.  Premium validators (ToxicLanguage) require an
# account token and are installed here at container start so the token is never
# baked into the image layer.
#
# Validators are written to ~/.guardrails/ which lives in the guardrail user's
# home directory.  They persist for the container's lifetime; recreating the
# container triggers a fresh install.

if [ -n "${GUARDRAILS_TOKEN}" ]; then
    echo "[guardrails] Token detected — configuring guardrails hub access..."

    # Write config directly instead of using `guardrails configure` — the CLI
    # --enable-metrics flag syntax has changed across versions and is unreliable.
    mkdir -p "${HOME}/.guardrails"
    printf '[DEFAULT]\ntoken = %s\nenable_metrics = False\n' "${GUARDRAILS_TOKEN}" \
        > "${HOME}/.guardrails/config"

    # Write pip.conf so every pip invocation — including the subprocess that
    # `guardrails hub install` spawns internally — installs to ~/.local without
    # needing root.  PIP_USER=1 on its own is not inherited by subprocesses.
    mkdir -p "${HOME}/.config/pip"
    printf '[global]\nuser = true\n' > "${HOME}/.config/pip/pip.conf"

    echo "[guardrails] Hub access configured."
    echo "[guardrails] NOTE: hub://guardrails/toxic_language requires a paid guardrails plan."
    echo "[guardrails] Toxicity detection is provided by LLM Guard (free, no token required)."
else
    echo "[guardrails] No GUARDRAILS_TOKEN set — running with free validators (DetectPII, SecretsPresent, LLM Guard)."
fi

# NeMo Guardrails uses OPENAI_API_KEY for LLM-based intent classification.
# A default colang policy covering OWASP LLM01 patterns is built into the
# backend and requires no extra setup.  When OPENAI_API_KEY is set, NeMo
# classifies subtle injection variants the colang patterns might miss.
if [ -n "${OPENAI_API_KEY}" ]; then
    echo "[nemo] OPENAI_API_KEY detected — NeMo will use LLM-based intent classification"
else
    echo "[nemo] No OPENAI_API_KEY — NeMo will use colang pattern-matching only"
fi

exec "$@"
