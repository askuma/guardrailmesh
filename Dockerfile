# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build React dashboard
# ─────────────────────────────────────────────────────────────────────────────
FROM node:18-alpine AS dashboard-build

WORKDIR /dashboard

COPY guardrail-dashboard/package.json .
RUN npm install --silent

COPY guardrail-dashboard/public/ ./public/
COPY guardrail-dashboard/src/    ./src/

ENV REACT_APP_API_URL=""
RUN npm run build


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Python API + serve built dashboard as static files
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Ashutosh Kumar"
LABEL description="guardrailmesh — Unified AI guardrail enforcement layer"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install the framework package
COPY guardrail_framework/ ./guardrail_framework/
COPY pyproject.toml README.md LICENSE ./
RUN pip install --no-cache-dir -e .

# Install spaCy + Presidio and download the NLP model for PII detection.
RUN pip install --no-cache-dir \
    "spacy>=3.0.0" \
    "presidio-analyzer>=2.2.0" \
    "presidio-anonymizer>=2.2.0" \
    && python -m spacy download en_core_web_lg

# Install GuardrailsAI hub validators (free validators, no token required)
RUN pip install --no-cache-dir detect-secrets && \
    guardrails hub install hub://guardrails/detect_pii --quiet 2>/dev/null || true && \
    guardrails hub install hub://guardrails/secrets_present --quiet 2>/dev/null || true && \
    pip cache purge 2>/dev/null || true

# Copy the compiled React app from stage 1
COPY --from=dashboard-build /dashboard/build ./guardrail_framework/static/

# Patch server.py to serve the React build
COPY patch_static.py .
RUN python patch_static.py

# Create persistent data directories
RUN mkdir -p /app/data

# Entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Pin OTel exporter versions for compatibility with guardrails-ai
RUN pip install --no-cache-dir \
        "opentelemetry-exporter-otlp-proto-http<1.27.0" \
        "opentelemetry-exporter-otlp-proto-grpc<1.27.0" \
        "opentelemetry-exporter-otlp-proto-common<1.27.0" && \
    pip cache purge 2>/dev/null || true && \
    find /usr/local/lib/python3.11 -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Non-root user
RUN useradd -m -u 1000 guardrail && \
    mkdir -p /app/hf_models && \
    chown -R guardrail:guardrail /app /app/data /app/hf_models

# /app/site-packages bind-mount for llamafirewall + llm-guard
RUN echo "/app/site-packages" >> /usr/local/lib/python3.11/site-packages/app_extras.pth

USER guardrail

ENV HF_HOME=/app/hf_models

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "guardrail_framework.server:app", \
    "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
