"""
API key authentication middleware.

Keys are loaded from the GUARDRAIL_API_KEYS env var (comma-separated).
Set GUARDRAIL_AUTH_ENABLED=false to disable auth (dev only).

Admin keys (GUARDRAIL_ADMIN_KEYS) are a subset of keys that may call
destructive write operations: bundle import, policy deletion, rollback,
and poller management. When GUARDRAIL_ADMIN_KEYS is unset, all regular
API keys are treated as admin (backward-compatible). Set it explicitly
to enforce privilege separation.

Example::
    GUARDRAIL_API_KEYS=key1,key2
    GUARDRAIL_ADMIN_KEYS=key2
    GUARDRAIL_AUTH_ENABLED=true
"""

import logging
import os
import secrets
from typing import Set

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("auth")

# Exact paths that are always public (no API key needed).
_PUBLIC_PATHS: Set[str] = {
    "/health",
    "/ready",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics/prometheus",   # Prometheus scrape — secure at network level
    "/push/events",          # auth handled in route handler via ?api_key= query param
}

# First path-segments that belong to the API.  Any request whose first segment
# is in this set requires an X-API-Key header.  Everything else (root, static
# assets, SPA navigation URLs) is served by the React dashboard and is public.
# Add a new segment here whenever a new API route group is introduced.
_API_PREFIXES: frozenset = frozenset({
    "check", "policies", "abtests", "metrics", "audit", "alerts",
    "schema", "test", "decision-log", "bundles", "versions", "push",
    "precompiler", "status", "score", "data-providers", "redteam",
})


def load_api_keys() -> Set[str]:
    raw = os.getenv("GUARDRAIL_API_KEYS", "").strip()
    if not raw:
        key = secrets.token_hex(32)
        logger.warning("GUARDRAIL_API_KEYS not configured — generated ephemeral key for this process.")
        # Print directly to stderr so the key bypasses log shippers (Datadog, CloudWatch, etc.)
        import sys
        print(f"  Ephemeral API key: {key}", file=sys.stderr)
        print("  Set GUARDRAIL_API_KEYS=<key> in your environment to make it persistent.", file=sys.stderr)
        return {key}
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    logger.info(f"Loaded {len(keys)} API key(s) from environment.")
    return keys


def load_admin_keys(api_keys: Set[str]) -> Set[str]:
    """Return the set of keys permitted to call admin/destructive endpoints.

    When GUARDRAIL_ADMIN_KEYS is unset, all regular API keys are treated as
    admin (backward-compatible default). Set it explicitly to enforce privilege
    separation between read/check callers and policy-management callers.
    """
    raw = os.getenv("GUARDRAIL_ADMIN_KEYS", "").strip()
    if not raw:
        return set(api_keys)
    keys = {k.strip() for k in raw.split(",") if k.strip()}
    logger.info(f"Loaded {len(keys)} admin API key(s) from environment.")
    return keys


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated requests with 401."""

    def __init__(self, app, api_keys: Set[str], enabled: bool = True):
        super().__init__(app)
        self._keys = api_keys
        self._enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self._enabled:
            return await call_next(request)

        path = request.url.path

        # Explicit public paths (health probes, docs, Prometheus scrape, SSE).
        if path in _PUBLIC_PATHS:
            return await call_next(request)

        # Dashboard routes: anything whose first path segment is not a known API
        # prefix is served by the React SPA and requires no API key.
        first_seg = path.lstrip("/").split("/")[0]
        if first_seg not in _API_PREFIXES:
            return await call_next(request)

        key = request.headers.get("X-API-Key")
        if not key or key not in self._keys:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid API key. Pass it in the X-API-Key header."},
            )
        return await call_next(request)
