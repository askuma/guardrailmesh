"""
guardrailmesh FastAPI / Starlette middleware.

Adds guardrail checks to any ASGI application with three lines::

    from guardrail_framework.middleware import GuardrailMiddleware
    from guardrail_framework.core import get_framework

    framework = get_framework()
    policy_id = framework.create_policy(policy)

    app.add_middleware(
        GuardrailMiddleware,
        framework=framework,
        policy_id=policy_id,
    )

Every POST / PUT / PATCH request whose JSON body contains the configured
``text_field`` (default ``"message"``) is checked *before* the route handler
runs.  When the guardrail blocks, the middleware short-circuits with an HTTP
400 response; the route handler is never called.

Optional parameters
-------------------
text_field : str
    JSON body key that holds the text to check (default ``"message"``).
skip_paths : set[str]
    URL paths that bypass guardrail checks (default: ``{"/health", "/ready"}``).
on_block_status : int
    HTTP status returned when a check fails (default ``400``).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Set

logger = logging.getLogger("guardrailmesh.middleware")

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    _STARLETTE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _STARLETTE_AVAILABLE = False
    BaseHTTPMiddleware = object  # type: ignore[assignment,misc]


_DEFAULT_SKIP_PATHS: frozenset = frozenset({"/health", "/ready", "/docs", "/openapi.json", "/redoc"})


class GuardrailMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """
    ASGI middleware that calls :meth:`~guardrail_framework.core.GuardrailFramework.check_input_async`
    on every mutating request before the route handler runs.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    framework:
        A configured :class:`~guardrail_framework.core.GuardrailFramework` instance.
    policy_id:
        ID of the guardrail policy to enforce.
    text_field:
        JSON body key that contains the user-supplied text (default ``"message"``).
    skip_paths:
        URL paths exempt from guardrail checks.  Probe endpoints and static
        assets should be listed here.
    on_block_status:
        HTTP status code returned when the guardrail blocks a request (default ``400``).
    """

    def __init__(
        self,
        app: Any,
        *,
        framework: Any,
        policy_id: str,
        text_field: str = "message",
        skip_paths: Optional[Set[str]] = None,
        on_block_status: int = 400,
    ) -> None:
        if not _STARLETTE_AVAILABLE:
            raise ImportError(
                "GuardrailMiddleware requires starlette. "
                "Install it with: pip install starlette  (or: pip install fastapi)"
            )
        super().__init__(app)
        self._framework = framework
        self._policy_id = policy_id
        self._text_field = text_field
        self._skip_paths = frozenset(skip_paths) | _DEFAULT_SKIP_PATHS if skip_paths else _DEFAULT_SKIP_PATHS
        self._on_block_status = on_block_status

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        if request.url.path in self._skip_paths:
            return await call_next(request)

        text = await self._extract_text(request)
        if not text:
            return await call_next(request)

        try:
            result = await self._framework.check_input_async(
                text,
                self._policy_id,
                context={"path": request.url.path, "method": request.method},
            )
        except Exception as exc:
            logger.error("GuardrailMiddleware check failed: %s — allowing request through", exc)
            return await call_next(request)

        if not result.passed:
            logger.warning(
                "GuardrailMiddleware blocked %s %s: action=%s risks=%s",
                request.method,
                request.url.path,
                result.action.value,
                [r.get("type") for r in result.detected_risks],
            )
            return JSONResponse(
                status_code=self._on_block_status,
                content={
                    "blocked": True,
                    "action": result.action.value,
                    "risks": result.detected_risks,
                    "request_id": result.request_id,
                },
            )

        return await call_next(request)

    async def _extract_text(self, request: Request) -> Optional[str]:
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return None
        try:
            body_bytes = await request.body()
            if not body_bytes:
                return None
            body: Dict[str, Any] = json.loads(body_bytes)
            return str(body.get(self._text_field, "")) or None
        except Exception:
            return None
