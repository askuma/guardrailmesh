"""
guardrailmesh — Unified AI guardrail enforcement layer.

Supports NeMo Guardrails, GuardrailsAI, Presidio, Lakera Guard,
OpenAI Moderation, Azure Content Safety, Azure Prompt Shields,
AWS Bedrock Guardrails, LlamaFirewall, LLM Guard, and custom HTTP endpoints.
"""

from .core import (
    GuardrailFramework,
    GuardrailPolicy,
    GuardrailBackend,
    GuardrailResult,
    RiskCategory,
    ActionType,
    ABTestConfig,
    GuardrailBlocked,
    GuardrailError,
    get_framework,
)
from .middleware import GuardrailMiddleware

__version__ = "0.1.1"
__all__ = [
    # Core framework
    "GuardrailFramework",
    "GuardrailPolicy",
    "GuardrailBackend",
    "GuardrailResult",
    "RiskCategory",
    "ActionType",
    "ABTestConfig",
    "get_framework",
    # Exceptions
    "GuardrailBlocked",
    "GuardrailError",
    # Middleware
    "GuardrailMiddleware",
]
