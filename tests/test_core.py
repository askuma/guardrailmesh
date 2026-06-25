"""Basic smoke tests for guardrailmesh core."""
import pytest
from guardrail_framework.core import (
    GuardrailFramework, GuardrailPolicy, GuardrailBackend,
    GuardrailResult, ActionType, get_framework,
)


def test_framework_initializes():
    fw = GuardrailFramework()
    assert "nemo" in fw.backends
    assert "custom" in fw.backends
    assert "ga_guard" not in fw.backends


def test_custom_backend_registered():
    fw = GuardrailFramework()
    assert GuardrailBackend.CUSTOM.value == "custom"
    assert "custom" in fw.backends


def test_no_ga_guard_in_enum():
    values = [b.value for b in GuardrailBackend]
    assert "ga_guard" not in values
    assert "custom" in values


def test_create_policy():
    fw = GuardrailFramework()
    policy = GuardrailPolicy(name="test", backend=GuardrailBackend.NEMO)
    pid = fw.create_policy(policy)
    assert pid in fw.policies


def test_no_redteam_imports():
    import guardrail_framework.core as core
    assert not hasattr(core, "RedTeamRunner")
    assert not hasattr(core, "ProbeLibrary")
    assert not hasattr(core, "ReportSigner")


def test_ten_vendor_backends():
    fw = GuardrailFramework()
    vendor_backends = [
        "nemo", "guardrails_ai", "presidio", "lakera",
        "openai_moderation", "azure_content_safety", "azure_prompt_shields",
        "aws_bedrock", "llama_firewall", "llm_guard",
    ]
    for b in vendor_backends:
        assert b in fw.backends, f"Missing backend: {b}"


def test_server_has_no_redteam_routes():
    import ast, inspect
    import guardrail_framework.server as srv
    src = inspect.getsource(srv)
    assert "/redteam/" not in src
    assert "report_signer" not in src
