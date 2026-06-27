"""
Guardrail Framework Usage Examples
Demonstrates how to use the framework in real-world scenarios
"""

import sys
import os

try:
    from guardrail_framework.core import (
        GuardrailFramework, GuardrailBackend,
        RiskCategory, ActionType, ABTestConfig
    )
    from guardrail_framework.compiler import PolicyCompiler, UnifiedPolicyBuilder, PolicyTemplates
    from guardrail_framework.observability import ObservabilityStack
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from guardrail_framework.core import (
        GuardrailFramework, GuardrailBackend,
        RiskCategory, ActionType, ABTestConfig
    )
    from guardrail_framework.compiler import PolicyCompiler, UnifiedPolicyBuilder, PolicyTemplates
    from guardrail_framework.observability import ObservabilityStack


# ============================================================================
# Example 1: Basic Setup - Create and Apply a Policy
# ============================================================================

def example_basic_setup():
    """Basic guardrail setup with a single policy"""
    print("\n=== Example 1: Basic Setup ===\n")
    
    # Initialize framework
    framework = GuardrailFramework()
    
    # Create a policy using the builder
    policy = UnifiedPolicyBuilder() \
        .with_name("Production Chat Policy") \
        .with_backend(GuardrailBackend.GUARDRAILS_AI) \
        .with_risk_categories([
            RiskCategory.PROMPT_INJECTION,
            RiskCategory.DATA_LEAKAGE
        ]) \
        .with_sensitivity("high") \
        .with_action(ActionType.BLOCK) \
        .build()
    
    # Register policy
    policy_id = framework.create_policy(policy)
    print(f"✓ Created policy: {policy_id}")
    
    # Test guardrail with input
    result = framework.check_input(
        "DROP TABLE users;",
        policy_id,
        context={"user_id": "test-user"}
    )
    
    print(f"✓ Input check passed: {result.passed}")
    print(f"  Risk score: {result.risk_score:.2f}")
    print(f"  Latency: {result.latency_ms:.1f}ms")
    
    return framework, policy_id


# ============================================================================
# Example 2: Multi-Backend Routing - Same Policy, Different Backends
# ============================================================================

def example_multi_backend():
    """Deploy the same policy to every backend without changing application code.

    Backends are grouped by what credentials they need:
      - Local / no credentials:  Presidio, LlamaFirewall, LLM Guard
      - Free API key:            GuardrailsAI (hub token), NeMo (OpenAI key),
                                 OpenAI Moderation (OPENAI_API_KEY)
      - Cloud credentials:       Lakera, GA Guard, Azure Content Safety,
                                 Azure Prompt Shields, AWS Bedrock
    """
    print("\n=== Example 2: Multi-Backend Routing ===\n")

    framework = GuardrailFramework()
    compiler = PolicyCompiler()

    base_policy = UnifiedPolicyBuilder() \
        .with_name("Multi-Backend Policy") \
        .with_risk_categories([RiskCategory.PROMPT_INJECTION, RiskCategory.DATA_LEAKAGE]) \
        .with_sensitivity("high") \
        .with_action(ActionType.BLOCK) \
        .build()

    # All supported backends — the framework routes to whichever has credentials.
    # Backends without the required env vars return ActionType.SKIPPED gracefully.
    all_backends = [
        # ── Local, no credentials required ──────────────────────────────────
        GuardrailBackend.PRESIDIO,          # PII detection via spaCy
        GuardrailBackend.GUARDRAILS_AI,     # Hub validators (DetectPII, SecretsPresent)
        GuardrailBackend.LLAMA_FIREWALL,    # Meta PromptGuard 2 — fully local
        GuardrailBackend.LLM_GUARD,         # PromptInjection + Toxicity — fully local
        # ── Requires OPENAI_API_KEY ──────────────────────────────────────────
        GuardrailBackend.NEMO,              # NeMo Guardrails with LLM classification
        GuardrailBackend.OPENAI_MODERATION, # OpenAI Moderation API
        # ── Requires cloud credentials ───────────────────────────────────────
        GuardrailBackend.LAKERA,            # LAKERA_GUARD_API_KEY
        GuardrailBackend.CUSTOM,            # GA_GUARD_API_URL + GA_GUARD_API_KEY
        GuardrailBackend.AZURE_CONTENT_SAFETY,   # AZURE_CONTENT_SAFETY_ENDPOINT + KEY
        GuardrailBackend.AZURE_PROMPT_SHIELDS,   # AZURE_CONTENT_SAFETY_ENDPOINT + KEY
        GuardrailBackend.AWS_BEDROCK,            # AWS_* credentials + guardrail ARN
    ]

    for backend in all_backends:
        base_policy.backend = backend
        policy_id = framework.create_policy(base_policy)
        compiled = compiler.compile(base_policy, backend)
        print(f"✓ Deployed to {backend.value}")
        print(f"  Policy ID: {policy_id}")
        print(f"  Config keys: {list(compiled.keys())}\n")


# ============================================================================
# Example 3: A/B Testing - Compare Two Policies
# ============================================================================

def example_ab_testing():
    """Set up A/B test comparing strict vs. balanced policies"""
    print("\n=== Example 3: A/B Testing ===\n")
    
    framework = GuardrailFramework()
    
    # Create two policies to compare
    strict_policy = PolicyTemplates.strict_security()
    balanced_policy = PolicyTemplates.balanced()
    
    strict_id = framework.create_policy(strict_policy)
    balanced_id = framework.create_policy(balanced_policy)
    
    print(f"✓ Created strict policy: {strict_id}")
    print(f"✓ Created balanced policy: {balanced_id}")
    
    # Create A/B test
    ab_test = ABTestConfig(
        name="Security vs. Usability",
        control_policy_id=strict_id,
        experiment_policy_id=balanced_id,
        traffic_split=0.5,  # 50/50 split
        duration_hours=24,
        metrics_to_track=[
            "block_rate",
            "latency_ms",
            "user_satisfaction"
        ]
    )
    
    test_id = framework.create_ab_test(ab_test)
    print(f"✓ Created A/B test: {test_id}")
    
    # Simulate traffic being routed
    print("\nSimulating request routing:")
    for i in range(10):
        policy_id = framework.get_policy_for_abtest(test_id)
        policy = framework.policies[policy_id]
        print(f"  Request {i+1}: Routed to {policy.name} ({policy_id[:8]}...)")


# ============================================================================
# Example 4: Agent-Specific Guardrails
# ============================================================================

def example_agent_guardrails():
    """Guardrails specifically for autonomous agent execution"""
    print("\n=== Example 4: Agent-Specific Guardrails ===\n")
    
    framework = GuardrailFramework()
    
    # Create agent policy with tool restrictions
    agent_policy = UnifiedPolicyBuilder() \
        .with_name("Autonomous Agent Safety") \
        .with_backend(GuardrailBackend.NEMO) \
        .with_risk_categories([
            RiskCategory.MALICIOUS_TOOL_USE,
            RiskCategory.UNSAFE_CODE,
            RiskCategory.DOS
        ]) \
        .with_sensitivity("high") \
        .with_action(ActionType.BLOCK) \
        .with_rules({
            "max_tool_calls_per_minute": 10,
            "max_concurrent_agents": 5,
            "allowed_tools": ["read_file", "search", "calculate", "send_email"],
            "forbidden_tools": ["delete_file", "exec_code", "drop_table", "rm_rf"],
            "max_file_size_mb": 100,
            "forbidden_domains": ["internal-admin.local"]
        }) \
        .build()
    
    policy_id = framework.create_policy(agent_policy)
    print(f"✓ Created agent policy: {policy_id}\n")
    
    # Validate various tool calls
    test_calls = [
        ("read_file", {"path": "/data/report.txt"}),
        ("search", {"query": "weather in NYC"}),
        ("delete_file", {"path": "/critical/data.db"}),
        ("exec_code", {"code": "import os; os.system('rm -rf /')"}),
    ]
    
    print("Validating tool calls:")
    for tool_name, args in test_calls:
        result = framework.validate_tool_call(
            policy_id,
            tool_name,
            args,
            context={"agent_id": "agent-001"}
        )
        status = "✓ ALLOWED" if result.passed else "✗ BLOCKED"
        print(f"  {status}: {tool_name}")


# ============================================================================
# Example 5: Observability and Monitoring
# ============================================================================

def example_observability():
    """Set up comprehensive monitoring and observability"""
    print("\n=== Example 5: Observability and Monitoring ===\n")
    
    framework = GuardrailFramework()
    observability = ObservabilityStack()
    
    # Create a policy
    policy = PolicyTemplates.balanced()
    policy_id = framework.create_policy(policy)
    
    # Simulate guardrail checks with metrics recording
    test_inputs = [
        ("legitimate request", 45.2, True, 0.1),
        ("user@example.com data leak", 52.1, False, 0.75),
        ("normal query", 43.8, True, 0.05),
        ("DROP TABLE users", 48.5, False, 0.92),
        ("another legit request", 44.3, True, 0.08),
    ]
    
    print("Recording guardrail checks:")
    for text, latency, passed, risk_score in test_inputs:
        result = framework.check_input(text, policy_id)
        
        observability.record_guardrail_check(
            policy_id,
            backend="guardrails_ai",
            input_text=text,
            output_text="[REDACTED]" if not passed else text,
            passed=passed,
            risk_score=risk_score,
            latency_ms=latency
        )
        
        status = "✓" if passed else "✗"
        print(f"  {status} {text[:40]:40} | Risk: {risk_score:.2f} | {latency:.1f}ms")
    
    # Get metrics
    print("\n📊 Metrics Summary:")
    dashboard = observability.get_dashboard_data()
    
    for metric_name, stats in dashboard["metrics"].items():
        if stats:
            print(f"  {metric_name}:")
            print(f"    Latest: {stats.get('latest', 0):.2f}")
            print(f"    Avg: {stats.get('avg', 0):.2f}")
            print(f"    Max: {stats.get('max', 0):.2f}")
    
    # Check alerts
    print("\n🚨 Active Alerts:")
    alerts = dashboard["alerts"]["active"]
    if alerts:
        for alert in alerts:
            print(f"  - {alert.title}")
            print(f"    Severity: {alert.severity.value}")
    else:
        print("  No active alerts")


# ============================================================================
# Example 6: Policy Export and Portability
# ============================================================================

def example_policy_export():
    """Export policies for backup, migration, or sharing"""
    print("\n=== Example 6: Policy Export and Portability ===\n")
    
    framework = GuardrailFramework()
    
    # Create a complex policy
    policy = UnifiedPolicyBuilder() \
        .with_name("Enterprise Data Protection") \
        .with_description("Comprehensive policy for enterprise deployment") \
        .with_backend(GuardrailBackend.GUARDRAILS_AI) \
        .with_risk_categories([
            RiskCategory.PROMPT_INJECTION,
            RiskCategory.DATA_LEAKAGE,
            RiskCategory.UNSAFE_CODE
        ]) \
        .with_sensitivity("high") \
        .with_action(ActionType.REDACT) \
        .with_escalation_email("security@company.com") \
        .with_tag("enterprise") \
        .with_tag("compliance") \
        .build()
    
    policy_id = framework.create_policy(policy)
    
    # Export as JSON
    json_export = framework.export_policy(policy_id, format="json")
    print("Exported to JSON:")
    print(json_export[:200] + "...\n")
    
    # Export as YAML
    yaml_export = framework.export_policy(policy_id, format="yaml")
    print("Exported to YAML:")
    print(yaml_export[:200] + "...\n")


# ============================================================================
# Example 7: Dynamic Policy Updates
# ============================================================================

def example_dynamic_policy_updates():
    """Update policies at runtime without downtime"""
    print("\n=== Example 7: Dynamic Policy Updates ===\n")
    
    framework = GuardrailFramework()
    
    # Create initial policy
    policy = UnifiedPolicyBuilder() \
        .with_name("Adaptive Policy") \
        .with_sensitivity("medium") \
        .with_action(ActionType.BLOCK) \
        .build()
    
    policy_id = framework.create_policy(policy)
    print(f"✓ Created policy: {policy.name}")
    print(f"  Sensitivity: {policy.sensitivity}")
    print(f"  Action: {policy.action_on_violation.value}")
    
    # Update sensitivity
    print("\n📝 Updating policy...")
    framework.update_policy(policy_id, {
        "sensitivity": "high",
        "action_on_violation": ActionType.REDACT
    })
    
    updated = framework.policies[policy_id]
    print(f"✓ Policy updated")
    print(f"  Sensitivity: {updated.sensitivity}")
    print(f"  Action: {updated.action_on_violation.value}")


# ============================================================================
# Example 8: Compliance Reporting
# ============================================================================

def example_compliance_reporting():
    """Generate compliance reports for audit purposes"""
    print("\n=== Example 8: Compliance Reporting ===\n")
    
    framework = GuardrailFramework()
    observability = ObservabilityStack()
    
    # Create policies and simulate checks
    policy = PolicyTemplates.privacy_focused()
    policy_id = framework.create_policy(policy)
    
    # Simulate various checks
    checks = [
        ("user_name_field", 50.5, False, 0.85),
        ("user_email_field", 48.2, False, 0.90),
        ("legitimate_query", 45.1, True, 0.10),
    ]
    
    for text, latency, passed, risk in checks:
        observability.record_guardrail_check(
            policy_id, "presidio", text, "[REDACTED]" if not passed else text,
            passed, risk, latency
        )
    
    # Generate compliance report
    print("🔐 Privacy Compliance Report\n")
    print(f"Policy: {policy.name}")
    print(f"Period: 24 hours")
    
    metrics = observability.metrics.get_metric_summary("check_count", hours=24)
    print(f"\nCheck Statistics:")
    print(f"  Total checks: {metrics.get('count', 0)}")
    
    pass_metrics = observability.metrics.get_metric_summary("pass_rate", hours=24)
    if pass_metrics:
        compliance_rate = pass_metrics.get('avg', 0) * 100
        print(f"  Compliance rate: {compliance_rate:.1f}%")
    
    print(f"\nAudit Log Entries: {len(observability.audit.entries)}")


# ============================================================================
# Main: Run All Examples
# ============================================================================

def main():
    """Run all examples"""
    print("=" * 70)
    print("GUARDRAIL FRAMEWORK ABSTRACTION LAYER - EXAMPLES")
    print("=" * 70)
    
    try:
        example_basic_setup()
        example_multi_backend()
        example_ab_testing()
        example_agent_guardrails()
        example_observability()
        example_policy_export()
        example_dynamic_policy_updates()
        example_compliance_reporting()
        
        print("\n" + "=" * 70)
        print("✅ All examples completed successfully!")
        print("=" * 70)
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
