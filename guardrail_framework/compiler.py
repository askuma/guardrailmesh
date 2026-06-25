"""
Unified Policy Language Compiler
Converts unified policy format to backend-specific configurations (Colang, YAML, etc.)
"""

import json
from typing import Dict, Any, Optional
from .core import GuardrailPolicy, RiskCategory, ActionType, GuardrailBackend


class PolicyCompiler:
    """Compile unified policy format to backend-specific configurations"""

    def __init__(self):
        self.compilers = {
            GuardrailBackend.NEMO:                  self.compile_to_colang,
            GuardrailBackend.GUARDRAILS_AI:         self.compile_to_guardrails_yaml,
            GuardrailBackend.PRESIDIO:              self.compile_to_presidio,
            GuardrailBackend.LLAMA_FIREWALL:        self.compile_to_llama_firewall,
            GuardrailBackend.LLM_GUARD:             self.compile_to_llm_guard,
            GuardrailBackend.OPENAI_MODERATION:     self.compile_to_openai_moderation,
            GuardrailBackend.AZURE_CONTENT_SAFETY:  self.compile_to_azure_content_safety,
            GuardrailBackend.AZURE_PROMPT_SHIELDS:  self.compile_to_azure_prompt_shields,
            GuardrailBackend.AWS_BEDROCK:           self.compile_to_aws_bedrock,
            GuardrailBackend.LAKERA:                self.compile_to_lakera,
            GuardrailBackend.GA_GUARD:              self.compile_to_ga_guard,
        }

    def compile(self, policy: GuardrailPolicy, target_backend: Optional[GuardrailBackend] = None) -> Dict[str, Any]:
        """Compile policy to target backend format."""
        backend = target_backend or policy.backend
        compiler_func = self.compilers.get(backend)

        if not compiler_func:
            # Unknown / custom backend — return a generic representation so
            # callers never need to handle a ValueError from the compiler.
            return self._compile_generic(policy, backend)

        return compiler_func(policy)
    
    def compile_to_colang(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to NVIDIA NeMo Colang DSL"""
        colang_policy = {
            "version": "1.0",
            "policies": []
        }
        
        # Define message types and flows
        flows = []
        
        # Generate flow for each risk category
        for risk in policy.risk_categories:
            flow = self._generate_colang_flow(risk, policy)
            flows.append(flow)
        
        colang_policy["flows"] = flows
        colang_policy["models"] = self._generate_colang_models(policy)
        
        return {
            "backend": GuardrailBackend.NEMO.value,
            "colang_policy": json.dumps(colang_policy, indent=2)
        }
    
    def compile_to_guardrails_yaml(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to GuardrailsAI YAML format"""
        yaml_config = {
            "version": "1.0",
            "validators": [],
            "guards": []
        }
        
        # Map risks to validators
        validator_mapping = {
            RiskCategory.PROMPT_INJECTION: "prompt_injection_validator",
            RiskCategory.JAILBREAKING: "jailbreak_validator",
            RiskCategory.DATA_LEAKAGE: "pii_validator",
            RiskCategory.UNSAFE_CODE: "code_validator",
            RiskCategory.HALLUCINATION: "hallucination_validator",
        }
        
        for risk in policy.risk_categories:
            validator = validator_mapping.get(risk, f"{risk.value}_validator")
            yaml_config["validators"].append({
                "type": validator,
                "on_fail": policy.action_on_violation.value,
                "severity": policy.sensitivity
            })
        
        # Create input and output guards
        yaml_config["guards"].append({
            "type": "input_guard",
            "validators": [v["type"] for v in yaml_config["validators"]]
        })
        
        yaml_config["guards"].append({
            "type": "output_guard",
            "validators": ["output_validator"]
        })
        
        return {
            "backend": GuardrailBackend.GUARDRAILS_AI.value,
            "guardrails_yaml": self._dict_to_yaml_string(yaml_config)
        }
    
    def compile_to_presidio(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to Microsoft Presidio configuration"""
        presidio_config = {
            "analyzer_engines": [],
            "redactors": [],
            "pii_detection": {
                "entities": [],
                "confidence_threshold": self._confidence_from_sensitivity(policy.sensitivity)
            }
        }
        
        # Default PII entities
        pii_entities = [
            "CREDIT_CARD",
            "DATE_TIME",
            "EMAIL_ADDRESS",
            "PERSON",
            "PHONE_NUMBER",
            "MEDICAL_LICENSE",
            "NRP",
            "IBAN_CODE",
            "URL",
            "IP_ADDRESS",
            "PAN_INDIA",
            "SSN",
        ]
        
        presidio_config["pii_detection"]["entities"] = pii_entities
        
        # Configure redactors
        presidio_config["redactors"] = [
            {
                "type": "replace",
                "new_value": "[REDACTED]"
            }
        ]
        
        return {
            "backend": GuardrailBackend.PRESIDIO.value,
            "presidio_config": presidio_config
        }
    
    def compile_to_llama_firewall(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to LlamaFirewall (Meta PromptGuard 2) config.

        LlamaFirewall is fully local — no credentials or external calls.
        The model runs inference on every input; the config captures which
        risk categories should trigger a block decision.
        """
        risk_labels = [r.value for r in policy.risk_categories]
        return {
            "backend": GuardrailBackend.LLAMA_FIREWALL.value,
            "model": "meta-llama/Prompt-Guard-2-86M",
            "block_on_decision": ["BLOCK", "HUMAN_REVIEW"],
            "risk_categories": risk_labels,
            "action_on_violation": policy.action_on_violation.value,
            "sensitivity": policy.sensitivity,
        }

    def compile_to_llm_guard(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to LLM Guard (Protect AI) scanner config.

        LLM Guard is fully local.  Input scanners run on every prompt;
        output scanners run on model responses.  Scanner selection mirrors
        the policy's risk categories.
        """
        risk_set = {r for r in policy.risk_categories}

        input_scanners: list = []
        output_scanners: list = []

        if RiskCategory.PROMPT_INJECTION in risk_set:
            input_scanners.append("PromptInjection")
        if RiskCategory.JAILBREAKING in risk_set or RiskCategory.PROMPT_INJECTION in risk_set:
            input_scanners.append("Toxicity")
        if RiskCategory.DATA_LEAKAGE in risk_set:
            input_scanners.append("Anonymize")
            output_scanners.append("Deanonymize")
        if RiskCategory.UNSAFE_CODE in risk_set:
            input_scanners.append("Code")
            output_scanners.append("Code")
        if not input_scanners:
            input_scanners = ["PromptInjection", "Toxicity"]

        output_scanners = output_scanners or ["Toxicity"]

        return {
            "backend": GuardrailBackend.LLM_GUARD.value,
            "input_scanners": input_scanners,
            "output_scanners": output_scanners,
            "fail_fast": policy.sensitivity == "high",
            "action_on_violation": policy.action_on_violation.value,
        }

    def compile_to_openai_moderation(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to OpenAI Moderation API config.

        Requires OPENAI_API_KEY.  The API maps policy risk categories to
        OpenAI moderation category flags.
        """
        category_map = {
            RiskCategory.JAILBREAKING:      ["hate", "harassment", "self-harm", "sexual", "violence"],
            RiskCategory.PROMPT_INJECTION:  ["illicit", "illicit/violent"],
            RiskCategory.UNSAFE_CODE:       ["illicit"],
            RiskCategory.DATA_LEAKAGE:      [],
        }
        flagged_categories: list = []
        for risk in policy.risk_categories:
            flagged_categories.extend(category_map.get(risk, []))

        return {
            "backend": GuardrailBackend.OPENAI_MODERATION.value,
            "api_key_env": "OPENAI_API_KEY",
            "model": "text-moderation-latest",
            "monitored_categories": list(dict.fromkeys(flagged_categories)),
            "action_on_violation": policy.action_on_violation.value,
        }

    def compile_to_azure_content_safety(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to Azure AI Content Safety config.

        Requires AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY.
        Block threshold is derived from policy sensitivity.
        """
        threshold_map = {"low": 6, "medium": 4, "high": 2}
        threshold = threshold_map.get(policy.sensitivity, 4)

        return {
            "backend": GuardrailBackend.AZURE_CONTENT_SAFETY.value,
            "endpoint_env": "AZURE_CONTENT_SAFETY_ENDPOINT",
            "api_key_env": "AZURE_CONTENT_SAFETY_KEY",
            "api_version": "2023-10-01",
            "block_threshold": threshold,
            "action_on_violation": policy.action_on_violation.value,
        }

    def compile_to_azure_prompt_shields(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to Azure AI Prompt Shields config.

        Dedicated endpoint for detecting direct and indirect prompt injection.
        Shares credentials with Azure Content Safety.
        """
        return {
            "backend": GuardrailBackend.AZURE_PROMPT_SHIELDS.value,
            "endpoint_env": "AZURE_CONTENT_SAFETY_ENDPOINT",
            "api_key_env": "AZURE_CONTENT_SAFETY_KEY",
            "api_version": "2024-02-15-preview",
            "detect_direct_attack": True,
            "detect_indirect_attack": RiskCategory.INDIRECT_ATTACK in policy.risk_categories,
            "action_on_violation": policy.action_on_violation.value,
        }

    def compile_to_aws_bedrock(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to AWS Bedrock Guardrails config.

        Requires AWS credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or
        an IAM role), plus AWS_BEDROCK_GUARDRAIL_ID and AWS_BEDROCK_GUARDRAIL_VERSION.
        """
        return {
            "backend": GuardrailBackend.AWS_BEDROCK.value,
            "region_env": "AWS_DEFAULT_REGION",
            "guardrail_id_env": "AWS_BEDROCK_GUARDRAIL_ID",
            "guardrail_version_env": "AWS_BEDROCK_GUARDRAIL_VERSION",
            "risk_categories": [r.value for r in policy.risk_categories],
            "action_on_violation": policy.action_on_violation.value,
        }

    def compile_to_lakera(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to Lakera Guard config.

        Requires LAKERA_GUARD_API_KEY.
        """
        return {
            "backend": GuardrailBackend.LAKERA.value,
            "api_key_env": "LAKERA_GUARD_API_KEY",
            "risk_categories": [r.value for r in policy.risk_categories],
            "action_on_violation": policy.action_on_violation.value,
            "sensitivity": policy.sensitivity,
        }

    def compile_to_ga_guard(self, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Compile to Galileo Protect (GA Guard) config.

        Requires GA_GUARD_API_KEY.
        """
        return {
            "backend": GuardrailBackend.GA_GUARD.value,
            "api_key_env": "GA_GUARD_API_KEY",
            "risk_categories": [r.value for r in policy.risk_categories],
            "action_on_violation": policy.action_on_violation.value,
            "sensitivity": policy.sensitivity,
        }

    def _compile_generic(self, policy: GuardrailPolicy, backend: GuardrailBackend) -> Dict[str, Any]:
        """Fallback for custom or future backends — returns the policy as a plain dict."""
        return {
            "backend": backend.value if hasattr(backend, "value") else str(backend),
            "name": policy.name,
            "risk_categories": [r.value for r in policy.risk_categories],
            "action_on_violation": policy.action_on_violation.value,
            "sensitivity": policy.sensitivity,
            "rules": policy.rules,
        }

    def _generate_colang_flow(self, risk: RiskCategory, policy: GuardrailPolicy) -> Dict[str, Any]:
        """Generate Colang flow for a specific risk"""
        flow_name = f"check_{risk.value.lower()}"
        
        return {
            "flow": {
                "name": flow_name,
                "steps": [
                    f"$input_text = retrieve_input()",
                    f"$risk_detected = detect_{risk.value.lower()}($input_text)",
                    f"if $risk_detected:",
                    f"  $action = '{policy.action_on_violation.value}'",
                    f"  execute_action($action, $input_text)",
                    f"else:",
                    f"  proceed_to_model($input_text)"
                ]
            }
        }
    
    def _generate_colang_models(self, policy: GuardrailPolicy) -> list:
        """Generate model configurations for Colang"""
        return [
            {
                "type": "risk_detector",
                "models": [
                    f"{risk.value.lower()}_detector" for risk in policy.risk_categories
                ]
            }
        ]
    
    def _confidence_from_sensitivity(self, sensitivity: str) -> float:
        """Map sensitivity level to confidence threshold"""
        mapping = {
            "low": 0.3,
            "medium": 0.5,
            "high": 0.8
        }
        return mapping.get(sensitivity, 0.5)
    
    def _dict_to_yaml_string(self, data: Dict[str, Any], indent: int = 0) -> str:
        """Convert dictionary to YAML-like string"""
        lines = []
        for key, value in data.items():
            prefix = "  " * indent
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(self._dict_to_yaml_string(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"{prefix}  -")
                        for k, v in item.items():
                            lines.append(f"{prefix}    {k}: {v}")
                    else:
                        lines.append(f"{prefix}  - {item}")
            else:
                lines.append(f"{prefix}{key}: {value}")
        return "\n".join(lines)


class UnifiedPolicyBuilder:
    """Builder for creating policies in unified format"""
    
    def __init__(self):
        self.policy = GuardrailPolicy()
    
    def with_name(self, name: str) -> "UnifiedPolicyBuilder":
        """Set policy name"""
        self.policy.name = name
        return self
    
    def with_description(self, description: str) -> "UnifiedPolicyBuilder":
        """Set policy description"""
        self.policy.description = description
        return self
    
    def with_backend(self, backend: GuardrailBackend) -> "UnifiedPolicyBuilder":
        """Set target backend"""
        self.policy.backend = backend
        return self
    
    def with_risk_categories(self, categories: list) -> "UnifiedPolicyBuilder":
        """Set risk categories to monitor"""
        self.policy.risk_categories = categories
        return self
    
    def with_sensitivity(self, level: str) -> "UnifiedPolicyBuilder":
        """Set sensitivity level (low, medium, high)"""
        if level not in ["low", "medium", "high"]:
            raise ValueError(f"Invalid sensitivity level: {level}")
        self.policy.sensitivity = level
        return self
    
    def with_action(self, action: ActionType) -> "UnifiedPolicyBuilder":
        """Set action on violation"""
        self.policy.action_on_violation = action
        return self
    
    def with_escalation_email(self, email: str) -> "UnifiedPolicyBuilder":
        """Set escalation email for high-severity violations"""
        self.policy.escalation_email = email
        return self
    
    def with_rules(self, rules: Dict[str, Any]) -> "UnifiedPolicyBuilder":
        """Add custom rules"""
        self.policy.rules = rules
        return self
    
    def with_tag(self, tag: str) -> "UnifiedPolicyBuilder":
        """Add tag for categorization"""
        self.policy.tags.append(tag)
        return self
    
    def build(self) -> GuardrailPolicy:
        """Build the policy"""
        if not self.policy.name:
            raise ValueError("Policy name is required")
        return self.policy


# Policy templates for common use cases
class PolicyTemplates:
    """Pre-built policy templates"""
    
    @staticmethod
    def strict_security() -> GuardrailPolicy:
        """Strict security policy - blocks all suspicious activity"""
        return UnifiedPolicyBuilder() \
            .with_name("Strict Security") \
            .with_description("Maximum security enforcement") \
            .with_backend(GuardrailBackend.GUARDRAILS_AI) \
            .with_risk_categories([
                RiskCategory.PROMPT_INJECTION,
                RiskCategory.JAILBREAKING,
                RiskCategory.DATA_LEAKAGE,
                RiskCategory.UNSAFE_CODE,
            ]) \
            .with_sensitivity("high") \
            .with_action(ActionType.BLOCK) \
            .with_tag("security") \
            .build()

    @staticmethod
    def privacy_focused() -> GuardrailPolicy:
        """Privacy-focused policy - emphasizes PII redaction"""
        return UnifiedPolicyBuilder() \
            .with_name("Privacy Focused") \
            .with_description("Emphasis on data privacy and PII protection") \
            .with_backend(GuardrailBackend.PRESIDIO) \
            .with_risk_categories([
                RiskCategory.DATA_LEAKAGE,
                RiskCategory.INDIRECT_ATTACK,
            ]) \
            .with_sensitivity("high") \
            .with_action(ActionType.REDACT) \
            .with_tag("privacy") \
            .build()

    @staticmethod
    def balanced() -> GuardrailPolicy:
        """Balanced policy - allows some risk, redacts sensitive data"""
        return UnifiedPolicyBuilder() \
            .with_name("Balanced") \
            .with_description("Balanced security and usability") \
            .with_backend(GuardrailBackend.GUARDRAILS_AI) \
            .with_risk_categories([
                RiskCategory.PROMPT_INJECTION,
                RiskCategory.DATA_LEAKAGE,
            ]) \
            .with_sensitivity("medium") \
            .with_action(ActionType.REDACT) \
            .with_tag("balanced") \
            .build()

    @staticmethod
    def agent_execution() -> GuardrailPolicy:
        """Policy for agentic AI - focuses on tool validation"""
        return UnifiedPolicyBuilder() \
            .with_name("Agent Execution") \
            .with_description("Guardrails for autonomous agent execution") \
            .with_backend(GuardrailBackend.NEMO) \
            .with_risk_categories([
                RiskCategory.MALICIOUS_TOOL_USE,
                RiskCategory.UNSAFE_CODE,
                RiskCategory.DOS,
            ]) \
            .with_sensitivity("high") \
            .with_action(ActionType.BLOCK) \
            .with_rules({
                "max_tool_calls_per_minute": 10,
                "max_concurrent_agents": 5,
                "allowed_tools": ["read_file", "search", "calculate"],
                "forbidden_tools": ["delete_file", "exec_code", "drop_table"]
            }) \
            .with_tag("agent") \
            .build()

    @staticmethod
    def prompt_injection_local() -> GuardrailPolicy:
        """Prompt-injection defence using LlamaFirewall (Meta PromptGuard 2).

        Fully local — no API key or network access required.
        Suitable for air-gapped environments or cost-sensitive deployments.
        """
        return UnifiedPolicyBuilder() \
            .with_name("Prompt Injection Guard (Local)") \
            .with_description("LlamaFirewall PromptGuard 2 — local, no credentials needed") \
            .with_backend(GuardrailBackend.LLAMA_FIREWALL) \
            .with_risk_categories([
                RiskCategory.PROMPT_INJECTION,
                RiskCategory.JAILBREAKING,
            ]) \
            .with_sensitivity("high") \
            .with_action(ActionType.BLOCK) \
            .with_tag("local") \
            .with_tag("prompt-injection") \
            .build()

    @staticmethod
    def input_safety_local() -> GuardrailPolicy:
        """Input safety scanning using LLM Guard (Protect AI).

        Fully local — no API key or network access required.
        Runs PromptInjection and Toxicity scanners on every input.
        """
        return UnifiedPolicyBuilder() \
            .with_name("Input Safety Scanner (Local)") \
            .with_description("LLM Guard PromptInjection + Toxicity scanners — local, no credentials needed") \
            .with_backend(GuardrailBackend.LLM_GUARD) \
            .with_risk_categories([
                RiskCategory.PROMPT_INJECTION,
                RiskCategory.JAILBREAKING,
                RiskCategory.DATA_LEAKAGE,
            ]) \
            .with_sensitivity("high") \
            .with_action(ActionType.BLOCK) \
            .with_tag("local") \
            .with_tag("toxicity") \
            .build()


if __name__ == "__main__":
    # Example usage
    compiler = PolicyCompiler()
    
    # Build a custom policy
    policy = UnifiedPolicyBuilder() \
        .with_name("Custom Data Protection") \
        .with_backend(GuardrailBackend.GUARDRAILS_AI) \
        .with_risk_categories([RiskCategory.DATA_LEAKAGE, RiskCategory.PROMPT_INJECTION]) \
        .with_sensitivity("high") \
        .with_action(ActionType.REDACT) \
        .build()
    
    # Compile to GuardrailsAI format
    compiled = compiler.compile(policy)
    print(json.dumps(compiled, indent=2))
    
    # Compile same policy to NeMo format
    policy.backend = GuardrailBackend.NEMO
    compiled_nemo = compiler.compile(policy)
    print(json.dumps(compiled_nemo, indent=2))
