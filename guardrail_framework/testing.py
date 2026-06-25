"""
Gap 1: Policy Unit Testing Framework
Gap 2: Default-Deny Posture

OPA ships `opa test` with coverage reports.
GuardrailFramework now has PolicyTestRunner, assertions, and
a fail-closed default-deny wrapper that blocks on any error.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import GuardrailFramework, GuardrailResult, ActionType


# ──────────────────────────────────────────────────────────────
# Data-classes
# ──────────────────────────────────────────────────────────────

@dataclass
class PolicyTestCase:
    """A single declarative test case for a guardrail policy."""
    name: str
    input_text: str
    policy_id: str
    check_type: str = "input"          # "input" | "output" | "tool"
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None

    # --- expected values (None = don't assert) ---
    expect_passed: Optional[bool] = None
    expect_action: Optional[str] = None          # e.g. "block", "redact"
    expect_risk_min: Optional[float] = None      # risk_score >= this
    expect_risk_max: Optional[float] = None      # risk_score <= this
    expect_risk_in: Optional[List[str]] = None   # detected_risks contains these types
    tags: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Outcome of running one PolicyTestCase."""
    test_name: str
    passed: bool
    policy_id: str
    check_type: str
    latency_ms: float
    guardrail_result: Optional[Any] = None   # GuardrailResult
    failures: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TestSuiteReport:
    """Aggregate report from PolicyTestRunner.run_all()."""
    total: int = 0
    passed: int = 0
    failed: int = 0
    errored: int = 0
    duration_ms: float = 0.0
    results: List[TestResult] = field(default_factory=list)

    # Coverage: which policies were exercised, how many checks each
    policy_coverage: Dict[str, int] = field(default_factory=dict)
    # Risk-category coverage: which risk types appeared in detected_risks
    risk_coverage: Dict[str, int] = field(default_factory=dict)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0.0

    def summary(self) -> str:
        lines = [
            f"{'='*56}",
            f"  Guardrail Policy Test Suite",
            f"{'='*56}",
            f"  Total   : {self.total}",
            f"  Passed  : {self.passed}  ({self.pass_rate:.1f}%)",
            f"  Failed  : {self.failed}",
            f"  Errored : {self.errored}",
            f"  Duration: {self.duration_ms:.1f} ms",
            f"",
            f"  Policy coverage ({len(self.policy_coverage)} policies):",
        ]
        for pid, count in self.policy_coverage.items():
            lines.append(f"    {pid[:8]}…  {count} checks")
        lines.append(f"")
        lines.append(f"  Risk category coverage:")
        for rtype, count in sorted(self.risk_coverage.items(), key=lambda x: -x[1]):
            lines.append(f"    {rtype:35s}  {count}x")
        lines.append(f"{'='*56}")

        failed_results = [r for r in self.results if not r.passed]
        if failed_results:
            lines.append(f"\n  FAILURES:")
            for r in failed_results:
                lines.append(f"  ✗ {r.test_name}")
                if r.error:
                    lines.append(f"      error: {r.error}")
                for f in r.failures:
                    lines.append(f"      {f}")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# Test runner
# ──────────────────────────────────────────────────────────────

class PolicyTestRunner:
    """
    OPA-style test runner for guardrail policies.

    Usage::

        runner = PolicyTestRunner(framework)

        runner.add(PolicyTestCase(
            name="blocks SQL injection",
            input_text="DROP TABLE users;",
            policy_id=my_policy_id,
            expect_passed=False,
            expect_action="block",
            expect_risk_min=0.3,
        ))

        report = runner.run_all()
        print(report.summary())
        assert report.failed == 0
    """

    def __init__(self, framework: "GuardrailFramework"):
        self.framework = framework
        self._cases: List[PolicyTestCase] = []

    # ── registration ───────────────────────────────────────────

    def add(self, case: PolicyTestCase) -> "PolicyTestRunner":
        self._cases.append(case)
        return self

    def add_many(self, cases: List[PolicyTestCase]) -> "PolicyTestRunner":
        self._cases.extend(cases)
        return self

    # convenience factories
    def expect_blocked(self, name: str, text: str, policy_id: str,
                       risk_min: float = 0.0, **kwargs) -> "PolicyTestRunner":
        return self.add(PolicyTestCase(
            name=name, input_text=text, policy_id=policy_id,
            expect_passed=False, expect_action="block",
            expect_risk_min=risk_min, **kwargs))

    def expect_allowed(self, name: str, text: str, policy_id: str,
                       risk_max: float = 1.0, **kwargs) -> "PolicyTestRunner":
        return self.add(PolicyTestCase(
            name=name, input_text=text, policy_id=policy_id,
            expect_passed=True, expect_risk_max=risk_max, **kwargs))

    # ── execution ──────────────────────────────────────────────

    def run_all(self, tags: Optional[List[str]] = None) -> TestSuiteReport:
        """Run all registered test cases, return a TestSuiteReport."""
        cases = self._cases
        if tags:
            cases = [c for c in cases if any(t in c.tags for t in tags)]

        report = TestSuiteReport()
        suite_start = time.time()

        for case in cases:
            result = self._run_one(case)
            report.results.append(result)
            report.total += 1

            if result.error:
                report.errored += 1
                report.failed += 1
            elif result.passed:
                report.passed += 1
            else:
                report.failed += 1

            # coverage tracking
            report.policy_coverage[case.policy_id] = \
                report.policy_coverage.get(case.policy_id, 0) + 1

            if result.guardrail_result:
                for risk in getattr(result.guardrail_result, "detected_risks", []):
                    rtype = risk.get("type", "unknown") if isinstance(risk, dict) else str(risk)
                    report.risk_coverage[rtype] = report.risk_coverage.get(rtype, 0) + 1

        report.duration_ms = (time.time() - suite_start) * 1000
        return report

    def _run_one(self, case: PolicyTestCase) -> TestResult:
        t0 = time.time()
        gr = None
        failures: List[str] = []
        error: Optional[str] = None

        try:
            if case.check_type == "input":
                gr = self.framework.check_input(case.input_text, case.policy_id, case.context)
            elif case.check_type == "output":
                gr = self.framework.check_output(case.input_text, case.policy_id, case.context)
            elif case.check_type == "tool":
                gr = self.framework.validate_tool_call(
                    case.policy_id,
                    case.tool_name or "",
                    case.tool_args or {},
                    case.context,
                )
            else:
                raise ValueError(f"Unknown check_type: {case.check_type!r}")

            # --- assertions ---
            if case.expect_passed is not None and gr.passed != case.expect_passed:
                failures.append(
                    f"expect_passed={case.expect_passed} but got passed={gr.passed}"
                )

            if case.expect_action is not None and gr.action.value != case.expect_action:
                failures.append(
                    f"expect_action={case.expect_action!r} but got {gr.action.value!r}"
                )

            if case.expect_risk_min is not None and gr.risk_score < case.expect_risk_min:
                failures.append(
                    f"expect_risk_min={case.expect_risk_min} but risk_score={gr.risk_score:.3f}"
                )

            if case.expect_risk_max is not None and gr.risk_score > case.expect_risk_max:
                failures.append(
                    f"expect_risk_max={case.expect_risk_max} but risk_score={gr.risk_score:.3f}"
                )

            if case.expect_risk_in:
                found_types = {
                    r.get("type", "") if isinstance(r, dict) else str(r)
                    for r in gr.detected_risks
                }
                for expected_type in case.expect_risk_in:
                    if expected_type not in found_types:
                        failures.append(
                            f"expected risk type {expected_type!r} not in detected_risks {found_types}"
                        )

        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"

        latency = (time.time() - t0) * 1000
        ok = (error is None) and (len(failures) == 0)
        return TestResult(
            test_name=case.name,
            passed=ok,
            policy_id=case.policy_id,
            check_type=case.check_type,
            latency_ms=latency,
            guardrail_result=gr,
            failures=failures,
            error=error,
        )


# ──────────────────────────────────────────────────────────────
# Gap 2 — Default-deny wrapper
# ──────────────────────────────────────────────────────────────

def fail_closed_result(reason: str = "fail-closed default-deny") -> "GuardrailResult":
    """
    Return a blocking GuardrailResult.
    Used whenever a backend raises or a policy is missing,
    ensuring the system fails closed (deny by default).
    """
    from .core import GuardrailResult, ActionType, GuardrailBackend
    return GuardrailResult(
        passed=False,
        severity="critical",
        action=ActionType.BLOCK,
        risk_score=1.0,
        detected_risks=[{"type": "system_error", "reason": reason}],
        backend_used=GuardrailBackend.CUSTOM,
        latency_ms=0.0,
    )
