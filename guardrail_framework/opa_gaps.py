"""
Gap 7:  Partial Evaluation / Policy Pre-compilation
Gap 8:  Prometheus + OpenTelemetry metrics export
Gap 9:  Status API (bundle activation, per-policy health)
Gap 10: WASM-ready rule scoring (pure-Python portable core, WASM-compilable)
Gap 11: Pluggable external data providers
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("opa_gaps")


# ══════════════════════════════════════════════════════════════
# Gap 7 — Partial Evaluation / Policy Pre-compilation
# ══════════════════════════════════════════════════════════════

@dataclass
class ResidualQuery:
    """
    A pre-compiled rule residual keyed on static context dimensions.
    Equivalent to OPA's partial evaluation output.
    """
    cache_key: str
    policy_id: str
    static_context: Dict[str, Any]       # the fixed dimensions used to compile
    compiled_patterns: List[re.Pattern]   # pre-compiled regex list
    risk_weights: Dict[str, float]        # keyword → weight
    threshold: float
    compiled_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hits: int = 0


class PolicyPrecompiler:
    """
    Pre-compiles guardrail rule patterns for a (policy_id, context) pair
    so that hot-path evaluation avoids repeated regex compilation.

    OPA parity: OPA's `partial` query compiles a policy + partial input
    into a residual expression. Here we compile regex patterns + weight
    tables for a given static context (tenant, environment, risk sensitivity).

    Usage::

        precompiler = PolicyPrecompiler(framework)

        # pre-warm for a known context at startup / policy load
        rq = precompiler.compile(policy_id, context={"env": "prod", "tenant": "acme"})

        # evaluate cheaply on every request
        score, risks = precompiler.evaluate(rq, text)
    """

    # sensitivity → score threshold
    THRESHOLDS = {"low": 0.80, "medium": 0.65, "high": 0.45}

    # Base patterns compiled once, reused across all policies
    _INJECTION_PATS: List[Tuple[str, float]] = [
        (r"ignore\s+(all\s+|previous\s+|prior\s+|your\s+)?(instructions|rules|guidelines|constraints)", 0.35),
        (r"pretend\s+(you\s+are|to\s+be|you\'?re|you\s+have\s+no)", 0.35),
        (r"(you\s+are|you\'?re)\s+now\s+(dan|jailbroken|free|unrestricted)", 0.40),
        (r"(disregard|forget|bypass|override)\s+(your\s+)?(safety|rules|restrictions|training)", 0.35),
        (r"do\s+anything\s+now", 0.40),
        (r"(reveal|show|print|output)\s+(your\s+|system\s+|hidden\s+)?(prompt|instructions|rules)", 0.30),
        (r"act\s+as\s+(if\s+you\s+have\s+no|without\s+any|an\s+ai\s+with\s+no)", 0.35),
    ]
    _SQL_PATS: List[Tuple[str, float]] = [
        (r"(drop|delete|truncate)\s+(table|database|schema)", 0.35),
        (r"(select|insert|update|delete)\s+.{0,40}(from|into|where)", 0.25),
        (r"union\s+select", 0.35),
        (r"exec\s*\(|execute\s*\(|xp_cmdshell", 0.40),
        (r"os\.(system|popen|execv|exec)", 0.40),
        (r"subprocess\.(run|call|Popen)", 0.40),
        (r"__import__\s*\(|compile\s*\(.*exec|eval\s*\(", 0.35),
    ]
    _KW_WEIGHTS: Dict[str, float] = {
        "drop table": 0.35, "rm -rf": 0.40, "passwd": 0.25,
        "shadow": 0.25, "/etc/": 0.15, "admin password": 0.30,
        "root password": 0.30, "base64_decode": 0.20,
    }

    def __init__(self, framework: Any, max_cache_size: int = 512):
        self.framework = framework
        self._cache: Dict[str, ResidualQuery] = {}
        self._lock = threading.Lock()
        self.max_cache_size = max_cache_size

        # Pre-compile base patterns once at import time
        self._compiled_injection = [(re.compile(p, re.I), w) for p, w in self._INJECTION_PATS]
        self._compiled_sql       = [(re.compile(p, re.I), w) for p, w in self._SQL_PATS]

    def compile(self, policy_id: str,
                context: Optional[Dict[str, Any]] = None) -> ResidualQuery:
        """
        Pre-compile a residual query for this (policy_id, context) pair.
        Returns cached result if available.
        """
        context = context or {}
        key = self._cache_key(policy_id, context)

        with self._lock:
            if key in self._cache:
                rq = self._cache[key]
                rq.hits += 1
                return rq

        policy = self.framework.policies.get(policy_id)
        threshold = self.THRESHOLDS.get(
            getattr(policy, "sensitivity", "medium"), 0.65
        )

        # Merge base keyword weights with any policy-level overrides
        kw_weights = dict(self._KW_WEIGHTS)
        if policy and policy.rules.get("extra_keywords"):
            kw_weights.update(policy.rules["extra_keywords"])

        # Collect all compiled patterns
        patterns = (
            [pat for pat, _ in self._compiled_injection] +
            [pat for pat, _ in self._compiled_sql]
        )

        rq = ResidualQuery(
            cache_key=key,
            policy_id=policy_id,
            static_context=context,
            compiled_patterns=patterns,
            risk_weights=kw_weights,
            threshold=threshold,
        )

        with self._lock:
            if len(self._cache) >= self.max_cache_size:
                # evict lowest-hit entry
                victim = min(self._cache, key=lambda k: self._cache[k].hits)
                del self._cache[victim]
            self._cache[key] = rq

        logger.debug(f"Pre-compiled residual for {policy_id[:8]} ctx={list(context.keys())}")
        return rq

    def evaluate(self, rq: ResidualQuery, text: str) -> Tuple[float, List[Dict]]:
        """
        Evaluate text against a pre-compiled residual.
        Returns (risk_score, detected_risks).
        """
        t = text.lower()
        score = 0.0
        risks: List[Dict] = []

        # Injection patterns — each item is (compiled_pattern, weight)
        for pat, w in self._compiled_injection:
            if pat.search(t):
                score += w
                risks.append({"type": "prompt_injection", "pattern": pat.pattern[:40], "weight": w})

        # SQL/code patterns
        for pat, w in self._compiled_sql:
            if pat.search(t):
                score += w
                risks.append({"type": "unsafe_code_or_sql", "pattern": pat.pattern[:40], "weight": w})

        # Keyword weights
        for kw, w in rq.risk_weights.items():
            if kw in t:
                score += w
                risks.append({"type": "keyword", "keyword": kw, "weight": w})

        return min(round(score, 3), 1.0), risks

    def invalidate(self, policy_id: str):
        """Remove all cached residuals for a policy (call after policy update)."""
        with self._lock:
            stale = [k for k in self._cache if self._cache[k].policy_id == policy_id]
            for k in stale:
                del self._cache[k]
        logger.debug(f"Invalidated {len(stale)} cache entries for {policy_id[:8]}")

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "cached_residuals": len(self._cache),
                "max_cache_size": self.max_cache_size,
                "entries": [
                    {"key": k[:16], "policy_id": v.policy_id[:8],
                     "hits": v.hits, "compiled_at": v.compiled_at}
                    for k, v in self._cache.items()
                ],
            }

    @staticmethod
    def _cache_key(policy_id: str, context: Dict) -> str:
        ctx_hash = hashlib.md5(
            json.dumps(context, sort_keys=True).encode()
        ).hexdigest()[:12]
        return f"{policy_id}:{ctx_hash}"


# ══════════════════════════════════════════════════════════════
# Gap 8 — Prometheus + OpenTelemetry metrics export
# ══════════════════════════════════════════════════════════════

class PrometheusMetrics:
    """
    OPA-parity Prometheus metrics.

    OPA exposes counters like opa_decisions_total and histograms like
    opa_decision_duration_seconds. This class replicates that pattern
    using prometheus_client when available, falling back to in-memory
    counters so the rest of the code never breaks.

    Expose via FastAPI::

        @app.get("/metrics")
        def prom_metrics():
            return Response(metrics.render(), media_type="text/plain")
    """

    def __init__(self):
        self._prom_available = False
        self._counters: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._try_init_prometheus()

    def _try_init_prometheus(self):
        try:
            from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
            self._registry = CollectorRegistry()

            self.decisions_total = Counter(
                "guardrail_decisions_total",
                "Total number of guardrail decisions",
                ["policy_id", "backend", "action", "passed"],
                registry=self._registry,
            )
            self.decision_duration = Histogram(
                "guardrail_decision_duration_seconds",
                "Guardrail decision latency in seconds",
                ["policy_id", "backend"],
                buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
                registry=self._registry,
            )
            self.risk_score = Histogram(
                "guardrail_risk_score",
                "Distribution of risk scores",
                ["policy_id"],
                buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
                registry=self._registry,
            )
            self.active_policies = Gauge(
                "guardrail_active_policies_total",
                "Number of active guardrail policies",
                registry=self._registry,
            )
            self.bundle_load_total = Counter(
                "guardrail_bundle_loads_total",
                "Bundle load attempts",
                ["status"],
                registry=self._registry,
            )
            self._generate_latest = generate_latest
            self._CONTENT_TYPE = CONTENT_TYPE_LATEST
            self._prom_available = True
            logger.info("Prometheus metrics enabled")
        except ImportError:
            logger.info("prometheus_client not installed — using in-memory fallback")

    def record_decision(self, policy_id: str, backend: str,
                        action: str, passed: bool,
                        latency_ms: float, risk_score: float):
        if self._prom_available:
            self.decisions_total.labels(
                policy_id=policy_id[:16], backend=backend,
                action=action, passed=str(passed)
            ).inc()
            self.decision_duration.labels(
                policy_id=policy_id[:16], backend=backend
            ).observe(latency_ms / 1000)
            self.risk_score.labels(policy_id=policy_id[:16]).observe(risk_score)
        else:
            with self._lock:
                key = f"{policy_id[:8]}:{backend}:{action}:{passed}"
                self._counters[key] = self._counters.get(key, 0) + 1
                self._histograms.setdefault("latency_ms", []).append(latency_ms)
                self._histograms.setdefault("risk_score", []).append(risk_score)

    def set_active_policies(self, count: int):
        if self._prom_available:
            self.active_policies.set(count)

    def record_bundle_load(self, success: bool):
        if self._prom_available:
            self.bundle_load_total.labels(status="ok" if success else "error").inc()

    def render(self) -> str:
        """Return Prometheus text format for /metrics endpoint."""
        if self._prom_available:
            return self._generate_latest(self._registry).decode()
        # Fallback: simple text rendering
        with self._lock:
            lines = ["# Guardrail Framework Metrics (fallback — install prometheus_client)"]
            for k, v in self._counters.items():
                safe = k.replace(":", "_").replace("-", "_")
                lines.append(f"guardrail_decisions_total{{{safe}}} {v}")
            for name, values in self._histograms.items():
                if values:
                    avg = sum(values) / len(values)
                    lines.append(f"guardrail_{name}_avg {avg:.4f}")
                    lines.append(f"guardrail_{name}_count {len(values)}")
            return "\n".join(lines)

    @property
    def content_type(self) -> str:
        if self._prom_available:
            return self._CONTENT_TYPE
        return "text/plain; charset=utf-8"


# ══════════════════════════════════════════════════════════════
# Gap 9 — Status API
# ══════════════════════════════════════════════════════════════

@dataclass
class PolicyStatus:
    policy_id: str
    policy_name: str
    backend: str
    enabled: bool
    last_check_at: Optional[str] = None
    total_checks: int = 0
    total_blocked: int = 0
    error_count: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    last_error: Optional[str] = None
    bundle_name: Optional[str] = None
    bundle_revision: Optional[str] = None


class StatusReporter:
    """
    OPA /v1/status parity.

    Tracks per-policy health metrics and exposes a /status endpoint
    that gives operators visibility into policy activation, error rates,
    and latency — separate from the basic /health liveness probe.

    Usage::

        reporter = StatusReporter()
        reporter.record(policy_id="...", backend="guardrails_ai",
                        passed=True, latency_ms=45.2)
        status = reporter.get_status()   # for /status endpoint
    """

    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._latencies: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._started_at = datetime.now(timezone.utc).isoformat()

    def register_policy(self, policy_id: str, policy_name: str,
                        backend: str, enabled: bool,
                        bundle_name: Optional[str] = None,
                        bundle_revision: Optional[str] = None):
        with self._lock:
            self._data.setdefault(policy_id, {
                "policy_name": policy_name,
                "backend": backend,
                "enabled": enabled,
                "last_check_at": None,
                "total_checks": 0,
                "total_blocked": 0,
                "error_count": 0,
                "last_error": None,
                "bundle_name": bundle_name,
                "bundle_revision": bundle_revision,
            })

    def record(self, policy_id: str, backend: str, passed: bool,
               latency_ms: float, error: Optional[str] = None):
        with self._lock:
            d = self._data.setdefault(policy_id, {
                "policy_name": policy_id[:8],
                "backend": backend,
                "enabled": True,
                "last_check_at": None,
                "total_checks": 0,
                "total_blocked": 0,
                "error_count": 0,
                "last_error": None,
                "bundle_name": None,
                "bundle_revision": None,
            })
            d["total_checks"] += 1
            d["last_check_at"] = datetime.now(timezone.utc).isoformat()
            if not passed:
                d["total_blocked"] += 1
            if error:
                d["error_count"] += 1
                d["last_error"] = error

            lats = self._latencies.setdefault(policy_id, [])
            lats.append(latency_ms)
            if len(lats) > 1000:        # rolling window
                lats.pop(0)

    def get_policy_status(self, policy_id: str) -> Optional[PolicyStatus]:
        with self._lock:
            d = self._data.get(policy_id)
            if d is None:
                return None
            lats = sorted(self._latencies.get(policy_id, [0]))
            avg = sum(lats) / len(lats) if lats else 0
            p95 = lats[int(len(lats) * 0.95)] if lats else 0
            return PolicyStatus(
                policy_id=policy_id,
                policy_name=d.get("policy_name", policy_id[:8]),
                backend=d.get("backend", "unknown"),
                enabled=d.get("enabled", True),
                last_check_at=d.get("last_check_at"),
                total_checks=d.get("total_checks", 0),
                total_blocked=d.get("total_blocked", 0),
                error_count=d.get("error_count", 0),
                avg_latency_ms=round(avg, 2),
                p95_latency_ms=round(p95, 2),
                last_error=d.get("last_error"),
                bundle_name=d.get("bundle_name"),
                bundle_revision=d.get("bundle_revision"),
            )

    def get_status(self, framework: Any = None) -> Dict[str, Any]:
        """Full status report — wired to GET /status."""
        policy_statuses = {}
        with self._lock:
            for pid in self._data:
                ps = self.get_policy_status(pid)
                if ps:
                    policy_statuses[pid] = asdict(ps)

        return {
            "started_at": self._started_at,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_policies": len(self._data),
            "healthy_policies": sum(
                1 for pid in self._data
                if self._data[pid].get("error_count", 0) == 0
            ),
            "policies": policy_statuses,
        }


# ══════════════════════════════════════════════════════════════
# Gap 10 — WASM-ready portable scoring core
# ══════════════════════════════════════════════════════════════

class WasmReadyScorer:
    """
    Pure-Python portable risk scoring core designed for WASM compilation.

    All logic uses only Python stdlib (re, json) — no C extensions,
    no numpy, no external deps — so it can be compiled to WASM via:
      - Pyodide (run in browser / Cloudflare Workers)
      - Emscripten + CPython-WASM
      - RustPython → wasm-pack (future)

    This is the single source of truth for risk scoring, replacing the
    duplicated _calculate_risk_score / _score_text methods in the backends.

    Usage::

        scorer = WasmReadyScorer()
        score, risks = scorer.score(text, sensitivity="high")
        passed = score < scorer.threshold(sensitivity)
    """

    # (pattern_string, risk_type, weight)
    RULES: List[Tuple[str, str, float]] = [
        # Prompt injection — allow any run of qualifier words between verb and object
        (r"ignore\s+(?:\w+\s+){0,3}instructions", "prompt_injection", 0.70),
        (r"ignore\s+(?:\w+\s+){0,3}(rules|guidelines|constraints)", "prompt_injection", 0.70),
        (r"disregard\s+(?:\w+\s+){0,3}(instructions|rules|prompt)", "prompt_injection", 0.70),
        (r"forget\s+(?:\w+\s+){0,3}(instructions|rules|everything)", "prompt_injection", 0.60),
        (r"pretend\s+(you\s+(are|have\s+no)|to\s+be)", "jailbreaking", 0.70),
        (r"(you\s+are|you\'?re)\s+now\s+(dan|jailbroken|unrestricted|free)", "jailbreaking", 0.80),
        (r"(bypass|override)\s+(?:\w+\s+){0,3}(safety|rules|training|restrictions)", "jailbreaking", 0.70),
        (r"do\s+anything\s+now", "jailbreaking", 0.70),
        (r"reveal\s+(?:\w+\s+){0,3}(prompt|instructions|system\s+prompt|keys|secrets)", "prompt_injection", 0.60),
        (r"act\s+as\s+(if\s+you\s+have\s+no|an\s+ai\s+without)", "jailbreaking", 0.65),
        # SQL / code injection
        (r"(drop|truncate|delete)\s+(table|database|schema)", "unsafe_code", 0.80),
        (r"union\s+select", "unsafe_code", 0.70),
        (r"exec\s*\(|execute\s*\(|xp_cmdshell", "unsafe_code", 0.80),
        (r"os\.(system|popen|execv)", "unsafe_code", 0.80),
        (r"subprocess\.(run|call|Popen)", "unsafe_code", 0.80),
        (r"__import__\s*\(", "unsafe_code", 0.70),
        (r"eval\s*\(|compile\s*\(.*exec", "unsafe_code", 0.70),
        # PII patterns
        (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "data_leakage", 0.50),
        (r"\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b", "data_leakage", 0.60),   # SSN
        (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "data_leakage", 0.60),         # Visa card
        (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "data_leakage", 0.40),  # Phone
    ]

    KW_RULES: List[Tuple[str, str, float]] = [
        ("drop table",      "unsafe_code",   0.40),
        ("rm -rf",          "unsafe_code",   0.45),
        ("passwd",          "data_leakage",  0.25),
        ("/etc/shadow",     "data_leakage",  0.30),
        ("admin password",  "prompt_injection", 0.30),
        ("root password",   "prompt_injection", 0.30),
        ("base64_decode",   "unsafe_code",   0.20),
    ]

    THRESHOLDS = {"low": 0.80, "medium": 0.65, "high": 0.45}

    def __init__(self):
        # compile once
        self._compiled = [(re.compile(pat, re.I | re.S), rtype, w)
                          for pat, rtype, w in self.RULES]

    def score(self, text: str,
              sensitivity: str = "medium",
              extra_rules: Optional[List[Tuple[str, str, float]]] = None
              ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Returns (risk_score 0-1, list of detected risk dicts).
        Designed to be the single hot-path call — O(patterns) per request.
        """
        t = text.lower()
        total = 0.0
        risks: List[Dict[str, Any]] = []

        for pat, rtype, w in self._compiled:
            if pat.search(t):
                total += w
                risks.append({"type": rtype, "confidence": round(w, 2)})

        for kw, rtype, w in self.KW_RULES:
            if kw in t:
                total += w
                risks.append({"type": rtype, "keyword": kw, "confidence": round(w, 2)})

        if extra_rules:
            for pat_str, rtype, w in extra_rules:
                if re.search(pat_str, t, re.I):
                    total += w
                    risks.append({"type": rtype, "custom": True, "confidence": round(w, 2)})

        return min(round(total, 3), 1.0), risks

    def threshold(self, sensitivity: str = "medium") -> float:
        return self.THRESHOLDS.get(sensitivity, 0.65)

    def passes(self, text: str, sensitivity: str = "medium") -> bool:
        score, _ = self.score(text, sensitivity)
        return score < self.threshold(sensitivity)

    # WASM export stub — when compiled with Pyodide this becomes callable from JS:
    #   import { score_text } from "./guardrail_scorer.wasm"
    def score_text_wasm(self, text: str, sensitivity: str) -> str:
        """JSON-serialisable interface for WASM boundary."""
        score, risks = self.score(text, sensitivity)
        return json.dumps({"risk_score": score, "detected_risks": risks,
                           "passed": score < self.threshold(sensitivity)})


# ══════════════════════════════════════════════════════════════
# Gap 11 — Pluggable external data providers
# ══════════════════════════════════════════════════════════════

class DataProvider:
    """
    Abstract base for external data sources that enrich guardrail checks.

    OPA bundles can carry data alongside policy and rules can call
    http.send() to query live data. This interface replicates that pattern
    in Python: providers are registered and called before each check,
    injecting dynamic context (blocklists, threat feeds, user attributes).
    """

    def name(self) -> str:
        return self.__class__.__name__

    def fetch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return enriched context data.
        Called before every guardrail check — must be fast (< 5 ms typically).
        Return {} if nothing to add.
        """
        raise NotImplementedError


class StaticBlocklistProvider(DataProvider):
    """
    Simple in-memory blocklist (users, IPs, keywords).
    Data is lost on restart. Use DatabaseBlocklistProvider for production.
    """

    def __init__(self,
                 blocked_users: Optional[List[str]] = None,
                 blocked_ips: Optional[List[str]] = None,
                 blocked_keywords: Optional[List[str]] = None):
        self._users    = set(blocked_users or [])
        self._ips      = set(blocked_ips or [])
        self._keywords = set(kw.lower() for kw in (blocked_keywords or []))

    def name(self) -> str:
        return "StaticBlocklistProvider"

    def fetch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "blocklisted_user":    context.get("user_id") in self._users,
            "blocklisted_ip":      context.get("ip") in self._ips,
            "blocked_keywords":    list(self._keywords),
        }

    def add_user(self, user_id: str):    self._users.add(user_id)
    def remove_user(self, user_id: str): self._users.discard(user_id)
    def add_ip(self, ip: str):           self._ips.add(ip)
    def add_keyword(self, kw: str):      self._keywords.add(kw.lower())


class DatabaseBlocklistProvider(DataProvider):
    """
    Blocklist provider backed by the persistence layer (SQLite / PostgreSQL).

    Survives restarts and is consistent across all replicas when using
    PostgreSQL. Entries are cached for ``ttl_secs`` to avoid a DB round-trip
    on every check; mutating methods (add_*/remove_*) invalidate the cache
    immediately.

    Usage::

        from guardrail_framework.opa_gaps import data_registry
        from guardrail_framework.persistence import PersistenceLayer

        db = PersistenceLayer()
        bl = DatabaseBlocklistProvider(db, ttl_secs=30)
        data_registry.register(bl)

        # Add entries at runtime (persisted across restarts):
        bl.add_user("bad-actor-id")
        bl.add_ip("203.0.113.42")
        bl.add_keyword("drop table")
    """

    def __init__(self, persistence: Any, ttl_secs: float = 30.0):
        self._persistence = persistence
        self._ttl = ttl_secs
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_at: float = 0.0
        self._lock = threading.Lock()

    def name(self) -> str:
        return "DatabaseBlocklistProvider"

    def _load(self) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            if self._cache is not None and (now - self._cache_at) < self._ttl:
                return dict(self._cache)
        try:
            raw = self._persistence.load_blocklist()
            result = {
                "_users":    set(raw.get("user", [])),
                "_ips":      set(raw.get("ip", [])),
                "_keywords": set(kw.lower() for kw in raw.get("keyword", [])),
            }
            with self._lock:
                self._cache = result
                self._cache_at = time.time()
            return result
        except Exception as exc:
            logger.warning("DatabaseBlocklistProvider: DB fetch failed: %s", exc)
            return {"_users": set(), "_ips": set(), "_keywords": set()}

    def _invalidate(self):
        with self._lock:
            self._cache = None

    def fetch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load()
        return {
            "blocklisted_user":  context.get("user_id") in data["_users"],
            "blocklisted_ip":    context.get("ip") in data["_ips"],
            "blocked_keywords":  list(data["_keywords"]),
        }

    def add_user(self, user_id: str):
        self._persistence.save_blocklist_entry("user", user_id)
        self._invalidate()

    def remove_user(self, user_id: str):
        self._persistence.delete_blocklist_entry("user", user_id)
        self._invalidate()

    def add_ip(self, ip: str):
        self._persistence.save_blocklist_entry("ip", ip)
        self._invalidate()

    def remove_ip(self, ip: str):
        self._persistence.delete_blocklist_entry("ip", ip)
        self._invalidate()

    def add_keyword(self, kw: str):
        self._persistence.save_blocklist_entry("keyword", kw.lower())
        self._invalidate()

    def remove_keyword(self, kw: str):
        self._persistence.delete_blocklist_entry("keyword", kw.lower())
        self._invalidate()


class HttpDataProvider(DataProvider):
    """
    Fetches enrichment data from a remote HTTP endpoint before each check.
    Includes TTL caching to avoid per-request network calls.
    """

    def __init__(self, url: str, ttl_secs: float = 60.0,
                 auth_token: Optional[str] = None, timeout_secs: float = 2.0):
        self.url = url
        self.ttl = ttl_secs
        self.auth_token = auth_token
        self.timeout = timeout_secs
        self._cache: Optional[Dict] = None
        self._cache_at: float = 0.0
        self._lock = threading.Lock()

    def name(self) -> str:
        return f"HttpDataProvider({self.url})"

    def fetch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            if self._cache is not None and (now - self._cache_at) < self.ttl:
                return dict(self._cache)
        try:
            import urllib.request as _ur
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            req = _ur.Request(self.url, headers=headers)
            with _ur.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
            with self._lock:
                self._cache = data
                self._cache_at = time.time()
            return data
        except Exception as exc:
            logger.warning(f"HttpDataProvider fetch failed: {exc}")
            return {}


class DataProviderRegistry:
    """
    Manages all registered data providers and merges their outputs
    into the context before each guardrail check.

    Usage::

        registry = DataProviderRegistry()
        registry.register(StaticBlocklistProvider(blocked_users=["evil-user"]))
        registry.register(HttpDataProvider("https://threatfeed.example.com/data"))

        # In GuardrailFramework.check_input:
        enriched_context = registry.enrich(context or {})
        result = backend.check_input(text, enriched_context)
    """

    def __init__(self):
        self._providers: List[DataProvider] = []
        self._lock = threading.Lock()
        self.call_count: int = 0
        self.error_count: int = 0

    def register(self, provider: DataProvider) -> "DataProviderRegistry":
        with self._lock:
            self._providers.append(provider)
        logger.info(f"DataProvider registered: {provider.name()}")
        return self

    def unregister(self, name: str):
        with self._lock:
            self._providers = [p for p in self._providers if p.name() != name]

    def enrich(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call every provider and merge results into a copy of context.
        Providers never overwrite existing context keys (they only add).
        """
        enriched = dict(context)
        with self._lock:
            providers = list(self._providers)
        for provider in providers:
            try:
                data = provider.fetch(context)
                for k, v in data.items():
                    enriched.setdefault(k, v)   # don't overwrite existing
                self.call_count += 1
            except Exception as exc:
                self.error_count += 1
                logger.warning(f"DataProvider {provider.name()} error: {exc}")
        return enriched

    def list_providers(self) -> List[str]:
        with self._lock:
            return [p.name() for p in self._providers]

    def stats(self) -> Dict[str, Any]:
        return {
            "providers": self.list_providers(),
            "call_count": self.call_count,
            "error_count": self.error_count,
        }


# ── module-level singletons used by server.py ─────────────────
prom_metrics     = PrometheusMetrics()
status_reporter  = StatusReporter()
data_registry    = DataProviderRegistry()
wasm_scorer      = WasmReadyScorer()
precompiler: Optional[PolicyPrecompiler] = None   # initialised in server.py after framework
