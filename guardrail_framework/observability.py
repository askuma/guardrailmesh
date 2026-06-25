"""
Monitoring, Logging, Metrics, and Alerting System
Unified observability for guardrail checks across all backends
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of alerts that can be triggered"""
    HIGH_BLOCK_RATE = "high_block_rate"
    LATENCY_SPIKE = "latency_spike"
    BACKEND_FAILURE = "backend_failure"
    ANOMALOUS_PATTERN = "anomalous_pattern"
    REPEATED_VIOLATIONS = "repeated_violations"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class Alert:
    """Alert triggered by monitoring system"""
    id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_id: Optional[str] = None
    backend_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    resolved: bool = False


@dataclass
class MetricPoint:
    """Single metric data point"""
    timestamp: str
    value: float
    policy_id: Optional[str] = None
    backend_name: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collects and aggregates metrics"""
    
    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self.metrics: Dict[str, List[MetricPoint]] = defaultdict(list)
        self.logger = logging.getLogger("MetricsCollector")
    
    def record_metric(self, metric_name: str, value: float, 
                     policy_id: Optional[str] = None,
                     backend_name: Optional[str] = None,
                     tags: Optional[Dict[str, str]] = None):
        """Record a metric value"""
        point = MetricPoint(
            timestamp=datetime.now(timezone.utc).isoformat(),
            value=value,
            policy_id=policy_id,
            backend_name=backend_name,
            tags=tags or {}
        )
        self.metrics[metric_name].append(point)
        self._cleanup_old_metrics()
    
    def get_metric_history(self, metric_name: str, hours: int = 1) -> List[MetricPoint]:
        """Get metric history for the past N hours"""
        if metric_name not in self.metrics:
            return []
        
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [
            p for p in self.metrics[metric_name]
            if datetime.fromisoformat(p.timestamp) > cutoff
        ]
    
    def get_metric_summary(self, metric_name: str, hours: int = 1) -> Dict[str, float]:
        """Get summary statistics for a metric"""
        points = self.get_metric_history(metric_name, hours)
        
        if not points:
            return {}
        
        values = [p.value for p in points]
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "latest": values[-1] if values else 0
        }
    
    def _cleanup_old_metrics(self):
        """Remove metrics older than retention period"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
        cutoff_iso = cutoff.isoformat()
        
        for metric_name in self.metrics:
            self.metrics[metric_name] = [
                p for p in self.metrics[metric_name]
                if p.timestamp > cutoff_iso
            ]


class AlertingSystem:
    """Monitors metrics and triggers alerts"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.alerts: List[Alert] = []
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger("AlertingSystem")
        
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Set up default alerting rules"""
        self.alert_rules = {
            "high_block_rate": {
                "metric": "block_rate",
                "threshold": 0.3,  # 30%
                "window_minutes": 5,
                "severity": AlertSeverity.WARNING
            },
            "latency_spike": {
                "metric": "latency_p95_ms",
                "threshold": 500,
                "window_minutes": 10,
                "severity": AlertSeverity.WARNING
            },
            "backend_failure": {
                "metric": "backend_error_rate",
                "threshold": 0.1,
                "window_minutes": 5,
                "severity": AlertSeverity.CRITICAL
            },
            "repeated_violations": {
                "metric": "violation_count",
                "threshold": 10,
                "window_minutes": 5,
                "severity": AlertSeverity.WARNING
            }
        }
    
    def check_alerts(self) -> List[Alert]:
        """Evaluate all alert rules and return triggered alerts"""
        triggered = []
        
        for alert_type, rule in self.alert_rules.items():
            metric_name = rule["metric"]
            threshold = rule["threshold"]
            window = rule["window_minutes"]
            severity = rule["severity"]
            
            summary = self.metrics.get_metric_summary(metric_name, hours=window/60)
            
            if summary and summary.get("latest", 0) > threshold:
                alert = Alert(
                    id=f"{alert_type}_{datetime.now(timezone.utc).timestamp()}",
                    alert_type=AlertType[alert_type.upper()],
                    severity=severity,
                    title=f"Alert: {alert_type}",
                    description=f"Metric '{metric_name}' exceeded threshold {threshold}. Current value: {summary['latest']}",
                    metric_value=summary["latest"],
                    threshold=threshold
                )
                triggered.append(alert)
        
        return triggered
    
    def add_alert_rule(self, name: str, metric: str, threshold: float, 
                      window_minutes: int, severity: AlertSeverity):
        """Add a custom alert rule"""
        self.alert_rules[name] = {
            "metric": metric,
            "threshold": threshold,
            "window_minutes": window_minutes,
            "severity": severity
        }
        self.logger.info(f"Alert rule added: {name}")
    
    def trigger_alert(self, alert: Alert):
        """Manually trigger an alert"""
        self.alerts.append(alert)
        self.logger.warning(f"Alert triggered: {alert.title}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all unresolved alerts"""
        return [a for a in self.alerts if not a.resolved]
    
    def resolve_alert(self, alert_id: str):
        """Mark an alert as resolved"""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.resolved = True
                self.logger.info(f"Alert resolved: {alert_id}")
                break


class AuditLogger:
    """Specialized logger for audit trails and compliance"""
    
    def __init__(self, log_file: Optional[str] = None):
        self.logger = logging.getLogger("AuditLogger")
        self.log_file = log_file
        self.entries: List[Dict[str, Any]] = []
        
        if log_file:
            handler = logging.FileHandler(log_file)
            self.logger.addHandler(handler)
    
    def log_guardrail_check(self, policy_id: str, action: str, 
                           passed: bool, risk_score: float,
                           input_text: str, output_text: str,
                           backend: str, latency_ms: float):
        """Log a guardrail check for audit purposes"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_id": policy_id,
            "action": action,
            "passed": passed,
            "risk_score": risk_score,
            "backend": backend,
            "latency_ms": latency_ms,
            "input_length": len(input_text),
            "output_length": len(output_text)
        }
        
        self.entries.append(entry)
        self.logger.info(json.dumps(entry))
    
    def log_policy_change(self, policy_id: str, action: str, details: Dict[str, Any]):
        """Log policy creation, update, or deletion"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "policy_change",
            "policy_id": policy_id,
            "action": action,
            "details": details
        }
        
        self.entries.append(entry)
        self.logger.info(json.dumps(entry))
    
    def log_backend_error(self, backend: str, error: str, context: Optional[Dict] = None):
        """Log backend failures or errors"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "backend_error",
            "backend": backend,
            "error": error,
            "context": context or {}
        }
        
        self.entries.append(entry)
        self.logger.error(json.dumps(entry))
    
    def get_compliance_report(self, start_date: str, end_date: str) -> Dict[str, Any]:
        """Generate compliance report for date range"""
        start = datetime.fromisoformat(start_date).replace(tzinfo=None)
        end = datetime.fromisoformat(end_date).replace(tzinfo=None)

        def _naive(ts: str) -> datetime:
            return datetime.fromisoformat(ts).replace(tzinfo=None)

        filtered = [
            e for e in self.entries
            if start <= _naive(e["timestamp"]) <= end
        ]
        
        report = {
            "period": {
                "start": start_date,
                "end": end_date
            },
            "summary": {
                "total_checks": len([e for e in filtered if e.get("action") == "check"]),
                "checks_passed": len([e for e in filtered if e.get("passed")]),
                "checks_failed": len([e for e in filtered if not e.get("passed")]),
                "average_risk_score": sum(
                    e.get("risk_score", 0) for e in filtered
                ) / len([e for e in filtered if "risk_score" in e]) if filtered else 0
            },
            "entries": filtered
        }
        
        return report


class PerformanceMonitor:
    """Monitors backend performance and SLA compliance"""
    
    def __init__(self):
        self.metrics = MetricsCollector()
        self.logger = logging.getLogger("PerformanceMonitor")
        self.sla_targets = {
            "latency_p95_ms": 100,
            "latency_p99_ms": 500,
            "availability_percent": 99.9,
            "error_rate": 0.01
        }
    
    def record_check(self, backend: str, latency_ms: float, 
                    passed: bool, policy_id: Optional[str] = None):
        """Record a guardrail check result"""
        # Record latency
        self.metrics.record_metric(
            "latency_ms",
            latency_ms,
            policy_id=policy_id,
            backend_name=backend
        )
        
        # Record success/failure
        self.metrics.record_metric(
            "success_rate",
            1.0 if passed else 0.0,
            policy_id=policy_id,
            backend_name=backend
        )
    
    def get_sla_compliance(self, backend: str, hours: int = 24) -> Dict[str, float]:
        """Check SLA compliance for a backend"""
        latencies = self.metrics.get_metric_history("latency_ms", hours=hours)
        
        if not latencies:
            return {}
        
        values = sorted([p.value for p in latencies])
        n = len(values)
        
        p95_idx = int(n * 0.95)
        p99_idx = int(n * 0.99)
        
        return {
            "p95_latency_ms": values[p95_idx] if n > 0 else 0,
            "p99_latency_ms": values[p99_idx] if n > 0 else 0,
            "sla_met": values[p95_idx] <= self.sla_targets["latency_p95_ms"],
        }
    
    def get_backend_health(self, backend: str) -> Dict[str, Any]:
        """Get overall health status of a backend"""
        latency_summary = self.metrics.get_metric_summary("latency_ms", hours=1)
        sla = self.get_sla_compliance(backend, hours=1)
        
        return {
            "backend": backend,
            "status": "healthy" if sla.get("sla_met") else "degraded",
            "latency": latency_summary,
            "sla": sla
        }


class ObservabilityStack:
    """Unified observability platform combining metrics, alerts, and logging"""
    
    def __init__(self):
        self.metrics = MetricsCollector()
        self.alerting = AlertingSystem(self.metrics)
        self.audit = AuditLogger()
        self.performance = PerformanceMonitor()
        self.logger = logging.getLogger("ObservabilityStack")
    
    def record_guardrail_check(self, policy_id: str, backend: str, 
                              input_text: str, output_text: str,
                              passed: bool, risk_score: float, latency_ms: float):
        """Unified method to record all aspects of a guardrail check"""
        # Log to audit trail
        self.audit.log_guardrail_check(
            policy_id, "guardrail_check", passed, risk_score,
            input_text, output_text, backend, latency_ms
        )
        
        # Record metrics
        self.metrics.record_metric("check_count", 1, policy_id=policy_id, backend_name=backend)
        self.metrics.record_metric("pass_rate", 1.0 if passed else 0.0, 
                                  policy_id=policy_id, backend_name=backend)
        self.metrics.record_metric("risk_score", risk_score, 
                                  policy_id=policy_id, backend_name=backend)
        self.metrics.record_metric("latency_ms", latency_ms, 
                                  policy_id=policy_id, backend_name=backend)
        
        # Update performance monitor
        self.performance.record_check(backend, latency_ms, passed, policy_id)
        
        # Check for alerts
        alerts = self.alerting.check_alerts()
        for alert in alerts:
            self.alerting.trigger_alert(alert)
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for observability dashboard"""
        return {
            "metrics": {
                "check_count": self.metrics.get_metric_summary("check_count"),
                "pass_rate": self.metrics.get_metric_summary("pass_rate"),
                "latency_ms": self.metrics.get_metric_summary("latency_ms"),
                "risk_score": self.metrics.get_metric_summary("risk_score")
            },
            "alerts": {
                "active": self.alerting.get_active_alerts(),
                "total": len(self.alerting.alerts)
            },
            "performance": {
                "sla_metrics": self.performance.sla_targets
            }
        }
