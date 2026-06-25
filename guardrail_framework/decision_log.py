"""
Gap 3: Remote Decision Log Shipping

OPA periodically uploads batched decision logs to a remote HTTP endpoint
with exponential backoff on failure.

DecisionLogShipper replicates this:
  - async in-memory queue
  - configurable remote sink URL
  - chunked uploads (max_chunk_size records)
  - exponential backoff with jitter
  - background thread so it never blocks a guardrail check
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


logger = logging.getLogger("DecisionLogShipper")


@dataclass
class DecisionEvent:
    """A single logged guardrail decision — mirrors OPA decision log schema."""
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # policy context
    policy_id: str = ""
    policy_name: str = ""
    policy_version: str = "1.0"
    backend: str = ""

    # check context
    check_type: str = ""          # input_check | output_check | tool_validation
    input_length: int = 0
    output_length: int = 0

    # decision
    passed: bool = True
    risk_score: float = 0.0
    action_taken: str = "allow"
    severity: str = "info"
    detected_risks: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0

    # tracing
    request_id: str = ""
    user_context: Dict[str, Any] = field(default_factory=dict)

    # bundle / version metadata (OPA parity)
    bundle_name: Optional[str] = None
    bundle_revision: Optional[str] = None


class DecisionLogShipper:
    """
    Ships decision events to a remote HTTP endpoint in batches.

    Usage::

        shipper = DecisionLogShipper(
            sink_url="https://logs.example.com/guardrail/decisions",
            max_chunk_size=100,
            flush_interval_secs=10,
        )
        shipper.start()

        # After each guardrail check:
        shipper.enqueue(DecisionEvent(
            policy_id=..., passed=result.passed, ...
        ))

        # On shutdown:
        shipper.stop()
    """

    def __init__(
        self,
        sink_url: str,
        max_chunk_size: int = 100,
        flush_interval_secs: float = 10.0,
        max_retries: int = 5,
        upload_size_limit_bytes: int = 1_000_000,   # 1 MB per chunk
        auth_token: Optional[str] = None,
    ):
        self.sink_url = sink_url
        self.max_chunk_size = max_chunk_size
        self.flush_interval_secs = flush_interval_secs
        self.max_retries = max_retries
        self.upload_size_limit_bytes = upload_size_limit_bytes
        self.auth_token = auth_token

        self._queue: queue.Queue[DecisionEvent] = queue.Queue(maxsize=50_000)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # stats
        self.events_enqueued: int = 0
        self.events_shipped: int = 0
        self.events_dropped: int = 0
        self.upload_errors: int = 0
        self.last_upload_at: Optional[str] = None
        self.last_error: Optional[str] = None

    # ── lifecycle ──────────────────────────────────────────────

    def start(self) -> "DecisionLogShipper":
        """Start the background shipping thread."""
        if self._thread and self._thread.is_alive():
            return self
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="DecisionLogShipper", daemon=True
        )
        self._thread.start()
        logger.info(f"DecisionLogShipper started → {self.sink_url}")
        return self

    def stop(self, drain_timeout_secs: float = 30.0):
        """Flush remaining events then stop the thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=drain_timeout_secs)
        self._flush_once()    # final flush
        logger.info("DecisionLogShipper stopped.")

    # ── enqueue ────────────────────────────────────────────────

    def enqueue(self, event: DecisionEvent):
        """Non-blocking enqueue. Drops if queue is full."""
        try:
            self._queue.put_nowait(event)
            self.events_enqueued += 1
        except queue.Full:
            self.events_dropped += 1
            logger.warning("DecisionLogShipper queue full — event dropped")

    def enqueue_from_result(
        self,
        result: Any,          # GuardrailResult
        policy_id: str,
        policy_name: str,
        check_type: str,
        input_text: str = "",
        output_text: str = "",
        context: Optional[Dict] = None,
        bundle_name: Optional[str] = None,
        bundle_revision: Optional[str] = None,
    ):
        """Convenience helper: build a DecisionEvent from a GuardrailResult."""
        event = DecisionEvent(
            policy_id=policy_id,
            policy_name=policy_name,
            backend=result.backend_used.value if hasattr(result.backend_used, "value") else str(result.backend_used),
            check_type=check_type,
            input_length=len(input_text),
            output_length=len(output_text),
            passed=result.passed,
            risk_score=result.risk_score,
            action_taken=result.action.value if hasattr(result.action, "value") else str(result.action),
            severity=result.severity,
            detected_risks=result.detected_risks,
            latency_ms=result.latency_ms,
            request_id=result.request_id,
            user_context=context or {},
            bundle_name=bundle_name,
            bundle_revision=bundle_revision,
        )
        self.enqueue(event)

    # ── background loop ────────────────────────────────────────

    def _loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.flush_interval_secs)
            self._flush_once()

    def _flush_once(self):
        """Drain queue into chunks and upload each chunk."""
        batch: List[DecisionEvent] = []
        try:
            while True:
                batch.append(self._queue.get_nowait())
                if len(batch) >= self.max_chunk_size:
                    self._upload_chunk(batch)
                    batch = []
        except queue.Empty:
            pass
        if batch:
            self._upload_chunk(batch)

    def _upload_chunk(self, events: List[DecisionEvent]):
        payload = json.dumps([asdict(e) for e in events]).encode()

        # respect upload_size_limit_bytes — split if needed
        if len(payload) > self.upload_size_limit_bytes:
            mid = len(events) // 2
            self._upload_chunk(events[:mid])
            self._upload_chunk(events[mid:])
            return

        self._post_with_retry(payload, len(events))

    def _post_with_retry(self, payload: bytes, n: int):
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        for attempt in range(self.max_retries):
            try:
                req = urllib.request.Request(
                    self.sink_url, data=payload, headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status < 300:
                        self.events_shipped += n
                        self.last_upload_at = datetime.now(timezone.utc).isoformat()
                        logger.debug(f"Shipped {n} events (attempt {attempt+1})")
                        return
                    logger.warning(f"Sink returned HTTP {resp.status}")
            except Exception as exc:
                self.last_error = str(exc)
                self.upload_errors += 1
                wait = min(2 ** attempt + 0.1 * attempt, 60)
                logger.warning(f"Upload attempt {attempt+1} failed: {exc} — retry in {wait:.1f}s")
                if attempt < self.max_retries - 1:
                    time.sleep(wait)

        logger.error(f"Giving up after {self.max_retries} attempts — {n} events lost")
        self.events_dropped += n

    # ── introspection ──────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            "sink_url": self.sink_url,
            "queue_depth": self._queue.qsize(),
            "events_enqueued": self.events_enqueued,
            "events_shipped": self.events_shipped,
            "events_dropped": self.events_dropped,
            "upload_errors": self.upload_errors,
            "last_upload_at": self.last_upload_at,
            "last_error": self.last_error,
            "running": bool(self._thread and self._thread.is_alive()),
        }
