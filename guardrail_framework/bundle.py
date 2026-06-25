"""
Gap 4: Policy Bundle Distribution   (OPA bundle API parity)
Gap 5: Policy Versioning & Rollback (immutable snapshot store)
Gap 6: Real-time Policy Push        (SSE broadcast channel)

Mirrors:
  OPA /v1/bundles  — tar.gz of policies polled from a remote server
  OPA status API   — last activation time, errors per bundle
  OPAL             — event-driven push to all running agents
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import logging
import tarfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional
from uuid import uuid4

logger = logging.getLogger("BundleManager")


# ══════════════════════════════════════════════════════════════
# Gap 5 — Policy versioning & rollback
# ══════════════════════════════════════════════════════════════

@dataclass
class PolicySnapshot:
    """Immutable snapshot of a GuardrailPolicy at a point in time."""
    snapshot_id: str = field(default_factory=lambda: str(uuid4()))
    policy_id: str = ""
    version_tag: str = "1.0"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str = "system"
    change_reason: str = ""
    data: Dict[str, Any] = field(default_factory=dict)  # serialised policy


class PolicyVersionStore:
    """
    Append-only store of PolicySnapshots.

    Usage::

        store = PolicyVersionStore(max_versions_per_policy=20)
        store.save(policy, created_by="ops@co", reason="tighten sensitivity")

        history = store.history(policy_id)      # newest first
        store.rollback(framework, policy_id, to_version="1.2")
    """

    def __init__(self, max_versions_per_policy: int = 20):
        self.max_versions = max_versions_per_policy
        self._store: Dict[str, List[PolicySnapshot]] = {}   # policy_id → [snap, ...]
        self._lock = threading.Lock()

    def save(self, policy: Any, created_by: str = "system",
             reason: str = "") -> PolicySnapshot:
        """Snapshot the current state of a policy."""
        from .core import GuardrailPolicy
        data = asdict(policy) if hasattr(policy, "__dataclass_fields__") else dict(vars(policy))

        snap = PolicySnapshot(
            policy_id=policy.id,
            version_tag=policy.version,
            created_by=created_by,
            change_reason=reason,
            data=data,
        )
        with self._lock:
            bucket = self._store.setdefault(policy.id, [])
            bucket.append(snap)
            # evict oldest if over limit
            if len(bucket) > self.max_versions:
                bucket.pop(0)

        logger.info(f"Snapshot saved: {policy.id} v{policy.version} ({snap.snapshot_id[:8]})")
        return snap

    def history(self, policy_id: str) -> List[PolicySnapshot]:
        """Return snapshots newest-first."""
        with self._lock:
            return list(reversed(self._store.get(policy_id, [])))

    def get_snapshot(self, policy_id: str, snapshot_id: str) -> Optional[PolicySnapshot]:
        with self._lock:
            for snap in self._store.get(policy_id, []):
                if snap.snapshot_id == snapshot_id:
                    return snap
        return None

    def rollback(self, framework: Any, policy_id: str,
                 snapshot_id: str) -> bool:
        """
        Restore a policy to a specific snapshot.
        Returns True on success, False if snapshot not found.
        """
        snap = self.get_snapshot(policy_id, snapshot_id)
        if snap is None:
            logger.warning(f"Rollback failed: snapshot {snapshot_id} not found")
            return False

        from .core import GuardrailPolicy, GuardrailBackend, RiskCategory, ActionType
        data = copy.deepcopy(snap.data)

        # coerce enums back
        try:
            data["backend"] = GuardrailBackend(data["backend"])
        except Exception:
            pass
        try:
            data["action_on_violation"] = ActionType(data["action_on_violation"])
        except Exception:
            pass
        try:
            data["risk_categories"] = [RiskCategory(r) for r in data.get("risk_categories", [])]
        except Exception:
            pass

        # rebuild policy object
        policy = GuardrailPolicy(**{k: v for k, v in data.items()
                                    if k in GuardrailPolicy.__dataclass_fields__})
        framework.policies[policy_id] = policy
        logger.info(f"Rolled back {policy_id} → snapshot {snapshot_id[:8]}")
        return True

    def all_policy_ids(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                pid: {"versions": len(snaps), "latest": snaps[-1].version_tag if snaps else None}
                for pid, snaps in self._store.items()
            }


# ══════════════════════════════════════════════════════════════
# Gap 4 — Bundle distribution
# ══════════════════════════════════════════════════════════════

@dataclass
class BundleMetadata:
    name: str
    revision: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sha256: str = ""
    policy_count: int = 0
    size_bytes: int = 0
    activated_at: Optional[str] = None
    activation_error: Optional[str] = None


class BundleBuilder:
    """
    Serialize a set of policies into an OPA-compatible tar.gz bundle.

    Bundle layout::

        bundle.tar.gz
        ├── .manifest          (JSON: revision, roots, metadata)
        └── policies/
            ├── <policy_id>.json
            └── ...
    """

    @staticmethod
    def build(policies: Dict[str, Any],
              bundle_name: str = "guardrail-bundle",
              revision: Optional[str] = None) -> bytes:
        revision = revision or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # manifest
            manifest = {
                "revision": revision,
                "bundle_name": bundle_name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "roots": ["policies"],
                "policy_count": len(policies),
            }
            _add_json(tar, ".manifest", manifest)

            # individual policy files
            for pid, policy in policies.items():
                data = asdict(policy) if hasattr(policy, "__dataclass_fields__") else dict(policy)
                _add_json(tar, f"policies/{pid}.json", data)

        raw = buf.getvalue()
        return raw

    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


def _add_json(tar: tarfile.TarFile, name: str, obj: Any):
    raw = json.dumps(obj, indent=2).encode()
    info = tarfile.TarInfo(name=name)
    info.size = len(raw)
    tar.addfile(info, io.BytesIO(raw))


class BundleLoader:
    """Extract policies from a tar.gz bundle back into a framework."""

    @staticmethod
    def load(data: bytes, framework: Any,
             version_store: Optional[PolicyVersionStore] = None,
             created_by: str = "bundle-loader") -> BundleMetadata:
        sha = BundleBuilder.sha256(data)
        meta = BundleMetadata(name="unknown", revision="unknown", sha256=sha,
                              size_bytes=len(data))
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                # read manifest
                try:
                    mf = tar.extractfile(".manifest")
                    if mf:
                        manifest = json.load(mf)
                        meta.name = manifest.get("bundle_name", "unknown")
                        meta.revision = manifest.get("revision", "unknown")
                except Exception:
                    pass

                # load each policy file
                count = 0
                from .core import GuardrailPolicy, GuardrailBackend, RiskCategory, ActionType
                for member in tar.getmembers():
                    if not member.name.startswith("policies/"):
                        continue
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    raw = json.loads(f.read())
                    # coerce enums
                    try:
                        raw["backend"] = GuardrailBackend(raw["backend"])
                    except Exception:
                        pass
                    try:
                        raw["action_on_violation"] = ActionType(raw["action_on_violation"])
                    except Exception:
                        pass
                    try:
                        raw["risk_categories"] = [RiskCategory(r) for r in raw.get("risk_categories", [])]
                    except Exception:
                        pass
                    policy = GuardrailPolicy(**{k: v for k, v in raw.items()
                                                if k in GuardrailPolicy.__dataclass_fields__})
                    framework.policies[policy.id] = policy
                    if version_store:
                        version_store.save(policy, created_by=created_by,
                                           reason=f"bundle load rev={meta.revision}")
                    count += 1

                meta.policy_count = count
                meta.activated_at = datetime.now(timezone.utc).isoformat()
                logger.info(f"Bundle activated: {meta.name} rev={meta.revision} ({count} policies)")

        except Exception as exc:
            meta.activation_error = str(exc)
            logger.error(f"Bundle activation failed: {exc}")

        return meta


class BundlePoller:
    """
    Periodically polls a remote URL for a new bundle.
    On change (different SHA-256), atomically loads it into the framework.

    Usage::

        poller = BundlePoller(
            bundle_url="https://config.example.com/guardrail-bundle.tar.gz",
            framework=framework,
            interval_secs=30,
        )
        poller.start()
    """

    def __init__(
        self,
        bundle_url: str,
        framework: Any,
        interval_secs: float = 30.0,
        version_store: Optional[PolicyVersionStore] = None,
        auth_token: Optional[str] = None,
        on_activation: Optional[Callable[[BundleMetadata], None]] = None,
    ):
        self.bundle_url = bundle_url
        self.framework = framework
        self.interval_secs = interval_secs
        self.version_store = version_store
        self.auth_token = auth_token
        self.on_activation = on_activation

        self._last_sha: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_meta: Optional[BundleMetadata] = None
        self.poll_errors: int = 0

    def start(self) -> "BundlePoller":
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="BundlePoller", daemon=True)
        self._thread.start()
        logger.info(f"BundlePoller started → {self.bundle_url} every {self.interval_secs}s")
        return self

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self):
        while not self._stop.is_set():
            self._poll_once()
            self._stop.wait(timeout=self.interval_secs)

    def _poll_once(self):
        try:
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            req = urllib.request.Request(self.bundle_url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
            sha = BundleBuilder.sha256(data)
            if sha == self._last_sha:
                logger.debug("Bundle unchanged — skipping")
                return
            logger.info(f"New bundle detected (sha={sha[:12]}…) — loading")
            meta = BundleLoader.load(data, self.framework, self.version_store)
            if not meta.activation_error:
                self._last_sha = sha
                self.last_meta = meta
                if self.on_activation:
                    self.on_activation(meta)
            else:
                self.poll_errors += 1
        except Exception as exc:
            self.poll_errors += 1
            logger.warning(f"BundlePoller fetch error: {exc}")

    def stats(self) -> Dict[str, Any]:
        return {
            "bundle_url": self.bundle_url,
            "interval_secs": self.interval_secs,
            "last_sha": self._last_sha,
            "poll_errors": self.poll_errors,
            "last_meta": asdict(self.last_meta) if self.last_meta else None,
            "running": bool(self._thread and self._thread.is_alive()),
        }


# ══════════════════════════════════════════════════════════════
# Gap 6 — Real-time policy push (OPAL / SSE pattern)
# ══════════════════════════════════════════════════════════════

class PolicyPushChannel:
    """
    Server-Sent Events (SSE) broadcast channel.

    The FastAPI /push/events endpoint yields from this channel.
    Any code that updates a policy calls push_channel.broadcast(event)
    and all connected SSE clients receive it immediately.

    Usage in server.py::

        push_channel = PolicyPushChannel()

        @app.get("/push/events")
        async def sse(request: Request):
            return EventSourceResponse(push_channel.subscribe())

        # When a policy changes:
        push_channel.broadcast({"type": "policy_updated", "policy_id": pid})
    """

    def __init__(self):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()

    def broadcast(self, event: Dict[str, Any]):
        """Send an event to all connected SSE subscribers."""
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        dead = []
        with self._lock:
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)
        logger.debug(f"Broadcast to {len(self._subscribers)} subscribers: {event.get('type')}")

    def subscribe(self) -> Generator[str, None, None]:
        """
        Generator for SSE — yields formatted SSE strings.
        Wire this into a FastAPI StreamingResponse or EventSourceResponse.
        """
        import queue as _q
        q: queue.Queue = _q.Queue(maxsize=200)
        with self._lock:
            self._subscribers.append(q)
        try:
            # heartbeat first
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                try:
                    event = q.get(timeout=30)
                    yield f"data: {json.dumps(event)}\n\n"
                except _q.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with self._lock:
                if q in self._subscribers:
                    self._subscribers.remove(q)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# singleton used by server.py
push_channel = PolicyPushChannel()
