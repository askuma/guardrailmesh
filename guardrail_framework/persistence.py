"""
SQLAlchemy persistence layer for policies, audit log, AB tests, and blocklist.

DB_URL env var controls the backend (defaults to SQLite for development).
Set DB_URL=postgresql://user:pass@host/db for production.
"""

import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text, UniqueConstraint,
    create_engine, event, select, text as sa_text, delete as sa_delete,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger("persistence")


class Base(DeclarativeBase):
    pass


class PolicyRecord(Base):
    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    data = Column(Text, nullable=False)       # full JSON blob
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted = Column(Boolean, default=False, nullable=False)


class AuditRecord(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    policy_id = Column(String(64), index=True)
    action = Column(String(64))
    passed = Column(Boolean)
    severity = Column(String(32))
    action_taken = Column(String(32))
    risk_score = Column(Float)
    latency_ms = Column(Float)
    backend = Column(String(64))
    request_id = Column(String(64), index=True)
    extra = Column(Text)   # full JSON blob for querying


class ABTestRecord(Base):
    __tablename__ = "ab_tests"

    id = Column(String(64), primary_key=True)
    name = Column(String(255))
    data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    deleted = Column(Boolean, default=False)


class BlocklistRecord(Base):
    __tablename__ = "blocklist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_type = Column(String(16), nullable=False, index=True)  # "user", "ip", "keyword"
    value = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("entry_type", "value", name="uq_blocklist_type_value"),
    )


def _sqlite_wal(dbapi_con, _):
    """Enable WAL mode for SQLite — safe for concurrent writers."""
    dbapi_con.execute("PRAGMA journal_mode=WAL")
    dbapi_con.execute("PRAGMA synchronous=NORMAL")


class PersistenceLayer:
    """
    Thread-safe persistence layer.

    Usage::
        layer = PersistenceLayer()           # reads DB_URL env var
        layer.save_policy(policy_id, data)
        policies = layer.load_all_policies()
    """

    def __init__(self, db_url: Optional[str] = None):
        url = db_url or os.getenv("GUARDRAIL_DB_URL", "sqlite:///guardrail.db")
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True)

        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _sqlite_wal)

        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        logger.info(f"Persistence layer ready (url={url.split('?')[0]})")

    def ping(self) -> bool:
        """Return True if the database is reachable (used by /ready health probe)."""
        try:
            with self.engine.connect() as conn:
                conn.execute(sa_text("SELECT 1"))
            return True
        except Exception:
            return False

    @contextmanager
    def _session(self):
        session: Session = self._Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ── Policies ─────────────────────────────────────────────────

    def save_policy(self, policy_id: str, policy_data: Dict[str, Any]):
        with self._session() as s:
            existing = s.get(PolicyRecord, policy_id)
            blob = json.dumps(policy_data, default=str)
            if existing:
                existing.data = blob
                existing.name = policy_data.get("name", "")
                existing.updated_at = datetime.now(timezone.utc)
                existing.deleted = False
            else:
                s.add(PolicyRecord(
                    id=policy_id,
                    name=policy_data.get("name", ""),
                    data=blob,
                ))

    def soft_delete_policy(self, policy_id: str):
        with self._session() as s:
            rec = s.get(PolicyRecord, policy_id)
            if rec:
                rec.deleted = True

    def load_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        with self._session() as s:
            rec = s.get(PolicyRecord, policy_id)
            if rec and not rec.deleted:
                return json.loads(rec.data)
            return None

    def load_all_policies(self) -> List[Dict[str, Any]]:
        with self._session() as s:
            records = s.query(PolicyRecord).filter(PolicyRecord.deleted == False).all()
            return [json.loads(r.data) for r in records]

    # ── Audit log ─────────────────────────────────────────────────

    def append_audit(self, entry: Dict[str, Any]):
        with self._session() as s:
            s.add(AuditRecord(
                policy_id=entry.get("policy_id", ""),
                action=entry.get("action", ""),
                passed=bool(entry.get("passed", True)),
                severity=entry.get("severity", "info"),
                action_taken=entry.get("action_taken", "allow"),
                risk_score=float(entry.get("risk_score", 0.0)),
                latency_ms=float(entry.get("latency_ms", 0.0)),
                backend=entry.get("backend", ""),
                request_id=entry.get("request_id", ""),
                extra=json.dumps(entry, default=str),
            ))

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._session() as s:
            records = (
                s.query(AuditRecord)
                .order_by(AuditRecord.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [json.loads(r.extra) for r in records]

    # ── A/B tests ─────────────────────────────────────────────────

    def save_ab_test(self, test_id: str, test_data: Dict[str, Any]):
        with self._session() as s:
            existing = s.get(ABTestRecord, test_id)
            blob = json.dumps(test_data, default=str)
            if existing:
                existing.data = blob
            else:
                s.add(ABTestRecord(
                    id=test_id,
                    name=test_data.get("name", ""),
                    data=blob,
                ))

    def load_all_ab_tests(self) -> List[Dict[str, Any]]:
        with self._session() as s:
            records = s.query(ABTestRecord).filter(ABTestRecord.deleted == False).all()
            return [json.loads(r.data) for r in records]

    # ── Blocklist ──────────────────────────────────────────────────

    def save_blocklist_entry(self, entry_type: str, value: str):
        """Add a user/ip/keyword to the persistent blocklist (idempotent)."""
        with self._session() as s:
            existing = s.execute(
                select(BlocklistRecord).where(
                    BlocklistRecord.entry_type == entry_type,
                    BlocklistRecord.value == value,
                )
            ).scalar_one_or_none()
            if not existing:
                s.add(BlocklistRecord(entry_type=entry_type, value=value))

    def delete_blocklist_entry(self, entry_type: str, value: str):
        """Remove a specific entry from the persistent blocklist."""
        with self._session() as s:
            s.execute(
                sa_delete(BlocklistRecord).where(
                    BlocklistRecord.entry_type == entry_type,
                    BlocklistRecord.value == value,
                )
            )

    def load_blocklist(self) -> Dict[str, List[str]]:
        """Return all blocklist entries grouped by type (user, ip, keyword)."""
        with self._session() as s:
            records = s.query(BlocklistRecord).all()
            result: Dict[str, List[str]] = {}
            for r in records:
                result.setdefault(r.entry_type, []).append(r.value)
            return result
