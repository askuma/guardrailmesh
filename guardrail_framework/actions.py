"""
Concrete implementations of ESCALATE and REWRITE actions.

ESCALATE  — sends an HTTP webhook POST and optionally an SMTP e-mail.
REWRITE   — redacts flagged spans and returns sanitised text.

Configuration via environment variables (all optional):
    GUARDRAIL_ESCALATION_WEBHOOK_URL  — HTTP endpoint that receives violation payloads
    GUARDRAIL_SMTP_HOST               — SMTP server hostname
    GUARDRAIL_SMTP_PORT               — SMTP server port (default: 587)
    GUARDRAIL_SMTP_USER               — SMTP login user
    GUARDRAIL_SMTP_PASS               — SMTP login password
    GUARDRAIL_SMTP_FROM               — From address (defaults to SMTP user)
"""

import json
import logging
import os
import re
import smtplib
import urllib.request
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

logger = logging.getLogger("actions")


# ─────────────────────────────────────────────────────────────────────────────
# ESCALATE
# ─────────────────────────────────────────────────────────────────────────────

def escalate(
    policy_id: str,
    policy_name: str,
    result: Any,
    escalation_email: Optional[str] = None,
) -> None:
    """Fire webhook and optional email for an ESCALATE action result."""
    payload = {
        "policy_id": policy_id,
        "policy_name": policy_name,
        "risk_score": result.risk_score,
        "detected_risks": result.detected_risks,
        "severity": result.severity,
        "request_id": result.request_id,
        "timestamp": result.timestamp,
    }
    _send_webhook(payload)
    if escalation_email:
        _send_email(escalation_email, policy_name, payload)


def _send_webhook(payload: Dict) -> None:
    url = os.getenv("GUARDRAIL_ESCALATION_WEBHOOK_URL", "").strip()
    if not url:
        logger.debug("GUARDRAIL_ESCALATION_WEBHOOK_URL not set — skipping webhook.")
        return
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
        logger.info(f"Escalation webhook sent for policy {payload['policy_id'][:8]}")
    except Exception as exc:
        logger.warning(f"Escalation webhook failed: {exc}")


def _send_email(to_addr: str, policy_name: str, payload: Dict) -> None:
    smtp_host = os.getenv("GUARDRAIL_SMTP_HOST", "").strip()
    if not smtp_host:
        logger.debug("GUARDRAIL_SMTP_HOST not set — skipping escalation email.")
        return

    smtp_port = int(os.getenv("GUARDRAIL_SMTP_PORT", "587"))
    smtp_user = os.getenv("GUARDRAIL_SMTP_USER", "")
    smtp_pass = os.getenv("GUARDRAIL_SMTP_PASS", "")
    from_addr = os.getenv("GUARDRAIL_SMTP_FROM", smtp_user or "guardrail@localhost")

    body = (
        f"GUARDRAIL ESCALATION — {policy_name}\n\n"
        f"Risk score : {payload['risk_score']:.3f}\n"
        f"Severity   : {payload['severity']}\n"
        f"Request ID : {payload['request_id']}\n"
        f"Timestamp  : {payload['timestamp']}\n\n"
        f"Detected risks:\n{json.dumps(payload['detected_risks'], indent=2)}\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[Guardrail] Escalation: {policy_name}"
    msg["From"] = from_addr
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if smtp_user and smtp_pass:
                smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
        logger.info(f"Escalation email sent to {to_addr}")
    except Exception as exc:
        logger.warning(f"Escalation email failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# REWRITE
# ─────────────────────────────────────────────────────────────────────────────

# Ordered redaction rules — applied in sequence; first match wins for overlapping spans.
_REWRITE_RULES: List = [
    # Credentials
    (re.compile(r'(?i)\b(password|passwd|secret|api[_\s]?key|token|auth[_\s]?token)\s*[:=]\s*\S+'), "[CREDENTIAL_REDACTED]"),
    # US Social Security Number
    (re.compile(r'\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b'), "[SSN_REDACTED]"),
    # Credit cards (Visa / Mastercard / Amex / Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), "[CARD_REDACTED]"),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), "[EMAIL_REDACTED]"),
    # Phone numbers (US-style)
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'), "[PHONE_REDACTED]"),
    # IP addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), "[IP_REDACTED]"),
    # JWT tokens (3-part base64url)
    (re.compile(r'\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'), "[JWT_REDACTED]"),
    # Generic long hex strings that look like secrets (32+ hex chars)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), "[HEX_SECRET_REDACTED]"),
]

# Injection/jailbreak phrases: replace the entire sentence containing the match.
_INJECTION_SENTENCE_PATS = [
    re.compile(r'[^.!?\n]*(?:ignore|disregard|forget)\s+(?:\w+\s+){0,3}(?:instructions|rules|guidelines)[^.!?\n]*[.!?\n]?', re.I),
    re.compile(r'[^.!?\n]*pretend\s+(?:you\s+are|to\s+be)[^.!?\n]*[.!?\n]?', re.I),
    re.compile(r'[^.!?\n]*you\s+are\s+now\s+(?:DAN|jailbroken|unrestricted)[^.!?\n]*[.!?\n]?', re.I),
]


def rewrite_text(text: str, detected_risks: Optional[List[Dict]] = None) -> str:
    """
    Redact/rewrite text by:
    1. Removing sentences that contain injection/jailbreak phrases.
    2. Replacing PII patterns with labelled placeholders.
    """
    result = text

    # Step 1: remove injection sentences
    for pat in _INJECTION_SENTENCE_PATS:
        result = pat.sub("[CONTENT_REMOVED]", result)

    # Step 2: replace PII spans
    for pat, replacement in _REWRITE_RULES:
        result = pat.sub(replacement, result)

    return result
