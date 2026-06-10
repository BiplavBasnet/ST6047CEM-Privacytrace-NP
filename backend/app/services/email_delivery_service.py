"""Minimal SMTP delivery for verification, invitations, and password reset."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from app.config import get_settings, resolve_company_verification_mode, synthetic_demo_actions_allowed

logger = logging.getLogger(__name__)


class EmailDeliveryError(Exception):
    def __init__(self, message: str, status_code: int = 503):
        self.status_code = status_code
        super().__init__(message)


def smtp_configured() -> bool:
    settings = get_settings()
    if not settings.smtp_enabled:
        return False
    host = (settings.smtp_host or "").strip()
    return bool(host)


def demo_token_exposure_allowed() -> bool:
    """Expose one-time tokens only in synthetic envs when SMTP is off (never production)."""
    if not synthetic_demo_actions_allowed() or smtp_configured():
        return False
    settings = get_settings()
    env = (settings.app_env or "").strip().lower()
    mode = resolve_company_verification_mode()
    return mode == "demo" or env in {"test", "dev", "development", "demo"}


def send_email(*, to_address: str, subject: str, body_text: str) -> None:
    """Send plain-text email. Never logs credentials or tokens."""
    settings = get_settings()
    if not smtp_configured():
        raise EmailDeliveryError("SMTP is not enabled")
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_address.strip()
    msg["Subject"] = subject
    msg.set_content(body_text)
    timeout = max(3, int(settings.smtp_timeout_seconds))
    try:
        with smtplib.SMTP(settings.smtp_host, int(settings.smtp_port), timeout=timeout) as server:
            if settings.smtp_tls:
                server.starttls()
            user = (settings.smtp_username or "").strip()
            if user:
                server.login(user, settings.smtp_password or "")
            server.send_message(msg)
    except Exception as exc:
        logger.warning("SMTP delivery failed for recipient domain path")
        raise EmailDeliveryError("Email delivery failed") from exc


def build_frontend_link(path: str) -> str:
    base = (get_settings().frontend_public_url or "").rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"
