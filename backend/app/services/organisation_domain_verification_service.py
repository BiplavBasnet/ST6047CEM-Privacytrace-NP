"""DNS TXT domain ownership challenges for organisation verification."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings, resolve_company_verification_mode, shared_email_domains
from app.models.enums import DomainChallengeStatus, OrganisationVerificationStatus
from app.models.organisation import Organisation, OrganisationDomainChallenge

CHALLENGE_PREFIX = "privacytrace-verification="
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


class DomainVerificationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def hash_challenge_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalise_domain(raw: str) -> str:
    value = (raw or "").strip().lower()
    value = value.removeprefix("http://").removeprefix("https://")
    value = value.split("/")[0].split("?")[0].split(":")[0]
    if value.startswith("www."):
        value = value[4:]
    value = value.strip(".")
    if not value or not _DOMAIN_RE.match(value):
        raise DomainVerificationError("Invalid domain")
    if value in shared_email_domains():
        raise DomainVerificationError(
            "Shared email-provider domains cannot prove corporate ownership",
            status_code=400,
        )
    return value


def _txt_lookup(domain: str) -> list[str]:
    """Resolve TXT via configurable DNS-over-HTTPS (stdlib only)."""
    settings = get_settings()
    base = (settings.dns_doh_url or "https://cloudflare-dns.com/dns-query").rstrip("?&")
    sep = "&" if "?" in base else "?"
    url = f"{base}{sep}name={domain}&type=TXT"
    timeout = max(2, int(settings.dns_lookup_timeout_seconds))
    retries = max(0, int(settings.dns_lookup_max_retries))
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_exc = exc
            if attempt >= retries:
                raise DomainVerificationError(
                    "DNS verification service unavailable",
                    status_code=503,
                ) from last_exc
    else:
        raise DomainVerificationError("DNS verification service unavailable", status_code=503)
    records: list[str] = []
    for answer in payload.get("Answer") or []:
        if int(answer.get("type") or 0) != 16:
            continue
        data = str(answer.get("data") or "").strip().strip('"')
        records.append(data)
    return records


def create_domain_challenge(
    db: Session,
    org: Organisation,
    *,
    domain: str,
) -> tuple[OrganisationDomainChallenge, str]:
    settings = get_settings()
    normalised = normalise_domain(domain)
    now = datetime.now(UTC)
    pending = db.scalars(
        select(OrganisationDomainChallenge).where(
            OrganisationDomainChallenge.organisation_id == org.id,
            OrganisationDomainChallenge.status == DomainChallengeStatus.PENDING,
        )
    ).all()
    for row in pending:
        row.status = DomainChallengeStatus.SUPERSEDED
    token = secrets.token_urlsafe(32)
    challenge = OrganisationDomainChallenge(
        organisation_id=org.id,
        domain=normalised,
        challenge_hash=hash_challenge_token(token),
        expires_at=now + timedelta(minutes=max(5, int(settings.domain_challenge_ttl_minutes))),
        status=DomainChallengeStatus.PENDING,
        attempt_count=0,
    )
    db.add(challenge)
    org.website_domain = normalised
    org.domain_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
    db.flush()
    return challenge, f"{CHALLENGE_PREFIX}{token}"


def verify_domain_challenge(
    db: Session,
    org: Organisation,
    *,
    txt_lookup=None,
    presented_txt: str | None = None,
) -> OrganisationDomainChallenge:
    settings = get_settings()
    lookup = txt_lookup or _txt_lookup
    challenge = db.scalar(
        select(OrganisationDomainChallenge)
        .where(
            OrganisationDomainChallenge.organisation_id == org.id,
            OrganisationDomainChallenge.status == DomainChallengeStatus.PENDING,
        )
        .order_by(OrganisationDomainChallenge.id.desc())
        .limit(1)
    )
    if challenge is None:
        raise DomainVerificationError("No pending domain challenge", status_code=404)
    now = datetime.now(UTC)
    if challenge.expires_at <= now:
        challenge.status = DomainChallengeStatus.EXPIRED
        raise DomainVerificationError("Domain challenge expired", status_code=400)
    max_attempts = max(1, int(settings.domain_challenge_max_attempts))
    if int(challenge.attempt_count or 0) >= max_attempts:
        raise DomainVerificationError("Domain verification rate limit exceeded", status_code=429)
    challenge.attempt_count = int(challenge.attempt_count or 0) + 1
    matched = False
    offered = (presented_txt or "").strip()
    if offered and resolve_company_verification_mode() == "demo":
        token = offered[len(CHALLENGE_PREFIX) :].strip() if offered.startswith(CHALLENGE_PREFIX) else offered
        matched = hash_challenge_token(token) == challenge.challenge_hash
    else:
        records = lookup(challenge.domain)
        for record in records:
            if not record.startswith(CHALLENGE_PREFIX):
                continue
            token = record[len(CHALLENGE_PREFIX) :].strip()
            if hash_challenge_token(token) == challenge.challenge_hash:
                matched = True
                break
    if not matched:
        raise DomainVerificationError("Incorrect DNS TXT verification record", status_code=400)
    challenge.status = DomainChallengeStatus.VERIFIED
    challenge.verified_at = now
    org.website_domain = challenge.domain
    org.domain_verification_status = OrganisationVerificationStatus.VERIFIED
    if challenge.domain not in (org.approved_email_domains or []):
        domains = list(org.approved_email_domains or [])
        domains.append(challenge.domain)
        org.approved_email_domains = domains
    db.flush()
    return challenge
