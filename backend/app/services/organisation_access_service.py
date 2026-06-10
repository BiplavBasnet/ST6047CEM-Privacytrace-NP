"""Organisation membership, first-setup lock, and invitation access control.

One PrivacyTrace-NP deployment serves one organisation. Shared-instance
SaaS multi-tenancy is out of scope. Access is derived from authenticated
membership, never from a client-supplied organisation_id.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings, resolve_company_verification_mode, synthetic_demo_actions_allowed
from app.models.enums import (
    InvitationStatus,
    MembershipStatus,
    OrganisationStatus,
    OrganisationVerificationStatus,
    UserRole,
)
from app.models.incident import Incident
from app.models.organisation import (
    DeploymentSetup,
    Organisation,
    OrganisationInvitation,
    OrganisationMembership,
)
from app.models.user import User
from app.services import password_service, user_service

SETUP_LOCK_KEY = 88114422
SETUP_COMPLETED_DETAIL = "Setup already completed"
BOOTSTRAP_REQUIRED_DETAIL = "A valid deployment bootstrap credential is required."
BOOTSTRAP_USED_DETAIL = "Bootstrap credential already used."
BOOTSTRAP_UNCONFIGURED = "Deployment bootstrap is not configured."
UNASSIGNED_DETAIL = (
    "Your account is not currently assigned to an organisation. "
    "Contact an organisation administrator or accept an invitation."
)
ORG_SUSPENDED_DETAIL = "This organisation is suspended."
ORG_UNVERIFIED_DETAIL = "Organisation verification is incomplete. Operational access is unavailable."
LAST_ADMIN_DETAIL = "Another active Organisation Administrator must exist first."
UNVERIFIED_INVITE_DETAIL = "Only a verified organisation may invite employees."
PLATFORM_ADMIN_BLOCKED = "Platform administrator cannot be assigned this way."
INVITE_TTL = timedelta(days=7)
DEMO_ORG_NAME = "PrivacyTrace Demo"
DEMO_ORG_SLUG = "privacytrace-demo"

ORG_ADMIN_ROLES = frozenset({UserRole.ADMIN, UserRole.ORGANISATION_ADMIN})
ASSIGNABLE_ROLES = frozenset(
    {
        UserRole.VIEWER,
        UserRole.SECURITY_ANALYST,
        UserRole.DEVELOPER,
        UserRole.DEVSECOPS_ENGINEER,
        UserRole.AUDITOR,
        UserRole.ADMIN,
        UserRole.ORGANISATION_ADMIN,
    }
)


class OrganisationAccessError(Exception):
    def __init__(self, message: str, status_code: int = 403):
        self.status_code = status_code
        super().__init__(message)


class SetupAlreadyCompletedError(OrganisationAccessError):
    def __init__(self, message: str = SETUP_COMPLETED_DETAIL):
        super().__init__(message, status_code=409)


def hash_invitation_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_bootstrap_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_and_consume_bootstrap(db: Session, bootstrap_token: str | None) -> None:
    """Validate PRIVACYTRACE_BOOTSTRAP_TOKEN and mark it consumed (one-time)."""
    settings = get_settings()
    expected = (settings.privacytrace_bootstrap_token or "").strip()
    provided = (bootstrap_token or "").strip()
    if not expected:
        raise OrganisationAccessError(BOOTSTRAP_UNCONFIGURED, status_code=503)
    if not provided or not secrets.compare_digest(
        hash_bootstrap_token(provided), hash_bootstrap_token(expected)
    ):
        raise OrganisationAccessError(BOOTSTRAP_REQUIRED_DETAIL, status_code=403)
    setup = db.get(DeploymentSetup, 1)
    if setup is None:
        setup = DeploymentSetup(id=1)
        db.add(setup)
        db.flush()
    if setup.bootstrap_consumed_at is not None:
        raise OrganisationAccessError(BOOTSTRAP_USED_DETAIL, status_code=409)
    setup.bootstrap_consumed_at = datetime.now(UTC)
    setup.bootstrap_token_hash = hash_bootstrap_token(provided)
    db.flush()


def is_replaceable_demo_organisation(db: Session, org: Organisation | None) -> bool:
    """Synthetic seed org may be converted into a real company registration."""
    if not synthetic_demo_actions_allowed():
        return False
    if org is None or not org.demo_verification_simulated:
        return False
    if (org.slug or "") != DEMO_ORG_SLUG:
        return False
    setup = db.get(DeploymentSetup, 1)
    if setup is not None and (setup.completed or setup.bootstrap_consumed_at is not None):
        return False
    return True


def registration_is_open(db: Session) -> bool:
    """True while /setup may still submit company registration."""
    if setup_is_completed(db):
        return False
    setup = db.get(DeploymentSetup, 1)
    if setup is not None and setup.bootstrap_consumed_at is not None:
        return False
    org = get_singleton_organisation(db)
    return org is None or is_replaceable_demo_organisation(db, org)


def bootstrap_required_for_setup(db: Session) -> bool:
    if not registration_is_open(db):
        return False
    setup = db.get(DeploymentSetup, 1)
    return setup is None or setup.bootstrap_consumed_at is None


def bump_token_version(user: User) -> None:
    user.token_version = int(user.token_version or 0) + 1


def is_org_admin_role(role: UserRole) -> bool:
    return role in ORG_ADMIN_ROLES


def validate_assignable_role(role: UserRole) -> UserRole:
    if role == UserRole.PLATFORM_ADMIN or role not in ASSIGNABLE_ROLES:
        raise OrganisationAccessError(PLATFORM_ADMIN_BLOCKED, status_code=403)
    return role


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return slug[:120] or "organisation"


def membership_to_public(membership: OrganisationMembership | None) -> dict | None:
    if membership is None:
        return None
    org = membership.organisation
    return {
        "organisation_id": membership.organisation_id,
        "organisation_name": org.name if org else None,
        "organisation_status": org.status.value if org else None,
        "overall_verification_status": (
            org.overall_verification_status.value if org and org.overall_verification_status else None
        ),
        "demo_verification_simulated": bool(org.demo_verification_simulated) if org else False,
        "role": membership.role.value,
        "status": membership.status.value,
    }


def _lock_setup(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": SETUP_LOCK_KEY})


def organisation_exists(db: Session) -> bool:
    return bool(db.scalar(select(func.count()).select_from(Organisation)) or 0)


def setup_is_required(db: Session) -> bool:
    """True when the deployment has no organisation row (empty first install)."""
    return not organisation_exists(db)


def setup_is_completed(db: Session) -> bool:
    """True only after verification activates the first admin and locks setup."""
    row = db.get(DeploymentSetup, 1)
    if row is not None and row.completed:
        return True
    org = get_singleton_organisation(db)
    if org is None or is_replaceable_demo_organisation(db, org):
        return False
    if org.slug == DEMO_ORG_SLUG and org.demo_verification_simulated:
        return False
    if org.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
        return False
    admin_count = db.scalar(
        select(func.count())
        .select_from(OrganisationMembership)
        .where(
            OrganisationMembership.organisation_id == org.id,
            OrganisationMembership.role.in_(tuple(ORG_ADMIN_ROLES)),
            OrganisationMembership.status == MembershipStatus.ACTIVE,
        )
    ) or 0
    return admin_count > 0


def verification_in_progress(db: Session) -> bool:
    if setup_is_completed(db):
        return False
    setup = db.get(DeploymentSetup, 1)
    if setup is not None and setup.bootstrap_consumed_at is not None:
        return True
    org = get_singleton_organisation(db)
    if org is None or is_replaceable_demo_organisation(db, org):
        return False
    return True


def get_singleton_organisation(db: Session) -> Organisation | None:
    return db.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))


def get_pending_membership(db: Session, user: User) -> OrganisationMembership | None:
    return db.scalar(
        select(OrganisationMembership)
        .where(
            OrganisationMembership.user_id == user.id,
            OrganisationMembership.status == MembershipStatus.PENDING,
        )
        .order_by(OrganisationMembership.id.asc())
        .limit(1)
    )


def get_active_membership(db: Session, user: User) -> OrganisationMembership | None:
    return db.scalar(
        select(OrganisationMembership)
        .where(
            OrganisationMembership.user_id == user.id,
            OrganisationMembership.status == MembershipStatus.ACTIVE,
        )
        .order_by(OrganisationMembership.id.asc())
        .limit(1)
    )


def require_active_membership(db: Session, user: User) -> OrganisationMembership:
    membership = get_active_membership(db, user)
    if membership is None:
        raise OrganisationAccessError(UNASSIGNED_DETAIL, status_code=403)
    org = membership.organisation or db.get(Organisation, membership.organisation_id)
    if org is None or org.status != OrganisationStatus.ACTIVE:
        raise OrganisationAccessError(ORG_SUSPENDED_DETAIL, status_code=403)
    if org.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
        raise OrganisationAccessError(ORG_UNVERIFIED_DETAIL, status_code=403)
    membership.organisation = org
    return membership


def require_pending_setup_actor(db: Session, user: User) -> tuple[Organisation, OrganisationMembership]:
    """Pending (or just-activated) organisation admin may access verification endpoints."""
    membership = get_pending_membership(db, user) or get_active_membership(db, user)
    if membership is None:
        raise OrganisationAccessError(UNASSIGNED_DETAIL, status_code=403)
    org = membership.organisation or db.get(Organisation, membership.organisation_id)
    if org is None:
        raise OrganisationAccessError(UNASSIGNED_DETAIL, status_code=403)
    if org.status == OrganisationStatus.SUSPENDED:
        raise OrganisationAccessError(ORG_SUSPENDED_DETAIL, status_code=403)
    if not is_org_admin_role(membership.role):
        raise OrganisationAccessError("Permission denied", status_code=403)
    membership.organisation = org
    return org, membership


def require_manage_users(db: Session, user: User) -> OrganisationMembership:
    from app.services import permission_service

    membership = require_active_membership(db, user)
    if not permission_service.role_has_permission(
        membership.role, permission_service.PERMISSION_USER_MANAGE
    ):
        raise OrganisationAccessError("Permission denied: user:manage", status_code=403)
    return membership


def reject_forged_organisation_id(requested: int | None, actual: int) -> None:
    if requested is not None and int(requested) != int(actual):
        raise OrganisationAccessError(
            "organisation_id is not valid for this session", status_code=403
        )


def count_active_org_admins(db: Session, organisation_id: int) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(OrganisationMembership)
            .where(
                OrganisationMembership.organisation_id == organisation_id,
                OrganisationMembership.status == MembershipStatus.ACTIVE,
                OrganisationMembership.role.in_(tuple(ORG_ADMIN_ROLES)),
            )
        )
        or 0
    )


def assert_not_last_org_admin(
    db: Session,
    *,
    organisation_id: int,
    target: OrganisationMembership,
    next_role: UserRole | None = None,
    next_status: MembershipStatus | None = None,
    next_user_active: bool | None = None,
) -> None:
    if not is_org_admin_role(target.role) or target.status != MembershipStatus.ACTIVE:
        return
    remaining_admin = is_org_admin_role(next_role) if next_role is not None else True
    remaining_status = next_status if next_status is not None else target.status
    remaining_user = True if next_user_active is None else next_user_active
    still_admin = (
        remaining_admin
        and remaining_status == MembershipStatus.ACTIVE
        and remaining_user
    )
    if still_admin:
        return
    if count_active_org_admins(db, organisation_id) <= 1:
        raise OrganisationAccessError(LAST_ADMIN_DETAIL, status_code=409)


def incident_visible_to_org(incident: Incident, organisation_id: int) -> bool:
    if incident.organisation_id is None:
        return True
    return incident.organisation_id == organisation_id


def assert_incident_visible(db: Session, user: User, incident_id: str) -> Incident:
    membership = require_active_membership(db, user)
    incident = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if incident is None or not incident_visible_to_org(incident, membership.organisation_id):
        raise OrganisationAccessError(f"Incident not found: {incident_id}", status_code=404)
    return incident


def filter_incidents_for_org(incidents: list[Incident], organisation_id: int) -> list[Incident]:
    return [row for row in incidents if incident_visible_to_org(row, organisation_id)]


def resolve_organisation_id(db: Session, user: User | None = None) -> int | None:
    if user is not None:
        membership = get_active_membership(db, user)
        if membership is not None:
            return membership.organisation_id
    org = db.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))
    return org.id if org else None


def ensure_demo_organisation(db: Session) -> Organisation:
    """Attach demo/test users to a synthetic org. Never a production onboarding path."""
    if not synthetic_demo_actions_allowed():
        raise OrganisationAccessError("Demo organisation seeding is disabled.")
    existing = db.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))
    if existing:
        setup = db.get(DeploymentSetup, 1)
        if setup is not None and (setup.completed or setup.bootstrap_consumed_at is not None):
            return existing
        if existing.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
            existing.overall_verification_status = OrganisationVerificationStatus.VERIFIED
            existing.legal_verification_status = OrganisationVerificationStatus.VERIFIED
            existing.domain_verification_status = OrganisationVerificationStatus.VERIFIED
            existing.admin_email_verification_status = OrganisationVerificationStatus.VERIFIED
            existing.pan_verification_status = OrganisationVerificationStatus.VERIFIED
            existing.demo_verification_simulated = True
            existing.verification_mode = existing.verification_mode or "demo"
            db.flush()
        return existing
    # ponytail: savepoint + short lock_timeout so another connection's uncommitted
    # deployment_slot=1 cannot hang the whole test transaction.
    try:
        with db.begin_nested():
            db.execute(text("SET LOCAL lock_timeout = '2s'"))
            org = Organisation(
                name=DEMO_ORG_NAME,
                slug=DEMO_ORG_SLUG,
                status=OrganisationStatus.ACTIVE,
                deployment_slot=1,
                approved_email_domains=[],
                overall_verification_status=OrganisationVerificationStatus.VERIFIED,
                legal_verification_status=OrganisationVerificationStatus.VERIFIED,
                pan_verification_status=OrganisationVerificationStatus.VERIFIED,
                domain_verification_status=OrganisationVerificationStatus.VERIFIED,
                admin_email_verification_status=OrganisationVerificationStatus.VERIFIED,
                verification_mode="demo",
                demo_verification_simulated=True,
                legal_verification_source="DEMO_SIMULATED",
            )
            db.add(org)
            db.flush()
            return org
    except Exception:
        existing = db.scalar(select(Organisation).order_by(Organisation.id.asc()).limit(1))
        if existing is not None:
            return existing
        raise


def ensure_membership(
    db: Session,
    *,
    user: User,
    organisation: Organisation,
    role: UserRole | None = None,
    status: MembershipStatus = MembershipStatus.ACTIVE,
    approved_by: int | None = None,
) -> OrganisationMembership:
    membership = db.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.organisation_id == organisation.id,
            OrganisationMembership.user_id == user.id,
        )
    )
    assigned_role = role or user.role
    now = datetime.now(UTC)
    if membership is None:
        membership = OrganisationMembership(
            organisation_id=organisation.id,
            user_id=user.id,
            role=assigned_role,
            status=status,
            approved_by=approved_by,
            approved_at=now if status == MembershipStatus.ACTIVE else None,
        )
        db.add(membership)
        db.flush()
        return membership
    membership.role = assigned_role
    membership.status = status
    if status == MembershipStatus.ACTIVE and membership.approved_at is None:
        membership.approved_by = approved_by
        membership.approved_at = now
    db.flush()
    return membership


def attach_demo_memberships(db: Session, users: list[User]) -> Organisation | None:
    if not users or not synthetic_demo_actions_allowed():
        return None
    org = ensure_demo_organisation(db)
    for user in users:
        ensure_membership(db, user=user, organisation=org, role=user.role)
    return org


def complete_setup(
    db: Session,
    *,
    organisation_name: str,
    admin_name: str,
    email: str,
    password: str,
    bootstrap_token: str | None = None,
    legal_name: str | None = None,
    registration_number: str | None = None,
    pan_number: str | None = None,
    registered_address: str | None = None,
    website_domain: str | None = None,
) -> tuple[Organisation, User, OrganisationMembership]:
    """Register company + pending first admin. Does not grant operational access."""
    from app.services import organisation_domain_verification_service as domain_service

    _lock_setup(db)
    if setup_is_completed(db):
        raise SetupAlreadyCompletedError()
    existing = get_singleton_organisation(db)
    if existing is not None and not is_replaceable_demo_organisation(db, existing):
        raise SetupAlreadyCompletedError()
    require_and_consume_bootstrap(db, bootstrap_token)

    mode = resolve_company_verification_mode()
    slug = slugify(organisation_name)
    legal = (legal_name or organisation_name).strip()
    reg = (registration_number or "").strip() or None
    pan = (pan_number or "").strip() or None
    address = (registered_address or "").strip() or None
    website = None
    domain_status = OrganisationVerificationStatus.UNVERIFIED
    if website_domain:
        try:
            website = domain_service.normalise_domain(website_domain)
            domain_status = OrganisationVerificationStatus.PENDING_VERIFICATION
        except domain_service.DomainVerificationError as exc:
            raise OrganisationAccessError(str(exc), status_code=exc.status_code) from exc

    if existing is not None:
        org = existing
        prior = db.scalars(
            select(OrganisationMembership).where(OrganisationMembership.organisation_id == org.id)
        ).all()
        for row in prior:
            row.status = MembershipStatus.REVOKED
        org.name = organisation_name.strip()
        org.slug = slug
        org.status = OrganisationStatus.ACTIVE
        org.approved_email_domains = []
        org.legal_name = legal
        org.registration_number = reg
        org.pan_number = pan
        org.registered_address = address
        org.website_domain = website
        org.overall_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
        org.legal_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
        org.pan_verification_status = OrganisationVerificationStatus.UNVERIFIED
        org.domain_verification_status = domain_status
        org.admin_email_verification_status = OrganisationVerificationStatus.UNVERIFIED
        org.verification_mode = mode
        org.demo_verification_simulated = mode == "demo"
        org.legal_verification_source = None
        org.legal_verification_method = None
        org.legal_verification_reference = None
        org.pan_verification_method = None
        org.pan_verification_reference = None
        org.overall_verification_method = None
        org.verified_at = None
        org.verified_by = None
        org.verification_notes_safe = None
        db.flush()
    else:
        org = Organisation(
            name=organisation_name.strip(),
            slug=slug,
            status=OrganisationStatus.ACTIVE,
            deployment_slot=1,
            approved_email_domains=[],
            legal_name=legal,
            registration_number=reg,
            pan_number=pan,
            registered_address=address,
            website_domain=website,
            overall_verification_status=OrganisationVerificationStatus.PENDING_VERIFICATION,
            legal_verification_status=OrganisationVerificationStatus.PENDING_VERIFICATION,
            pan_verification_status=OrganisationVerificationStatus.UNVERIFIED,
            domain_verification_status=domain_status,
            admin_email_verification_status=OrganisationVerificationStatus.UNVERIFIED,
            verification_mode=mode,
            demo_verification_simulated=(mode == "demo"),
        )
        db.add(org)
        try:
            db.flush()
        except IntegrityError as err:
            raise SetupAlreadyCompletedError() from err

    user = user_service.create_user(
        db,
        name=admin_name.strip(),
        email=email,
        role=UserRole.ORGANISATION_ADMIN,
        password=password,
    )
    user.admin_email_verified = False
    membership = OrganisationMembership(
        organisation_id=org.id,
        user_id=user.id,
        role=UserRole.ORGANISATION_ADMIN,
        status=MembershipStatus.PENDING,
        approved_by=None,
        approved_at=None,
    )
    db.add(membership)
    # Link setup row but do not mark completed until verification activates.
    setup = db.get(DeploymentSetup, 1)
    if setup is None:
        setup = DeploymentSetup(id=1)
        db.add(setup)
    setup.completed = False
    setup.organisation_id = org.id
    try:
        db.flush()
    except IntegrityError as err:
        raise SetupAlreadyCompletedError() from err
    return org, user, membership


def domain_warning(organisation: Organisation, email: str) -> str | None:
    domains = organisation.approved_email_domains or []
    if not domains:
        return None
    domain = (email or "").rsplit("@", 1)[-1].lower()
    allowed = {str(item).strip().lower().lstrip("@") for item in domains if str(item).strip()}
    if domain not in allowed:
        return f"Email domain {domain} is not in the organisation's approved domain list."
    return None


def create_invitation(
    db: Session,
    *,
    actor: User,
    email: str,
    role: UserRole,
    organisation_id: int | None = None,
) -> tuple[OrganisationInvitation, str]:
    membership = require_manage_users(db, actor)
    reject_forged_organisation_id(organisation_id, membership.organisation_id)
    org = membership.organisation
    if org.status != OrganisationStatus.ACTIVE:
        raise OrganisationAccessError(ORG_SUSPENDED_DETAIL, status_code=403)
    if org.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
        raise OrganisationAccessError(UNVERIFIED_INVITE_DETAIL, status_code=403)
    assigned = validate_assignable_role(role)
    normalised = user_service.normalise_email(email)
    now = datetime.now(UTC)
    prior = db.scalars(
        select(OrganisationInvitation).where(
            OrganisationInvitation.organisation_id == org.id,
            OrganisationInvitation.email == normalised,
            OrganisationInvitation.status == InvitationStatus.PENDING,
        )
    ).all()
    for row in prior:
        row.status = InvitationStatus.REVOKED
        row.revoked_at = now
    if prior:
        db.flush()
    raw = secrets.token_urlsafe(32)
    invitation = OrganisationInvitation(
        organisation_id=org.id,
        email=normalised,
        role=assigned,
        token_hash=hash_invitation_token(raw),
        invited_by=actor.id,
        expires_at=datetime.now(UTC) + INVITE_TTL,
        status=InvitationStatus.PENDING,
    )
    db.add(invitation)
    try:
        db.flush()
    except IntegrityError as extra:
        raise OrganisationAccessError(
            "A pending invitation already exists for this email.", status_code=409
        ) from extra
    return invitation, raw


def preview_invitation(db: Session, token: str) -> OrganisationInvitation:
    invitation = _load_invitation_for_token(db, token, for_update=False)
    _assert_invitation_usable(invitation)
    return invitation


def _load_invitation_for_token(
    db: Session, token: str, *, for_update: bool
) -> OrganisationInvitation:
    stmt = select(OrganisationInvitation).where(
        OrganisationInvitation.token_hash == hash_invitation_token(token)
    )
    if for_update:
        stmt = stmt.with_for_update()
    invitation = db.scalar(stmt)
    if invitation is None:
        raise OrganisationAccessError("Invitation is invalid.", status_code=400)
    return invitation


def _assert_invitation_usable(invitation: OrganisationInvitation) -> None:
    now = datetime.now(UTC)
    expires = invitation.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if invitation.status == InvitationStatus.REVOKED or invitation.revoked_at is not None:
        raise OrganisationAccessError("Invitation has been revoked.", status_code=400)
    if invitation.status == InvitationStatus.ACCEPTED or invitation.accepted_at is not None:
        raise OrganisationAccessError("Invitation has already been used.", status_code=409)
    if invitation.status == InvitationStatus.EXPIRED or expires <= now:
        invitation.status = InvitationStatus.EXPIRED
        raise OrganisationAccessError("Invitation has expired.", status_code=400)
    if invitation.status != InvitationStatus.PENDING:
        raise OrganisationAccessError("Invitation is not pending.", status_code=400)
    org = invitation.organisation
    if org is None or org.status != OrganisationStatus.ACTIVE:
        raise OrganisationAccessError(ORG_SUSPENDED_DETAIL, status_code=403)
    if org.overall_verification_status != OrganisationVerificationStatus.VERIFIED:
        raise OrganisationAccessError(UNVERIFIED_INVITE_DETAIL, status_code=403)
    validate_assignable_role(invitation.role)


def accept_invitation(
    db: Session,
    *,
    token: str,
    full_name: str,
    email: str,
    password: str,
) -> tuple[User, OrganisationMembership, OrganisationInvitation]:
    invitation = _load_invitation_for_token(db, token, for_update=True)
    _assert_invitation_usable(invitation)
    normalised = user_service.normalise_email(email)
    if normalised != invitation.email:
        raise OrganisationAccessError("Invitation email does not match.", status_code=400)

    existing = db.scalar(select(User).where(User.email == normalised))
    if existing is not None:
        if not existing.password_hash or not password_service.verify_password(
            password, existing.password_hash
        ):
            raise OrganisationAccessError(
                "An account with this email already exists. Sign in with the invited email to continue.",
                status_code=409,
            )
        user = existing
        if full_name.strip() and user.name != full_name.strip():
            user.name = full_name.strip()
    else:
        user = user_service.create_user(
            db,
            name=full_name.strip(),
            email=normalised,
            role=invitation.role,
            password=password,
        )

    conflict = db.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.organisation_id == invitation.organisation_id,
            OrganisationMembership.user_id == user.id,
            OrganisationMembership.status == MembershipStatus.ACTIVE,
        )
    )
    if conflict is not None and conflict.role != invitation.role:
        raise OrganisationAccessError("User is already a member of this organisation.", status_code=409)

    membership = ensure_membership(
        db,
        user=user,
        organisation=invitation.organisation,
        role=invitation.role,
        status=MembershipStatus.ACTIVE,
        approved_by=invitation.invited_by,
    )
    user.role = invitation.role
    user.is_active = True
    invitation.status = InvitationStatus.ACCEPTED
    invitation.accepted_at = datetime.now(UTC)
    db.flush()
    return user, membership, invitation


def revoke_invitation(db: Session, *, actor: User, invitation_id: int) -> OrganisationInvitation:
    membership = require_manage_users(db, actor)
    invitation = db.get(OrganisationInvitation, invitation_id)
    if invitation is None or invitation.organisation_id != membership.organisation_id:
        raise OrganisationAccessError("Invitation not found.", status_code=404)
    if invitation.status != InvitationStatus.PENDING:
        raise OrganisationAccessError("Invitation is not pending.", status_code=409)
    invitation.status = InvitationStatus.REVOKED
    invitation.revoked_at = datetime.now(UTC)
    db.flush()
    return invitation


def list_org_users(db: Session, actor: User) -> list[tuple[User, OrganisationMembership | None]]:
    membership = require_manage_users(db, actor)
    org_id = membership.organisation_id
    members = list(
        db.scalars(
            select(OrganisationMembership).where(OrganisationMembership.organisation_id == org_id)
        ).all()
    )
    member_ids = {item.user_id for item in members}
    by_user = {item.user_id: item for item in members}
    users = list(db.scalars(select(User).order_by(User.id)).all())
    rows: list[tuple[User, OrganisationMembership | None]] = []
    for user in users:
        if user.role == UserRole.PLATFORM_ADMIN:
            continue
        item = by_user.get(user.id)
        if item is not None:
            rows.append((user, item))
        elif user.id not in member_ids:
            rows.append((user, None))
    return rows


def assign_unassigned_user(
    db: Session,
    *,
    actor: User,
    user_id: int,
    role: UserRole,
    organisation_id: int | None = None,
) -> OrganisationMembership:
    membership = require_manage_users(db, actor)
    reject_forged_organisation_id(organisation_id, membership.organisation_id)
    assigned = validate_assignable_role(role)
    target = db.get(User, user_id)
    if target is None:
        raise OrganisationAccessError("User not found.", status_code=404)
    created = ensure_membership(
        db,
        user=target,
        organisation=membership.organisation,
        role=assigned,
        status=MembershipStatus.ACTIVE,
        approved_by=actor.id,
    )
    target.role = assigned
    bump_token_version(target)
    db.flush()
    return created


def change_membership_role(
    db: Session,
    *,
    actor: User,
    user_id: int,
    new_role: UserRole,
    reason: str | None = None,
) -> tuple[OrganisationMembership, UserRole]:
    del reason
    actor_membership = require_manage_users(db, actor)
    assigned = validate_assignable_role(new_role)
    target_membership = db.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.organisation_id == actor_membership.organisation_id,
            OrganisationMembership.user_id == user_id,
        )
    )
    if target_membership is None:
        raise OrganisationAccessError("User is not a member of this organisation.", status_code=404)
    assert_not_last_org_admin(
        db,
        organisation_id=actor_membership.organisation_id,
        target=target_membership,
        next_role=assigned,
    )
    if actor.id == user_id and assigned != target_membership.role:
        raise OrganisationAccessError("Users cannot change their own role", status_code=403)
    old_role = target_membership.role
    target_membership.role = assigned
    target = db.get(User, user_id)
    if target is not None:
        target.role = assigned
        bump_token_version(target)
    db.flush()
    return target_membership, old_role


def set_membership_status(
    db: Session,
    *,
    actor: User,
    user_id: int,
    status: MembershipStatus,
) -> OrganisationMembership:
    actor_membership = require_manage_users(db, actor)
    target_membership = db.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.organisation_id == actor_membership.organisation_id,
            OrganisationMembership.user_id == user_id,
        )
    )
    if target_membership is None:
        raise OrganisationAccessError("User is not a member of this organisation.", status_code=404)
    if status in {MembershipStatus.SUSPENDED, MembershipStatus.REVOKED}:
        assert_not_last_org_admin(
            db,
            organisation_id=actor_membership.organisation_id,
            target=target_membership,
            next_status=status,
        )
    target_membership.status = status
    target = db.get(User, user_id)
    if target is not None:
        bump_token_version(target)
    db.flush()
    return target_membership


def set_user_active(
    db: Session,
    *,
    actor: User,
    user_id: int,
    is_active: bool,
) -> User:
    actor_membership = require_manage_users(db, actor)
    target_membership = db.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.organisation_id == actor_membership.organisation_id,
            OrganisationMembership.user_id == user_id,
        )
    )
    if target_membership is None:
        raise OrganisationAccessError("User is not a member of this organisation.", status_code=404)
    if not is_active:
        assert_not_last_org_admin(
            db,
            organisation_id=actor_membership.organisation_id,
            target=target_membership,
            next_user_active=False,
        )
    target = db.get(User, user_id)
    if target is None:
        raise OrganisationAccessError("User not found.", status_code=404)
    target.is_active = is_active
    bump_token_version(target)
    db.flush()
    return target


def invite_only_blocks_public_register() -> bool:
    settings = get_settings()
    return bool(getattr(settings, "invite_only_registration", False)) and not bool(
        getattr(settings, "self_registration_enabled", True)
    )


def suspend_organisation(
    db: Session,
    *,
    actor: User,
    reason: str,
) -> Organisation:
    """Platform Operator suspends the singleton organisation (blocks invites/ingest)."""
    if actor.role != UserRole.PLATFORM_ADMIN:
        raise OrganisationAccessError("Platform administrator required", status_code=403)
    org = get_singleton_organisation(db)
    if org is None:
        raise OrganisationAccessError("Organisation not found.", status_code=404)
    clean = (reason or "").strip()
    if len(clean) < 3:
        raise OrganisationAccessError("Suspension reason is required", status_code=400)
    org.status = OrganisationStatus.SUSPENDED
    org.overall_verification_status = OrganisationVerificationStatus.SUSPENDED
    org.verification_notes_safe = f"Suspended: {clean}"[:2000]
    for membership in db.scalars(
        select(OrganisationMembership).where(OrganisationMembership.organisation_id == org.id)
    ).all():
        user = db.get(User, membership.user_id)
        if user is not None:
            bump_token_version(user)
    db.flush()
    return org


def recover_organisation_admin(
    db: Session,
    *,
    actor: User,
    user_id: int,
    reason: str,
) -> OrganisationMembership:
    """Platform Operator restores an Organisation Admin when last-admin lockout occurs."""
    if actor.role != UserRole.PLATFORM_ADMIN:
        raise OrganisationAccessError("Platform administrator required", status_code=403)
    clean = (reason or "").strip()
    if len(clean) < 3:
        raise OrganisationAccessError("Recovery reason is required", status_code=400)
    org = get_singleton_organisation(db)
    if org is None:
        raise OrganisationAccessError("Organisation not found.", status_code=404)
    if org.status == OrganisationStatus.SUSPENDED:
        org.status = OrganisationStatus.ACTIVE
        if org.overall_verification_status == OrganisationVerificationStatus.SUSPENDED:
            org.overall_verification_status = OrganisationVerificationStatus.VERIFIED
    target = db.get(User, user_id)
    if target is None or target.role == UserRole.PLATFORM_ADMIN:
        raise OrganisationAccessError("User not found.", status_code=404)
    membership = db.scalar(
        select(OrganisationMembership).where(
            OrganisationMembership.organisation_id == org.id,
            OrganisationMembership.user_id == user_id,
        )
    )
    if membership is None:
        membership = OrganisationMembership(
            organisation_id=org.id,
            user_id=user_id,
            role=UserRole.ORGANISATION_ADMIN,
            status=MembershipStatus.ACTIVE,
            approved_by=actor.id,
            approved_at=datetime.now(UTC),
        )
        db.add(membership)
    else:
        membership.role = UserRole.ORGANISATION_ADMIN
        membership.status = MembershipStatus.ACTIVE
        membership.approved_by = actor.id
        membership.approved_at = datetime.now(UTC)
    target.role = UserRole.ORGANISATION_ADMIN
    target.is_active = True
    bump_token_version(target)
    org.verification_notes_safe = f"Admin recovered: {clean}"[:2000]
    db.flush()
    return membership
