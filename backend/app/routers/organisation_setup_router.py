"""Company registration + organisation verification endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import get_current_user
from app.models.enums import OrganisationVerificationStatus, UserRole
from app.models.user import User
from app.schemas.organisation_schema import (
    DomainChallengeRequest,
    DomainChallengeResponse,
    DomainVerifyRequest,
    EmailTokenConsumeRequest,
    EmailTokenIssueResponse,
    InvitationPreviewResponse,
    LegalVerificationRequest,
    ManualReviewDecisionRequest,
    ManualReviewRequest,
    OrganisationSuspendRequest,
    PanVerificationRequest,
    PlatformAdminRecoveryRequest,
    SetupOrganisationRequest,
    SetupOrganisationResponse,
    SetupStatusResponse,
    VerificationStatusResponse,
)
from app.services import (
    audit_service,
    company_registry_verification_service as registry_service,
    organisation_access_service as org_access,
    organisation_domain_verification_service as domain_service,
    organisation_email_verification_service as email_service,
    organisation_manual_review_service as manual_service,
    organisation_verification_policy_service as policy,
    pan_verification_service as pan_service,
)

router = APIRouter(tags=["setup", "organisation-verification"])


def _status_payload(db: Session, org) -> VerificationStatusResponse:
    payload = policy.verification_status_public(org)
    payload["setup_completed"] = org_access.setup_is_completed(db)
    return VerificationStatusResponse(**payload)


def _setup_actor(db: Session, user: User):
    try:
        return org_access.require_pending_setup_actor(db, user)
    except org_access.OrganisationAccessError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/setup/status", response_model=SetupStatusResponse)
def setup_status(db: Session = Depends(get_db_session)):
    completed = org_access.setup_is_completed(db)
    required = org_access.setup_is_required(db)
    return SetupStatusResponse(
        required=required,
        completed=completed,
        verification_pending=org_access.verification_in_progress(db),
        bootstrap_required=org_access.bootstrap_required_for_setup(db),
        registration_open=org_access.registration_is_open(db),
    )


@router.post(
    "/setup/organisation",
    response_model=SetupOrganisationResponse,
    status_code=status.HTTP_201_CREATED,
)
def setup_organisation(body: SetupOrganisationRequest, db: Session = Depends(get_db_session)):
    try:
        org, user, membership = org_access.complete_setup(
            db,
            organisation_name=body.organisation_name,
            admin_name=body.administrator_full_name,
            email=body.email,
            password=body.password,
            bootstrap_token=body.bootstrap_token,
            legal_name=body.legal_name,
            registration_number=body.registration_number,
            pan_number=body.pan_number,
            registered_address=body.registered_address,
            website_domain=body.website_domain,
        )
        audit_service.log_action(
            db,
            action="company_registration_submitted",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={
                "organisation_name": org.name,
                "overall_verification_status": org.overall_verification_status.value,
                "verification_mode": org.verification_mode,
                "demo_verification_simulated": org.demo_verification_simulated,
            },
            organisation_id=org.id,
        )
        db.commit()
    except org_access.SetupAlreadyCompletedError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except org_access.OrganisationAccessError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise

    return SetupOrganisationResponse(
        organisation_id=org.id,
        organisation_name=org.name,
        organisation_slug=org.slug,
        administrator_id=user.id,
        administrator_email=user.email,
        role=user.role,
        overall_verification_status=org.overall_verification_status.value,
        membership_status=membership.status.value,
    )


@router.get("/invitations/preview", response_model=InvitationPreviewResponse)
def invitation_preview(token: str = Query(min_length=8), db: Session = Depends(get_db_session)):
    try:
        invitation = org_access.preview_invitation(db, token)
    except org_access.OrganisationAccessError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    org = invitation.organisation
    return InvitationPreviewResponse(
        email=invitation.email,
        role=invitation.role,
        organisation_name=org.name if org else "",
        expires_at=invitation.expires_at,
    )


@router.get("/setup/verification/status", response_model=VerificationStatusResponse)
def verification_status(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    org, _membership = _setup_actor(db, user)
    return _status_payload(db, org)


@router.post("/setup/verification/legal", response_model=VerificationStatusResponse)
def verify_legal(
    body: LegalVerificationRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    org, _ = _setup_actor(db, user)
    legal_name = (body.legal_name or org.legal_name or org.name or "").strip()
    registration_number = (body.registration_number or org.registration_number or "").strip()
    if not legal_name or not registration_number:
        raise HTTPException(status_code=400, detail="legal_name and registration_number are required")
    try:
        result = registry_service.verify_company_registration(
            legal_name=legal_name,
            registration_number=registration_number,
            registry_name=body.registry_name,
            match_status=body.match_status,
            reference_safe=body.reference_safe,
        )
        audit_service.log_action(
            db,
            action="registry_check_attempted",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={
                "match_status": result.match_status,
                "verification_method": result.verification_method,
                "source": result.source,
            },
            organisation_id=org.id,
        )
        org.legal_name = legal_name
        org.registration_number = registration_number
        if org.overall_verification_status == OrganisationVerificationStatus.VERIFIED:
            policy.invalidate_identity_change(org, field="legal_name")
            policy.invalidate_identity_change(org, field="registration_number")
        org.legal_verification_source = result.source
        org.legal_verification_method = result.verification_method
        org.legal_verification_reference = result.reference_safe
        if result.match_status == registry_service.MatchStatus.MATCHED:
            org.legal_verification_status = OrganisationVerificationStatus.VERIFIED
            if result.verification_method == "DEMO_SIMULATED":
                org.demo_verification_simulated = True
        elif result.match_status == registry_service.MatchStatus.VERIFICATION_SERVICE_UNAVAILABLE:
            org.legal_verification_status = OrganisationVerificationStatus.MANUAL_REVIEW
            policy.route_to_manual_review(org, reason_safe="Registry service unavailable")
        else:
            org.legal_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
            policy.route_to_manual_review(org, reason_safe="Registry mismatch requiring clarification")
        audit_service.log_action(
            db,
            action="registry_verification_result",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={
                "match_status": result.match_status,
                "legal_verification_status": org.legal_verification_status.value,
                "demo_simulated": result.verification_method == "DEMO_SIMULATED",
            },
            organisation_id=org.id,
        )
        policy.recompute_and_maybe_activate(db, org, actor_id=user.id)
        db.commit()
        db.refresh(org)
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/setup/verification/pan", response_model=VerificationStatusResponse)
def verify_pan(
    body: PanVerificationRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    org, _ = _setup_actor(db, user)
    try:
        result = pan_service.verify_pan(
            pan=body.pan,
            match_status=body.match_status,
            reference_safe=body.reference_safe,
        )
        if (
            org.overall_verification_status == OrganisationVerificationStatus.VERIFIED
            and (org.pan_number or "").strip() != (result.pan or "").strip()
        ):
            policy.invalidate_identity_change(org, field="pan_number")
        org.pan_number = result.pan
        org.pan_verification_method = result.verification_method
        org.pan_verification_reference = result.reference_safe
        if result.match_status == pan_service.PanMatchStatus.MATCHED:
            org.pan_verification_status = OrganisationVerificationStatus.VERIFIED
        elif result.match_status == pan_service.PanMatchStatus.VERIFICATION_SERVICE_UNAVAILABLE:
            org.pan_verification_status = OrganisationVerificationStatus.MANUAL_REVIEW
            if pan_service.pan_verification_required():
                policy.route_to_manual_review(org, reason_safe="PAN check unavailable")
        else:
            org.pan_verification_status = OrganisationVerificationStatus.PENDING_VERIFICATION
            if pan_service.pan_verification_required():
                policy.route_to_manual_review(org, reason_safe="PAN verification unsuccessful / unavailable")
        audit_service.log_action(
            db,
            action="pan_verification_result",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={
                "match_status": result.match_status,
                "message_safe": result.message_safe,
                "pan_verification_required": pan_service.pan_verification_required(),
            },
            organisation_id=org.id,
        )
        policy.recompute_and_maybe_activate(db, org, actor_id=user.id)
        db.commit()
        db.refresh(org)
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/setup/verification/domain/challenge", response_model=DomainChallengeResponse)
def create_domain_challenge(
    body: DomainChallengeRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    org, _ = _setup_actor(db, user)
    try:
        if org.overall_verification_status == OrganisationVerificationStatus.VERIFIED:
            policy.invalidate_identity_change(org, field="website_domain")
        challenge, txt = domain_service.create_domain_challenge(db, org, domain=body.domain)
        audit_service.log_action(
            db,
            action="dns_challenge_created",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={"domain": challenge.domain, "expires_at": challenge.expires_at.isoformat()},
            organisation_id=org.id,
        )
        db.commit()
    except domain_service.DomainVerificationError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return DomainChallengeResponse(
        domain=challenge.domain,
        txt_record=txt,
        expires_at=challenge.expires_at,
        status=challenge.status.value,
    )


@router.post("/setup/verification/domain/verify", response_model=VerificationStatusResponse)
def verify_domain(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
    body: DomainVerifyRequest = Body(default=DomainVerifyRequest()),
):
    org, _ = _setup_actor(db, user)
    try:
        domain_service.verify_domain_challenge(db, org, presented_txt=body.txt_record)
        audit_service.log_action(
            db,
            action="domain_verified",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={"domain": org.website_domain},
            organisation_id=org.id,
        )
        policy.recompute_and_maybe_activate(db, org, actor_id=user.id)
        db.commit()
        db.refresh(org)
    except domain_service.DomainVerificationError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/setup/verification/email/issue", response_model=EmailTokenIssueResponse)
def issue_email_token(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    from app.services import email_delivery_service

    org, _ = _setup_actor(db, user)
    try:
        row, token = email_service.issue_email_verification(db, org, user)
        audit_service.log_action(
            db,
            action="admin_email_verification_issued",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="user",
            target_id=str(user.id),
            details={"email": user.email, "expires_at": row.expires_at.isoformat()},
            organisation_id=org.id,
        )
        link = email_delivery_service.build_frontend_link(f"/setup?email_token={token}")
        body_text = (
            "PrivacyTrace-NP organisation admin email verification\n\n"
            f"Open this one-time link:\n{link}\n"
        )
        delivery = "none"
        if email_delivery_service.smtp_configured():
            email_delivery_service.send_email(
                to_address=user.email,
                subject="Verify your PrivacyTrace-NP admin email",
                body_text=body_text,
            )
            delivery = "smtp"
        db.commit()
    except email_service.EmailVerificationError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except email_delivery_service.EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    expose = email_delivery_service.demo_token_exposure_allowed()
    return EmailTokenIssueResponse(
        email=user.email,
        expires_at=row.expires_at,
        verify_path=f"/setup?email_token={token}" if expose else None,
        verify_token=token if expose else None,
        delivery="demo" if expose and delivery == "none" else delivery,
        demo_simulated=expose,
    )


@router.post("/setup/verification/email/confirm", response_model=VerificationStatusResponse)
def confirm_email(
    body: EmailTokenConsumeRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    org, _ = _setup_actor(db, user)
    try:
        email_service.consume_email_verification(db, token=body.token, user=user)
        audit_service.log_action(
            db,
            action="email_verified",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="user",
            target_id=str(user.id),
            details={"email": user.email},
            organisation_id=org.id,
        )
        if policy.recompute_and_maybe_activate(db, org, actor_id=user.id) == OrganisationVerificationStatus.VERIFIED:
            audit_service.log_action(
                db,
                action="organisation_verified",
                actor_id=user.id,
                actor_email=user.email,
                actor_role=user.role.value,
                target_type="organisation",
                target_id=str(org.id),
                details={"overall_verification_status": "verified"},
                organisation_id=org.id,
            )
            audit_service.log_action(
                db,
                action="first_admin_activated",
                actor_id=user.id,
                actor_email=user.email,
                actor_role=user.role.value,
                target_type="organisation",
                target_id=str(org.id),
                details={},
                organisation_id=org.id,
            )
            audit_service.log_action(
                db,
                action="setup_completed",
                actor_id=user.id,
                actor_email=user.email,
                actor_role=user.role.value,
                target_type="organisation",
                target_id=str(org.id),
                details={},
                organisation_id=org.id,
            )
        db.commit()
        db.refresh(org)
    except email_service.EmailVerificationError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/setup/verification/manual-review", response_model=VerificationStatusResponse)
def request_manual_review(
    body: ManualReviewRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    org, _ = _setup_actor(db, user)
    try:
        manual_service.request_manual_review(db, org, reason=body.reason, requested_by=user.id)
        audit_service.log_action(
            db,
            action="manual_review_requested",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={"reason": body.reason[:255]},
            organisation_id=org.id,
        )
        db.commit()
        db.refresh(org)
    except manual_service.ManualReviewError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/setup/verification/manual-review/{review_id}/decide", response_model=VerificationStatusResponse)
def decide_manual_review(
    review_id: int,
    body: ManualReviewDecisionRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    if user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(status_code=403, detail="Platform administrator required")
    try:
        row = manual_service.decide_manual_review(
            db,
            review_id,
            reviewer=user,
            decision=body.decision,
            notes_safe=body.notes_safe,
        )
        org = org_access.get_singleton_organisation(db)
        audit_service.log_action(
            db,
            action="manual_verification_decided",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(row.organisation_id),
            details={"decision": body.decision, "review_id": review_id},
            organisation_id=row.organisation_id,
        )
        db.commit()
        if org is None:
            org = org_access.get_singleton_organisation(db)
        db.refresh(org)
    except manual_service.ManualReviewError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/organisation/suspend", response_model=VerificationStatusResponse)
def suspend_organisation(
    body: OrganisationSuspendRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    try:
        org = org_access.suspend_organisation(db, actor=user, reason=body.reason)
        audit_service.log_action(
            db,
            action="organisation_suspended",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="organisation",
            target_id=str(org.id),
            details={"reason": body.reason[:255]},
            organisation_id=org.id,
        )
        db.commit()
        db.refresh(org)
    except org_access.OrganisationAccessError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)


@router.post("/organisation/recover-admin", response_model=VerificationStatusResponse)
def recover_organisation_admin(
    body: PlatformAdminRecoveryRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    from app.models.organisation import Organisation

    try:
        membership = org_access.recover_organisation_admin(
            db, actor=user, user_id=body.user_id, reason=body.reason
        )
        org = db.get(Organisation, membership.organisation_id)
        audit_service.log_action(
            db,
            action="organisation_admin_recovered",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="user",
            target_id=str(body.user_id),
            details={"reason": body.reason[:255], "organisation_id": membership.organisation_id},
            organisation_id=membership.organisation_id,
        )
        db.commit()
        db.refresh(org)
    except org_access.OrganisationAccessError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return _status_payload(db, org)