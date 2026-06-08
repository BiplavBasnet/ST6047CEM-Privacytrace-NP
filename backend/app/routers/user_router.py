from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import get_current_user, require_permission
from app.models.enums import MembershipStatus, UserRole
from app.models.user import User
from app.schemas.organisation_schema import (
    AssignMembershipRequest,
    InvitationCreateRequest,
    InvitationCreatedResponse,
    InvitationRead,
    MembershipStatusRequest,
    RoleChangeRequest,
)
from app.schemas.user_schema import UserCreate, UserListResponse, UserRead, UserUpdate
from app.services import audit_service, organisation_access_service as org_access, permission_service, user_service

router = APIRouter(prefix="/users", tags=["users"])


def _raise_org(error: org_access.OrganisationAccessError) -> None:
    raise HTTPException(status_code=error.status_code, detail=str(error)) from error


def _user_read(user: User, membership) -> UserRead:
    data = UserRead.model_validate(user)
    if membership is None:
        data.membership_status = "pending_unassigned"
        data.membership_role = None
        data.organisation_id = None
        return data
    data.membership_status = membership.status.value
    data.membership_role = membership.role
    data.organisation_id = membership.organisation_id
    return data


@router.get("", response_model=UserListResponse)
def list_users(
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
    organisation_id: int | None = Query(default=None),
):
    try:
        membership = org_access.require_manage_users(db, current_user)
        org_access.reject_forged_organisation_id(organisation_id, membership.organisation_id)
        rows = org_access.list_org_users(db, current_user)
    except org_access.OrganisationAccessError as extra:
        _raise_org(extra)
    items = [_user_read(user, member) for user, member in rows]
    return UserListResponse(users=items, total=len(items))


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        actor_membership = org_access.require_manage_users(db, current_user)
        org_access.validate_assignable_role(body.role)
        user = user_service.create_user(
            db,
            name=body.name,
            email=body.email,
            role=body.role,
            password=body.password,
        )
        membership = org_access.ensure_membership(
            db,
            user=user,
            organisation=actor_membership.organisation,
            role=body.role,
            status=MembershipStatus.ACTIVE,
            approved_by=current_user.id,
        )
        audit_service.log_action(
            db,
            action=audit_service.ACTION_USER_CREATED,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="user",
            target_id=str(user.id),
            details={"email": user.email, "role": user.role.value},
            organisation_id=actor_membership.organisation_id,
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    except user_service.DuplicateEmailError as extra:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(extra)) from extra
    return _user_read(user, membership)


@router.post("/invitations", response_model=InvitationCreatedResponse, status_code=status.HTTP_201_CREATED)
def invite_user(
    body: InvitationCreateRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    from app.services import email_delivery_service

    try:
        invitation, raw = org_access.create_invitation(
            db,
            actor=current_user,
            email=body.email,
            role=body.role,
            organisation_id=body.organisation_id,
        )
        warning = org_access.domain_warning(invitation.organisation, invitation.email)
        audit_service.log_action(
            db,
            action="organisation_invitation_created",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="invitation",
            target_id=str(invitation.id),
            details={"email": invitation.email, "role": invitation.role.value},
            organisation_id=invitation.organisation_id,
        )
        invite_path = f"/signup?invite={raw}"
        link = email_delivery_service.build_frontend_link(invite_path)
        delivery = "none"
        if email_delivery_service.smtp_configured():
            try:
                email_delivery_service.send_email(
                    to_address=invitation.email,
                    subject="PrivacyTrace-NP invitation",
                    body_text=(
                        "You have been invited to PrivacyTrace-NP.\n\n"
                        f"Accept invitation:\n{link}\n"
                    ),
                )
                delivery = "smtp"
            except email_delivery_service.EmailDeliveryError:
                from app.config import synthetic_demo_actions_allowed

                if not synthetic_demo_actions_allowed():
                    raise
                delivery = "none"
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    except email_delivery_service.EmailDeliveryError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    from app.config import synthetic_demo_actions_allowed

    # Expose raw invite token only when mail was not delivered and env is synthetic.
    expose = delivery != "smtp" and synthetic_demo_actions_allowed()
    return InvitationCreatedResponse(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        status=invitation.status,
        expires_at=invitation.expires_at,
        invite_token=raw if expose else None,
        invite_path=invite_path if expose else None,
        domain_warning=warning,
        delivery="demo" if expose and delivery == "none" else delivery,
        demo_simulated=expose,
    )


@router.get("/invitations", response_model=list[InvitationRead])
def list_invitations(
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    from sqlalchemy import select
    from app.models.organisation import OrganisationInvitation

    try:
        membership = org_access.require_manage_users(db, current_user)
    except org_access.OrganisationAccessError as extra:
        _raise_org(extra)
    rows = list(
        db.scalars(
            select(OrganisationInvitation)
            .where(OrganisationInvitation.organisation_id == membership.organisation_id)
            .order_by(OrganisationInvitation.id.desc())
        ).all()
    )
    return [InvitationRead.model_validate(row) for row in rows]


@router.post("/invitations/{invitation_id}/revoke", response_model=InvitationRead)
def revoke_invitation(
    invitation_id: int,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        invitation = org_access.revoke_invitation(db, actor=current_user, invitation_id=invitation_id)
        audit_service.log_action(
            db,
            action="organisation_invitation_revoked",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="invitation",
            target_id=str(invitation.id),
            details={"email": invitation.email},
            organisation_id=invitation.organisation_id,
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    return InvitationRead.model_validate(invitation)


@router.patch("/{user_id}/role", response_model=UserRead)
def change_role(
    user_id: int,
    body: RoleChangeRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        actor_membership = org_access.require_manage_users(db, current_user)
        org_access.reject_forged_organisation_id(body.organisation_id, actor_membership.organisation_id)
        membership, old_role = org_access.change_membership_role(
            db,
            actor=current_user,
            user_id=user_id,
            new_role=body.role,
            reason=body.reason,
        )
        audit_service.log_action(
            db,
            action="organisation_role_changed",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="user",
            target_id=str(user_id),
            details={
                "old_role": old_role.value,
                "new_role": body.role.value,
                "reason": body.reason,
            },
            organisation_id=actor_membership.organisation_id,
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    target = db.get(User, user_id)
    return _user_read(target, membership)


@router.post("/{user_id}/assign-membership", response_model=UserRead)
def assign_membership(
    user_id: int,
    body: AssignMembershipRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        membership = org_access.assign_unassigned_user(
            db,
            actor=current_user,
            user_id=user_id,
            role=body.role,
            organisation_id=body.organisation_id,
        )
        audit_service.log_action(
            db,
            action="organisation_membership_assigned",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="user",
            target_id=str(user_id),
            details={"role": body.role.value},
            organisation_id=membership.organisation_id,
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    target = db.get(User, user_id)
    return _user_read(target, membership)


@router.patch("/{user_id}/membership", response_model=UserRead)
def update_membership_status(
    user_id: int,
    body: MembershipStatusRequest,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    try:
        actor_membership = org_access.require_manage_users(db, current_user)
        org_access.reject_forged_organisation_id(body.organisation_id, actor_membership.organisation_id)
        membership = org_access.set_membership_status(
            db, actor=current_user, user_id=user_id, status=body.status
        )
        audit_service.log_action(
            db,
            action=f"organisation_membership_{body.status.value}",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="user",
            target_id=str(user_id),
            details={"status": body.status.value},
            organisation_id=actor_membership.organisation_id,
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    target = db.get(User, user_id)
    return _user_read(target, membership)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    body: UserUpdate,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    if current_user.id == user_id and body.role is not None and body.role != current_user.role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Users cannot change their own role",
        )
    try:
        actor_membership = org_access.require_manage_users(db, current_user)
        target_membership = None
        if body.role is not None:
            target_membership, _old = org_access.change_membership_role(
                db, actor=current_user, user_id=user_id, new_role=body.role
            )
        if body.is_active is False:
            org_access.set_user_active(db, actor=current_user, user_id=user_id, is_active=False)
        user = user_service.update_user(
            db,
            user_id,
            name=body.name,
            email=body.email,
            role=None,
            is_active=body.is_active,
            password=body.password,
        )
        if target_membership is None:
            from sqlalchemy import select
            from app.models.organisation import OrganisationMembership

            target_membership = db.scalar(
                select(OrganisationMembership).where(
                    OrganisationMembership.organisation_id == actor_membership.organisation_id,
                    OrganisationMembership.user_id == user_id,
                )
            )
        audit_service.log_action(
            db,
            action=audit_service.ACTION_USER_UPDATED,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="user",
            target_id=str(user.id),
            details={"email": user.email, "role": user.role.value, "is_active": user.is_active},
            organisation_id=actor_membership.organisation_id,
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    except user_service.UserNotFoundError as extra:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(extra)) from extra
    except user_service.DuplicateEmailError as extra:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(extra)) from extra
    return _user_read(user, target_membership)


@router.patch("/{user_id}/deactivate", response_model=UserRead)
def deactivate_user(
    user_id: int,
    current_user: Annotated[User, Depends(require_permission(permission_service.PERMISSION_USER_MANAGE))],
    db: Session = Depends(get_db_session),
):
    if current_user.id == user_id:
        try:
            actor_membership = org_access.require_manage_users(db, current_user)
            from sqlalchemy import select as _select
            from app.models.organisation import OrganisationMembership as _Membership

            target_membership = db.scalar(
                _select(_Membership).where(
                    _Membership.organisation_id == actor_membership.organisation_id,
                    _Membership.user_id == user_id,
                )
            )
            if target_membership is not None:
                org_access.assert_not_last_org_admin(
                    db,
                    organisation_id=actor_membership.organisation_id,
                    target=target_membership,
                    next_user_active=False,
                )
        except org_access.OrganisationAccessError as extra:
            _raise_org(extra)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot deactivate your own account",
        )
    try:
        user = org_access.set_user_active(db, actor=current_user, user_id=user_id, is_active=False)
        audit_service.log_action(
            db,
            action=audit_service.ACTION_USER_DEACTIVATED,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
            target_type="user",
            target_id=str(user.id),
            details={"email": user.email},
        )
        db.commit()
    except org_access.OrganisationAccessError as extra:
        db.rollback()
        _raise_org(extra)
    except user_service.UserNotFoundError as extra:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(extra)) from extra
    from sqlalchemy import select
    from app.models.organisation import OrganisationMembership

    membership = db.scalar(select(OrganisationMembership).where(OrganisationMembership.user_id == user.id))
    return _user_read(user, membership)
