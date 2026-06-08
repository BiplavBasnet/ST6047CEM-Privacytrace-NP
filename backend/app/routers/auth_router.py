from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies.auth_dependencies import get_current_user
from app.dependencies import get_db_session
from app.models.user import User
from app.schemas.auth_schema import (
    AuthUserRead,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    PasswordResetRequestResponse,
    RegisterRequest,
    RegisterResponse,
    RegistrationStatusResponse,
)
from app.schemas.organisation_schema import MembershipRead
from app.services import (
    audit_service,
    auth_service,
    organisation_access_service as org_access,
    password_reset_service,
)
router = APIRouter(prefix="/auth", tags=["auth"])


def _user_read(db: Session, user: User) -> AuthUserRead:
    membership = org_access.get_active_membership(db, user)
    public = org_access.membership_to_public(membership)
    return AuthUserRead(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        membership=MembershipRead(**public) if public else None,
    )


@router.get("/registration-status", response_model=RegistrationStatusResponse)
def registration_status():
    settings = get_settings()
    return RegistrationStatusResponse(
        enabled=bool(settings.self_registration_enabled) and not bool(settings.invite_only_registration),
        email_verification_required=bool(settings.email_verification_required),
        default_role=(settings.default_registration_role or "viewer").strip().lower(),
        invite_only=bool(settings.invite_only_registration),
    )


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db_session)):
    settings = get_settings()
    email_for_audit = auth_service.normalise_email(body.email)
    invite_token = (body.invite_token or "").strip() or None

    if not invite_token and not settings.self_registration_enabled:
        audit_service.log_action(
            db,
            action=audit_service.ACTION_REGISTRATION_DISABLED,
            target_type="user",
            details={"email": email_for_audit, "reason": "disabled"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-registration is currently unavailable.",
        )

    try:
        user = auth_service.register_user(
            db,
            full_name=body.full_name,
            email=body.email,
            password=body.password,
            invite_token=invite_token,
        )
        membership = org_access.get_active_membership(db, user)
        audit_service.log_action(
            db,
            action="invitation_accepted" if invite_token else audit_service.ACTION_REGISTRATION_SUCCEEDED,
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="user",
            target_id=str(user.id),
            details={"email": user.email, "role": user.role.value, "invited": bool(invite_token)},
            organisation_id=membership.organisation_id if membership else None,
        )
        db.commit()
    except auth_service.RegistrationDisabledError as extra:
        audit_service.log_action(
            db,
            action=audit_service.ACTION_REGISTRATION_DISABLED,
            target_type="user",
            details={"email": email_for_audit, "reason": "disabled"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(extra)) from extra
    except auth_service.RegistrationRejectedError as extra:
        audit_service.log_action(
            db,
            action=audit_service.ACTION_REGISTRATION_REJECTED,
            target_type="user",
            details={"email": email_for_audit, "reason": extra.reason},
        )
        db.commit()
        status_code = (
            status.HTTP_409_CONFLICT
            if extra.reason == "duplicate_email"
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=status_code, detail=str(extra)) from extra

    message = (
        "Invitation accepted. Sign in with your email and password."
        if invite_token
        else "Account created. Sign in with your email and password."
    )
    return RegisterResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        message=message,
    )


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db_session)):
    email_for_audit = auth_service.normalise_email(body.email)
    try:
        user = auth_service.authenticate_user(db, email=body.email, password=body.password)
        db.commit()
    except auth_service.InvalidCredentialsError:
        audit_service.log_action(
            db,
            action=audit_service.ACTION_LOGIN_FAILED,
            target_type="user",
            details={"email": email_for_audit},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        ) from None
    except auth_service.InactiveUserError as extra:
        audit_service.log_action(
            db,
            action=audit_service.ACTION_LOGIN_FAILED,
            target_type="user",
            details={"email": email_for_audit, "reason": "inactive"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(extra)) from extra

    token = auth_service.create_access_token(user=user)
    membership = org_access.get_active_membership(db, user)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_LOGIN_SUCCESS,
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role.value,
        target_type="user",
        target_id=str(user.id),
        organisation_id=membership.organisation_id if membership else None,
    )
    db.commit()
    return LoginResponse(
        access_token=token,
        token_type=auth_service.TOKEN_TYPE_BEARER,
        user=_user_read(db, user),
    )


@router.get("/me", response_model=AuthUserRead)
def auth_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return _user_read(db, current_user)


@router.patch("/me")
def reject_me_patch():
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Users cannot change their own role",
    )


@router.post("/logout", response_model=LogoutResponse)
def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    membership = org_access.get_active_membership(db, current_user)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_LOGOUT,
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
        target_type="user",
        target_id=str(current_user.id),
        organisation_id=membership.organisation_id if membership else None,
    )
    db.commit()
    return LogoutResponse()


@router.post("/password-reset/request", response_model=PasswordResetRequestResponse)
def request_password_reset(body: PasswordResetRequest, db: Session = Depends(get_db_session)):
    demo_token = password_reset_service.request_password_reset(db, body.email)
    audit_service.log_action(
        db,
        action="password_reset_requested",
        target_type="user",
        details={"email": auth_service.normalise_email(body.email)},
        organisation_id=None,
    )
    db.commit()
    expose = bool(demo_token)
    return PasswordResetRequestResponse(
        demo_reset_token=demo_token if expose else None,
        demo_simulated=expose,
    )


@router.post("/password-reset/confirm", response_model=LogoutResponse)
def confirm_password_reset(body: PasswordResetConfirmRequest, db: Session = Depends(get_db_session)):
    try:
        user = password_reset_service.consume_password_reset(
            db, token=body.token, new_password=body.password
        )
        audit_service.log_action(
            db,
            action="password_reset_completed",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=user.role.value,
            target_type="user",
            target_id=str(user.id),
        )
        db.commit()
    except password_reset_service.PasswordResetError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return LogoutResponse(message="Password updated. Sign in with your new password.")
