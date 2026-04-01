"""User settings endpoints: profile, password change, username, API key, delete account."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_current_user,
    get_db_session,
    require_verified_email,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.services.user_service import UserService

router = APIRouter()


# ── Request models ────────────────────────────────────────────


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ChangeUsernameRequest(BaseModel):
    username: str


class DeleteAccountRequest(BaseModel):
    password: str


# ── User Settings ────────────────────────────────────────────


@router.get(
    "/api/settings",
    tags=["Settings"],
    summary="Get user settings",
    description="Return the authenticated user's profile including email, username, tier, subscription status, linked OAuth accounts, and API key presence.",
    response_description="User profile, subscription status, and linked accounts",
)
def get_settings(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Get user profile and settings."""
    service = UserService(session, config)
    return service.get_settings(user)


@router.post(
    "/api/settings/password",
    tags=["Settings"],
    summary="Change password",
    description="Change the authenticated user's password. Requires the current password for verification.",
    response_description="Confirmation that the password was updated",
)
def change_password(
    request: ChangePasswordRequest,
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Change user password."""
    service = UserService(session, None)
    return service.change_password(user, request.current_password, request.new_password)


@router.post(
    "/api/settings/username",
    tags=["Settings"],
    summary="Change display username",
    description="Update the display username shown in the sidebar and profile. Must be between 2 and 30 characters.",
    response_description="Confirmation with the new username",
)
def change_username(
    request: ChangeUsernameRequest,
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Change display username."""
    service = UserService(session, None)
    return service.change_username(user, request.username)


@router.delete(
    "/api/settings/account",
    tags=["Settings"],
    summary="Delete user account",
    description="Permanently delete the user account and all associated data including command logs, incidents, and scans. Requires password confirmation.",
    response_description="Confirmation that the account and associated data were deleted",
)
def delete_account(
    request: DeleteAccountRequest,
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Permanently delete user account and all associated data."""
    try:
        service = UserService(session, config)
        return service.delete_account(user, request.password)
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        raise HTTPException(status_code=500, detail={"error": "Failed to delete account"})


# ── API Key Management ────────────────────────────────────────


@router.post(
    "/api/settings/api-key",
    tags=["Settings"],
    summary="Generate API key",
    description="Generate a new API key for programmatic access. The plaintext key is returned once; only its SHA-256 hash is stored. Requires verified email.",
    response_description="The plaintext API key (shown only once)",
)
def generate_api_key(
    user: TokenData = Depends(require_verified_email),
    session: Session = Depends(get_db_session),
):
    """Generate a new API key. Returns the plaintext key once, stores SHA-256 hash."""
    service = UserService(session, None)
    return service.generate_api_key(user)


@router.delete(
    "/api/settings/api-key",
    tags=["Settings"],
    summary="Revoke API key",
    description="Revoke the current API key, immediately invalidating all programmatic access using that key.",
    response_description="Confirmation that the API key was revoked",
)
def revoke_api_key(
    user: TokenData = Depends(require_verified_email),
    session: Session = Depends(get_db_session),
):
    """Revoke the current API key."""
    service = UserService(session, None)
    return service.revoke_api_key(user)
