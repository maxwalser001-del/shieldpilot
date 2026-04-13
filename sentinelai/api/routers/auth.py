"""Authentication endpoints: login, register, password reset, OAuth, email verification, /me."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from sentinelai.api.auth import (
    Token,
    TokenData,
)
from sentinelai.api.deps import (
    _is_local_request,
    get_config,
    get_current_user,
    get_db_session,
)
from sentinelai.api.routers._shared import (
    _login_limiter,
    _password_reset_confirm_limiter,
    _password_reset_limiter,
    _rate_limit_logger,
    _registration_limiter,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.services.auth_service import AuthService

router = APIRouter()


# ── Request/Response models ───────────────────────────────────


class LoginRequest(BaseModel):
    username: str  # Can be username or email
    password: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    username: Optional[str] = None  # Defaults to email prefix
    tos_accepted: bool = False  # Must be True to register


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


# ── Auth mode (public, no auth required) ─────────────────────


@router.get(
    "/api/auth/mode",
    tags=["Authentication"],
    summary="Get authentication mode",
    description="Returns whether local-first mode is active (no login required on localhost).",
)
def auth_mode(request: Request, config: SentinelConfig = Depends(get_config)):
    local = _is_local_request(request)
    return {
        "local_first": config.auth.local_first and local,
        "is_local": local,
    }


# ── Auth endpoints ────────────────────────────────────────────


@router.post(
    "/api/auth/login",
    response_model=Token,
    tags=["Authentication"],
    summary="Authenticate user",
    description="Authenticate with email/username and password. Returns a JWT access token. Rate-limited to 5 attempts per minute per IP.",
    response_description="JWT access token",
)
def login(
    credentials: LoginRequest,
    http_request: Request,
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Authenticate and receive a JWT token."""
    # Rate limiting: 5 attempts per minute per IP
    client_ip = http_request.client.host if http_request.client else "unknown"
    if _login_limiter.is_blocked(client_ip):
        retry_after = _login_limiter.get_retry_after(client_ip)
        _rate_limit_logger.warning(f"Login rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Too many login attempts", "message": f"Try again in {retry_after} seconds."},
            headers={"Retry-After": str(retry_after)},
        )

    service = AuthService(session, config)
    return service.authenticate(credentials.username, credentials.password, client_ip)


@router.post(
    "/api/auth/register",
    response_model=Token,
    tags=["Authentication"],
    summary="Register new user",
    description="Create a new user account with email, password, and optional username. Sends a verification email. Rate-limited to 5 registrations per hour per IP.",
    response_description="JWT access token for the newly created account",
)
def register(
    request: RegisterRequest,
    http_request: Request,
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Register a new user with email and password."""
    # Rate limiting: 5 registrations per hour per IP
    client_ip = http_request.client.host if http_request.client else "unknown"
    if _registration_limiter.is_blocked(client_ip):
        retry_after = _registration_limiter.get_retry_after(client_ip)
        _rate_limit_logger.warning(f"Registration rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Too many registration attempts", "message": f"Try again in {retry_after // 60} minutes."},
            headers={"Retry-After": str(retry_after)},
        )

    service = AuthService(session, config)
    return service.register(
        email=request.email,
        password=request.password,
        username=request.username,
        tos_accepted=request.tos_accepted,
        client_ip=client_ip,
        user_agent=http_request.headers.get("user-agent", ""),
    )


@router.post(
    "/api/auth/password-reset/request",
    tags=["Authentication"],
    summary="Request password reset",
    description="Send a password reset email to the given address. Always returns success to prevent email enumeration. Rate-limited to 3 requests per hour per email.",
    response_description="Confirmation message (always succeeds to prevent email enumeration)",
)
def request_password_reset(
    request: PasswordResetRequest,
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Request a password reset email."""
    # Rate limiting: 3 requests per hour per email
    if _password_reset_limiter.is_blocked(request.email.lower()):
        retry_after = _password_reset_limiter.get_retry_after(request.email.lower())
        _rate_limit_logger.warning(f"Password reset rate limit exceeded for {request.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Too many reset requests", "message": f"Try again in {retry_after // 60} minutes."},
            headers={"Retry-After": str(retry_after)},
        )

    service = AuthService(session, config)
    return service.request_password_reset(request.email)


@router.post(
    "/api/auth/password-reset/confirm",
    tags=["Authentication"],
    summary="Confirm password reset",
    description="Reset the user's password using a one-time token received via email. The token expires after 1 hour.",
    response_description="Success message after password has been changed",
)
def confirm_password_reset(
    request: PasswordResetConfirm,
    http_request: Request,
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Reset password using token."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    if _password_reset_confirm_limiter.is_blocked(client_ip):
        retry_after = _password_reset_confirm_limiter.get_retry_after(client_ip)
        _rate_limit_logger.warning(f"Password reset confirm rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Too many reset attempts", "message": f"Try again in {retry_after // 60} minutes."},
            headers={"Retry-After": str(retry_after)},
        )
    _password_reset_confirm_limiter.record_attempt(client_ip)
    service = AuthService(session, config)
    return service.confirm_password_reset(request.token, request.new_password)


# ── Email Verification ────────────────────────────────────────


@router.get(
    "/api/auth/verify-email",
    tags=["Authentication"],
    summary="Verify email address",
    description="Verify a user's email address using the token from the verification email. Redirects to the login page with a status query parameter.",
    response_description="Redirects to login page with verification status",
)
def verify_email(
    token: str,
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Verify email address using token from verification email."""
    service = AuthService(session, config)
    redirect_url = service.verify_email(token)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.post(
    "/api/auth/verify-email/resend",
    tags=["Authentication"],
    summary="Resend verification email",
    description="Resend the email verification link to the authenticated user's email address. Requires a valid JWT.",
    response_description="Confirmation that the verification email was sent",
)
def resend_verification_email(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Resend email verification link."""
    service = AuthService(session, config)
    return service.resend_verification_email(user)


# ── Google OAuth endpoints ────────────────────────────────────


@router.get(
    "/api/auth/google",
    tags=["Authentication"],
    summary="Initiate Google OAuth flow",
    description="Generate a Google OAuth authorization URL with a CSRF state token. The frontend should redirect the user to this URL.",
    response_description="Google OAuth authorization URL and state token",
)
def google_auth_redirect(
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Get Google OAuth authorization URL."""
    service = AuthService(session, config)
    return service.get_google_auth_url()


@router.get(
    "/api/auth/google/callback",
    tags=["Authentication"],
    summary="Handle Google OAuth callback",
    description="Process the Google OAuth callback, exchange the authorization code for user info, and redirect to the login page with a JWT token.",
    response_description="Redirects to login page with JWT token",
)
def google_callback(
    code: str,
    state: str,
    http_request: Request,
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Handle Google OAuth callback."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    user_agent = http_request.headers.get("user-agent", "")

    service = AuthService(session, config)
    token = service.handle_google_callback(code, state, client_ip, user_agent)
    # Use URL fragment (#token=) instead of query param (?token=) so the JWT
    # is never sent to the server in subsequent requests, never logged by
    # reverse proxies, and never leaked via the Referer header.
    return RedirectResponse(
        url=f"/login#token={token.access_token}",
        status_code=302,
    )


@router.get(
    "/api/auth/me",
    tags=["Authentication"],
    summary="Get current user info",
    description="Return the profile data of the currently authenticated user, including username, email, role, tier, and verification status.",
    response_description="Authenticated user profile data",
)
def get_me(user: TokenData = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "tier": user.tier,
        "is_super_admin": user.is_super_admin,
        "email_verified": user.email_verified,
    }


@router.get(
    "/api/auth/validate",
    tags=["Authentication"],
    summary="Validate credentials",
    description="Validate a JWT Bearer token or X-API-Key. Returns 200 with user info if valid, 401 if invalid. Intended for SDK health-checks before making API calls.",
    response_description="Validation result with user info",
)
def validate_credentials(user: TokenData = Depends(get_current_user)):
    """Validate the current credentials (JWT or API key) and return user info.

    200 OK   → {"valid": true,  "user": {...}}
    401      → {"valid": false, "error": "..."} via HTTPException from get_current_user
    """
    return {
        "valid": True,
        "user": {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "tier": user.tier,
            "is_super_admin": user.is_super_admin,
            "email_verified": user.email_verified,
        },
    }
