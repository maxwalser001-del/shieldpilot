"""JWT authentication for the ShieldPilot dashboard API.

Handles login, token creation, token validation, and password hashing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel

from sentinelai.core.config import AuthConfig


class TokenData(BaseModel):
    """Data embedded in the JWT token."""
    username: str
    email: Optional[str] = None
    role: str = "viewer"
    tenant_id: Optional[str] = None
    tier: str = "free"
    is_super_admin: bool = False
    email_verified: bool = False


class Token(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(
    data: TokenData,
    auth_config: AuthConfig,
    expires_delta: Optional[timedelta] = None,
) -> Token:
    """Create a JWT access token.

    Args:
        data: User data to encode in the token.
        auth_config: Auth configuration with secret key and algorithm.
        expires_delta: Custom expiration time. Defaults to config value.

    Returns:
        Token with access_token string and expiration info.
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=auth_config.access_token_expire_minutes)

    expire = datetime.utcnow() + expires_delta
    to_encode = {
        "sub": data.username,
        "email": data.email,
        "role": data.role,
        "tenant_id": data.tenant_id,
        "tier": data.tier,
        "is_super_admin": data.is_super_admin,
        "email_verified": data.email_verified,
        "exp": expire,
    }

    encoded_jwt = jwt.encode(
        to_encode,
        auth_config.secret_key,
        algorithm=auth_config.algorithm,
    )

    return Token(
        access_token=encoded_jwt,
        expires_in=int(expires_delta.total_seconds()),
    )


def decode_token(token: str, auth_config: AuthConfig) -> Optional[TokenData]:
    """Decode and validate a JWT token.

    Returns:
        TokenData if valid, None if invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            auth_config.secret_key,
            algorithms=[auth_config.algorithm],
        )
        username = payload.get("sub")
        if username is None:
            return None
        return TokenData(
            username=username,
            email=payload.get("email"),
            role=payload.get("role", "viewer"),
            tenant_id=payload.get("tenant_id"),
            tier=payload.get("tier", "free"),
            is_super_admin=payload.get("is_super_admin", False),
            email_verified=payload.get("email_verified", False),
        )
    except JWTError:
        return None
