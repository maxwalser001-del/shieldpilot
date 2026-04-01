"""Google OAuth integration for ShieldPilot."""

from __future__ import annotations

from typing import Dict, Optional
from urllib.parse import urlencode

import httpx

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def get_google_auth_url(
    client_id: str,
    redirect_uri: str,
    state: str,
) -> str:
    """Generate Google OAuth authorization URL.

    Args:
        client_id: Google OAuth client ID.
        redirect_uri: URL to redirect to after authorization.
        state: CSRF state token for security.

    Returns:
        Full authorization URL to redirect user to.
    """
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> Dict:
    """Exchange authorization code for access token.

    Args:
        code: Authorization code from Google.
        client_id: Google OAuth client ID.
        client_secret: Google OAuth client secret.
        redirect_uri: Same redirect URI used in authorization.

    Returns:
        Token response containing access_token, refresh_token, etc.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        response.raise_for_status()
        return response.json()


def exchange_code_for_token_sync(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> Dict:
    """Synchronous version of exchange_code_for_token."""
    with httpx.Client() as client:
        response = client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        response.raise_for_status()
        return response.json()


async def get_google_user_info(access_token: str) -> Dict:
    """Get user info from Google.

    Args:
        access_token: Valid Google access token.

    Returns:
        User info containing id, email, name, picture, etc.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()


def get_google_user_info_sync(access_token: str) -> Dict:
    """Synchronous version of get_google_user_info."""
    with httpx.Client() as client:
        response = client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
        return response.json()
