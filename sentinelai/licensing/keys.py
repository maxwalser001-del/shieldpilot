"""License key generation and Ed25519 key management.

License keys use the format SP-XXXXXXXX-XXXXXXXX-XXXXXXXX-... where the
payload is a signed JWT (EdDSA / Ed25519) containing tier, email, and expiry.

Server-side: Ed25519 private key signs keys.
Client-side: Ed25519 public key verifies keys offline.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# Valid tiers (must match TIER_LIMITS in sentinelai.core.config)
VALID_TIERS = {"free", "pro", "pro_plus", "enterprise", "unlimited"}


# ── Base64url helpers (RFC 7515) ──────────────────────────────


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode with automatic padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── Ed25519 Key-Pair Management ──────────────────────────────


def generate_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 key pair for license signing."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def serialize_private_key(key: Ed25519PrivateKey) -> bytes:
    """Serialize Ed25519 private key to PEM format."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(key: Ed25519PublicKey) -> bytes:
    """Serialize Ed25519 public key to PEM format."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 private key")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    """Load Ed25519 public key from PEM bytes."""
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Expected Ed25519 public key")
    return key


# ── License Key Generation ───────────────────────────────────


def generate_key(
    tier: str,
    email: str,
    expiry: int,
    private_key: Ed25519PrivateKey,
) -> str:
    """Generate a signed license key.

    Args:
        tier: One of 'free', 'pro', 'enterprise', 'unlimited'.
        email: Licensed user's email address.
        expiry: Unix timestamp when the license expires.
        private_key: Ed25519 private key for signing.

    Returns:
        License key string in format SP-XXXXXXXX-XXXXXXXX-...
    """
    if tier not in VALID_TIERS:
        raise ValueError(f"Invalid tier: {tier!r}. Must be one of {VALID_TIERS}")

    # Build JWT-style token: header.payload.signature
    header = _b64url_encode(
        json.dumps({"alg": "EdDSA", "typ": "LIC"}, separators=(",", ":")).encode()
    )
    payload = _b64url_encode(
        json.dumps(
            {
                "tier": tier,
                "email": email,
                "exp": expiry,
                "iat": int(time.time()),
            },
            separators=(",", ":"),
        ).encode()
    )

    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)

    jwt_token = f"{header}.{payload}.{sig_b64}"
    return format_key(jwt_token)


# ── Key Format Helpers ───────────────────────────────────────


def format_key(jwt_token: str) -> str:
    """Format a JWT token as SP-XXXXXXXX-XXXXXXXX-... license key.

    Uses base32 encoding so the key only contains [A-Z2-7], which avoids
    conflicts with the dash group separator.
    """
    raw = jwt_token.encode("ascii")
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [b32[i : i + 8] for i in range(0, len(b32), 8)]
    return "SP-" + "-".join(groups)


def parse_key(key_str: str) -> str:
    """Parse SP-XXXXXXXX license key back to JWT token string.

    Raises:
        ValueError: If the key format is invalid.
    """
    key_str = key_str.strip()
    if not key_str.startswith("SP-"):
        raise ValueError("Invalid license key: must start with 'SP-'")
    body = key_str[3:]
    b32 = body.replace("-", "")

    # Restore base32 padding
    padding = (8 - len(b32) % 8) % 8
    b32 += "=" * padding

    try:
        raw = base64.b32decode(b32)
        jwt_token = raw.decode("ascii")
    except Exception as e:
        raise ValueError(f"Invalid license key: decode error ({e})") from e

    # Validate JWT structure (must have exactly 3 parts)
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid license key: corrupted token structure")

    return jwt_token
