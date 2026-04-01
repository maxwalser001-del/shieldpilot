"""ShieldPilot License Key System.

Provides offline license validation using Ed25519 signatures.

Usage:
    from sentinelai.licensing import get_current_license

    license_info = get_current_license()
    if license_info.is_valid:
        print(f"Licensed: {license_info.tier} tier for {license_info.email}")
    if license_info.is_feature_enabled("export"):
        # allow export
        ...
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinelai.licensing.keys import load_public_key
from sentinelai.licensing.storage import load_key
from sentinelai.licensing.validator import LicenseInfo, validate_key

logger = logging.getLogger(__name__)

# ── Embedded Public Key ──────────────────────────────────────
# Replace this with the actual production public key.
# Generate a key pair with:
#   from sentinelai.licensing.keys import generate_keypair, serialize_public_key
#   priv, pub = generate_keypair()
#   print(serialize_public_key(pub).decode())

_EMBEDDED_PUBLIC_KEY_PEM: Optional[bytes] = None

# ── Cache ────────────────────────────────────────────────────

_cache_lock = threading.Lock()
_cached_license: Optional[LicenseInfo] = None


def set_public_key(pem: bytes) -> None:
    """Set the embedded public key for license validation.

    Call this once at application startup before any license checks.
    """
    global _EMBEDDED_PUBLIC_KEY_PEM
    _EMBEDDED_PUBLIC_KEY_PEM = pem
    invalidate_cache()


def get_current_license() -> LicenseInfo:
    """Get the current license info, loading from storage on first call.

    Returns a cached LicenseInfo after the first successful load.
    Thread-safe via lock.

    Returns:
        LicenseInfo with is_valid=True if a valid license exists,
        or a default free-tier LicenseInfo if no key or invalid.
    """
    global _cached_license

    with _cache_lock:
        if _cached_license is not None:
            return _cached_license

        license_info = _load_and_validate()
        _cached_license = license_info
        return license_info


def invalidate_cache() -> None:
    """Clear the cached license, forcing a reload on next access."""
    global _cached_license
    with _cache_lock:
        _cached_license = None


def _load_and_validate() -> LicenseInfo:
    """Load key from storage and validate it."""
    if _EMBEDDED_PUBLIC_KEY_PEM is None:
        logger.debug("No public key configured for license validation")
        return LicenseInfo(error="No public key configured")

    key_str = load_key()
    if key_str is None:
        logger.debug("No license key found in storage")
        return LicenseInfo(error="No license key found")

    try:
        public_key: Ed25519PublicKey = load_public_key(_EMBEDDED_PUBLIC_KEY_PEM)
    except (ValueError, Exception) as e:
        logger.error("Failed to load public key: %s", e)
        return LicenseInfo(error=f"Invalid public key: {e}")

    license_info = validate_key(key_str, public_key)

    if license_info.is_valid:
        logger.info(
            "License validated: tier=%s email=%s expires=%s",
            license_info.tier,
            license_info.email,
            license_info.expires_at,
        )
    else:
        logger.warning("License validation failed: %s", license_info.error)

    return license_info


# Public API
__all__ = [
    "get_current_license",
    "invalidate_cache",
    "set_public_key",
    "LicenseInfo",
    "validate_key",
]
