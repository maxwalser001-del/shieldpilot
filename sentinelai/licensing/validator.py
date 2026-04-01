"""Offline license key validation using Ed25519 public key.

Validates license keys without network access. The public key is embedded
in the client; only the server holds the private key.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinelai.licensing.keys import VALID_TIERS, _b64url_decode, parse_key


# ── Feature Mapping per Tier ─────────────────────────────────
# Mirrors TIER_LIMITS in sentinelai.core.config but as feature flags
# for offline license validation (no DB/config dependency).

TIER_FEATURES: Dict[str, Dict[str, bool]] = {
    "free": {
        "history_24h": True,
        "history_30d": False,
        "history_unlimited": False,
        "export": False,
        "llm_analysis": False,
        "api_access": False,
        "multi_user": False,
        "priority_support": False,
        "library_access": False,
    },
    "pro": {
        "history_24h": True,
        "history_30d": True,
        "history_unlimited": False,
        "export": True,
        "llm_analysis": False,
        "api_access": True,
        "multi_user": False,
        "priority_support": False,
        "library_access": True,
    },
    "pro_plus": {
        "history_24h": True,
        "history_30d": True,
        "history_unlimited": False,
        "export": True,
        "llm_analysis": True,
        "api_access": True,
        "multi_user": True,
        "priority_support": True,
        "library_access": True,
    },
    "enterprise": {
        "history_24h": True,
        "history_30d": True,
        "history_unlimited": True,
        "export": True,
        "llm_analysis": True,
        "api_access": True,
        "multi_user": True,
        "priority_support": True,
        "library_access": True,
    },
    "unlimited": {
        "history_24h": True,
        "history_30d": True,
        "history_unlimited": True,
        "export": True,
        "llm_analysis": True,
        "api_access": True,
        "multi_user": True,
        "priority_support": True,
        "library_access": True,
    },
}


# ── LicenseInfo Dataclass ───────────────────────────────────


@dataclass
class LicenseInfo:
    """Validated license information.

    Attributes:
        tier: License tier ('free', 'pro', 'enterprise', 'unlimited').
        email: Email address the license is bound to.
        expires_at: Expiration datetime (UTC).
        is_valid: Whether the license is valid (signature OK + not expired).
        features: Dict of feature_name -> enabled for this tier.
        error: Human-readable error message if validation failed.
    """

    tier: str = "free"
    email: str = ""
    expires_at: Optional[datetime] = None
    is_valid: bool = False
    features: Dict[str, bool] = field(default_factory=lambda: TIER_FEATURES["free"].copy())
    error: Optional[str] = None

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Check if a specific feature is enabled for this license tier.

        Args:
            feature_name: Feature to check (e.g. 'export', 'llm_analysis').

        Returns:
            True if the license is valid and the feature is enabled.
        """
        if not self.is_valid:
            return False
        return self.features.get(feature_name, False)


# ── Validation ───────────────────────────────────────────────


def validate_key(key_str: str, public_key: Ed25519PublicKey) -> LicenseInfo:
    """Validate a license key offline using the Ed25519 public key.

    Checks:
    1. Key format (SP-XXXX-...) is parseable
    2. Ed25519 signature is valid
    3. License has not expired
    4. Tier is recognized

    Args:
        key_str: License key in SP-XXXXXXXX-... format.
        public_key: Ed25519 public key for signature verification.

    Returns:
        LicenseInfo with is_valid=True on success, or is_valid=False with error.
    """
    # Step 1: Parse key format
    try:
        jwt_token = parse_key(key_str)
    except ValueError as e:
        return LicenseInfo(error=str(e))

    parts = jwt_token.split(".")
    if len(parts) != 3:
        return LicenseInfo(error="Invalid token structure")

    header_b64, payload_b64, sig_b64 = parts

    # Step 2: Verify Ed25519 signature
    try:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = _b64url_decode(sig_b64)
        public_key.verify(signature, signing_input)
    except (InvalidSignature, Exception) as e:
        return LicenseInfo(error=f"Invalid signature: {e}")

    # Step 3: Decode payload
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (json.JSONDecodeError, Exception) as e:
        return LicenseInfo(error=f"Invalid payload: {e}")

    tier = payload.get("tier", "")
    email = payload.get("email", "")
    exp = payload.get("exp")

    # Step 4: Validate tier
    if tier not in VALID_TIERS:
        return LicenseInfo(
            tier=tier,
            email=email,
            error=f"Unknown tier: {tier!r}",
        )

    # Step 5: Check expiry
    if exp is None:
        return LicenseInfo(
            tier=tier,
            email=email,
            error="Missing expiry timestamp",
        )

    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    now = time.time()

    if now > exp:
        return LicenseInfo(
            tier=tier,
            email=email,
            expires_at=expires_at,
            is_valid=False,
            features=TIER_FEATURES.get(tier, TIER_FEATURES["free"]).copy(),
            error="License has expired",
        )

    # All checks passed
    return LicenseInfo(
        tier=tier,
        email=email,
        expires_at=expires_at,
        is_valid=True,
        features=TIER_FEATURES.get(tier, TIER_FEATURES["free"]).copy(),
    )
