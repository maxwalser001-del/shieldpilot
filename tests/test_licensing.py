"""Tests for the sentinelai.licensing package (E1-E7)."""

import time
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinelai.licensing.keys import (
    generate_keypair,
    generate_key,
    parse_key,
    format_key,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    VALID_TIERS,
)
from sentinelai.licensing.validator import (
    LicenseInfo,
    validate_key,
    TIER_FEATURES,
)
from sentinelai.licensing.storage import save_key, load_key, remove_key
from sentinelai.licensing import (
    get_current_license,
    invalidate_cache,
    set_public_key,
)


@pytest.fixture
def keypair():
    priv, pub = generate_keypair()
    return priv, pub


@pytest.fixture
def valid_expiry():
    return int(time.time()) + 3600


# ── E1: License Key Format ───────────────────────────────────


class TestKeyFormat:
    def test_key_starts_with_sp(self, keypair, valid_expiry):
        priv, _ = keypair
        key = generate_key("pro", "test@example.com", valid_expiry, priv)
        assert key.startswith("SP-")

    def test_key_has_dash_separated_groups(self, keypair, valid_expiry):
        priv, _ = keypair
        key = generate_key("pro", "test@example.com", valid_expiry, priv)
        parts = key.split("-")
        assert len(parts) >= 5  # SP + at least 4 groups
        assert parts[0] == "SP"

    def test_key_roundtrip(self, keypair, valid_expiry):
        priv, _ = keypair
        key = generate_key("pro", "test@example.com", valid_expiry, priv)
        jwt = parse_key(key)
        assert len(jwt.split(".")) == 3

    def test_invalid_tier_raises(self, keypair, valid_expiry):
        priv, _ = keypair
        with pytest.raises(ValueError, match="Invalid tier"):
            generate_key("gold", "test@example.com", valid_expiry, priv)

    def test_all_valid_tiers(self, keypair, valid_expiry):
        priv, pub = keypair
        for tier in VALID_TIERS:
            key = generate_key(tier, "t@t.com", valid_expiry, priv)
            info = validate_key(key, pub)
            assert info.is_valid, f"Tier {tier} should be valid"
            assert info.tier == tier


# ── E2: Ed25519 Key-Pair ─────────────────────────────────────


class TestKeypair:
    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        assert priv is not None
        assert pub is not None

    def test_serialize_roundtrip_private(self, keypair):
        priv, _ = keypair
        pem = serialize_private_key(priv)
        loaded = load_private_key(pem)
        # Verify loaded key can sign
        sig = loaded.sign(b"test")
        keypair[1].verify(sig, b"test")

    def test_serialize_roundtrip_public(self, keypair):
        _, pub = keypair
        pem = serialize_public_key(pub)
        loaded = load_public_key(pem)
        # Verify loaded key can verify a signature
        priv = keypair[0]
        sig = priv.sign(b"test")
        loaded.verify(sig, b"test")  # should not raise

    def test_signing_verification_separate(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("pro", "user@test.com", valid_expiry, priv)
        # Verify with public key only
        info = validate_key(key, pub)
        assert info.is_valid

    def test_wrong_public_key_rejects(self, keypair, valid_expiry):
        priv, _ = keypair
        _, other_pub = generate_keypair()
        key = generate_key("pro", "user@test.com", valid_expiry, priv)
        info = validate_key(key, other_pub)
        assert not info.is_valid
        assert "signature" in info.error.lower()


# ── E3: validate_key ─────────────────────────────────────────


class TestValidation:
    def test_valid_key(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("pro", "test@example.com", valid_expiry, priv)
        info = validate_key(key, pub)
        assert info.is_valid
        assert info.tier == "pro"
        assert info.email == "test@example.com"
        assert info.error is None

    def test_expired_key(self, keypair):
        priv, pub = keypair
        expired = int(time.time()) - 100
        key = generate_key("pro", "test@example.com", expired, priv)
        info = validate_key(key, pub)
        assert not info.is_valid
        assert "expired" in info.error.lower()

    def test_tampered_key(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("pro", "test@example.com", valid_expiry, priv)
        tampered = key[:-5] + "ZZZZZ"
        info = validate_key(tampered, pub)
        assert not info.is_valid

    def test_invalid_format(self, keypair):
        _, pub = keypair
        info = validate_key("NOT-A-KEY", pub)
        assert not info.is_valid
        assert info.error is not None

    def test_empty_key(self, keypair):
        _, pub = keypair
        info = validate_key("", pub)
        assert not info.is_valid


# ── E4: LicenseInfo Dataclass ────────────────────────────────


class TestLicenseInfo:
    def test_default_is_free_invalid(self):
        info = LicenseInfo()
        assert info.tier == "free"
        assert info.email == ""
        assert info.is_valid is False
        assert info.features == TIER_FEATURES["free"]

    def test_all_fields_populated(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("enterprise", "ent@co.com", valid_expiry, priv)
        info = validate_key(key, pub)
        assert info.tier == "enterprise"
        assert info.email == "ent@co.com"
        assert info.expires_at is not None
        assert info.is_valid is True
        assert isinstance(info.features, dict)
        assert info.error is None

    def test_features_match_tier(self, keypair, valid_expiry):
        priv, pub = keypair
        for tier in VALID_TIERS:
            key = generate_key(tier, "t@t.com", valid_expiry, priv)
            info = validate_key(key, pub)
            assert info.features == TIER_FEATURES[tier]


# ── E5: Feature Gating ───────────────────────────────────────


class TestFeatureGating:
    def test_free_no_export(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("free", "f@t.com", valid_expiry, priv)
        info = validate_key(key, pub)
        assert not info.is_feature_enabled("export")
        assert info.is_feature_enabled("history_24h")
        assert not info.is_feature_enabled("history_30d")

    def test_pro_has_export(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("pro", "p@t.com", valid_expiry, priv)
        info = validate_key(key, pub)
        assert info.is_feature_enabled("export")
        assert not info.is_feature_enabled("llm_analysis")  # LLM is Pro+ only
        assert info.is_feature_enabled("library_access")
        assert not info.is_feature_enabled("multi_user")

    def test_enterprise_all_features(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("enterprise", "e@t.com", valid_expiry, priv)
        info = validate_key(key, pub)
        assert info.is_feature_enabled("multi_user")
        assert info.is_feature_enabled("priority_support")
        assert info.is_feature_enabled("export")

    def test_invalid_license_no_features(self, keypair):
        priv, pub = keypair
        expired = int(time.time()) - 100
        key = generate_key("pro", "p@t.com", expired, priv)
        info = validate_key(key, pub)
        assert not info.is_feature_enabled("export")

    def test_unknown_feature_returns_false(self, keypair, valid_expiry):
        priv, pub = keypair
        key = generate_key("unlimited", "u@t.com", valid_expiry, priv)
        info = validate_key(key, pub)
        assert not info.is_feature_enabled("nonexistent_feature")


# ── E6: Storage ──────────────────────────────────────────────


class TestStorage:
    def test_save_and_load(self, keypair, valid_expiry, tmp_path):
        priv, _ = keypair
        key = generate_key("pro", "s@t.com", valid_expiry, priv)
        license_file = tmp_path / "license.key"

        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file), \
             patch("sentinelai.licensing.storage._SHIELDPILOT_DIR", tmp_path):
            save_key(key)
            loaded = load_key()
            assert loaded == key

    def test_load_nonexistent(self, tmp_path):
        license_file = tmp_path / "license.key"
        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file):
            assert load_key() is None

    def test_remove_key(self, keypair, valid_expiry, tmp_path):
        priv, _ = keypair
        key = generate_key("pro", "r@t.com", valid_expiry, priv)
        license_file = tmp_path / "license.key"

        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file), \
             patch("sentinelai.licensing.storage._SHIELDPILOT_DIR", tmp_path):
            save_key(key)
            assert remove_key() is True
            assert load_key() is None

    def test_remove_nonexistent(self, tmp_path):
        license_file = tmp_path / "license.key"
        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file):
            assert remove_key() is False


# ── E7: get_current_license (cached) ─────────────────────────


class TestGetCurrentLicense:
    def test_no_key_returns_invalid(self, tmp_path):
        license_file = tmp_path / "license.key"
        invalidate_cache()
        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file), \
             patch("sentinelai.licensing._EMBEDDED_PUBLIC_KEY_PEM", b"dummy"):
            info = get_current_license()
            assert not info.is_valid
        invalidate_cache()

    def test_valid_key_cached(self, keypair, valid_expiry, tmp_path):
        priv, pub = keypair
        key = generate_key("pro", "c@t.com", valid_expiry, priv)
        pub_pem = serialize_public_key(pub)
        license_file = tmp_path / "license.key"

        invalidate_cache()
        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file), \
             patch("sentinelai.licensing.storage._SHIELDPILOT_DIR", tmp_path), \
             patch("sentinelai.licensing._EMBEDDED_PUBLIC_KEY_PEM", pub_pem):
            save_key(key)
            info1 = get_current_license()
            info2 = get_current_license()
            assert info1.is_valid
            assert info1 is info2  # same cached object
        invalidate_cache()

    def test_invalidate_cache_reloads(self, keypair, valid_expiry, tmp_path):
        priv, pub = keypair
        pub_pem = serialize_public_key(pub)
        license_file = tmp_path / "license.key"

        invalidate_cache()
        with patch("sentinelai.licensing.storage._LICENSE_FILE", license_file), \
             patch("sentinelai.licensing.storage._SHIELDPILOT_DIR", tmp_path), \
             patch("sentinelai.licensing._EMBEDDED_PUBLIC_KEY_PEM", pub_pem):
            # First: no key
            info1 = get_current_license()
            assert not info1.is_valid

            # Save a key and invalidate
            key = generate_key("pro", "r@t.com", valid_expiry, priv)
            save_key(key)
            invalidate_cache()

            info2 = get_current_license()
            assert info2.is_valid
            assert info2.tier == "pro"
        invalidate_cache()
