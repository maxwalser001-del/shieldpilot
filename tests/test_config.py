"""Tests for configuration loading and validation."""

from __future__ import annotations

import os
import tempfile

import pytest
import yaml

from sentinelai.core.config import SentinelConfig, load_config


class TestLoadConfig:
    """Test configuration loading from various sources."""

    def test_default_config(self):
        """Loading without any file returns valid defaults."""
        # Point to a non-existent path to force defaults
        config = load_config("/nonexistent/path/sentinel.yaml")
        assert config.mode == "enforce"
        assert config.risk_thresholds.block == 80
        assert config.risk_thresholds.warn == 40

    def test_load_from_yaml(self, tmp_path):
        """Loading from a YAML file picks up values."""
        config_data = {
            "sentinel": {
                "mode": "audit",
                "risk_thresholds": {"block": 90, "warn": 50},
                "llm": {"enabled": True, "model": "test-model"},
            }
        }
        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text(yaml.dump(config_data))

        config = load_config(str(config_file))
        assert config.mode == "audit"
        assert config.risk_thresholds.block == 90
        assert config.risk_thresholds.warn == 50
        assert config.llm.enabled is True

    def test_env_override_mode(self, monkeypatch):
        """Environment variables override YAML values."""
        monkeypatch.setenv("SENTINEL_MODE", "disabled")
        config = load_config("/nonexistent/sentinel.yaml")
        assert config.mode == "disabled"

    def test_env_override_llm(self, monkeypatch):
        """SENTINEL_LLM_ENABLED env var overrides config."""
        monkeypatch.setenv("SENTINEL_LLM_ENABLED", "true")
        config = load_config("/nonexistent/sentinel.yaml")
        assert config.llm.enabled is True

    def test_empty_yaml_file(self, tmp_path):
        """Empty YAML file uses defaults."""
        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text("")
        config = load_config(str(config_file))
        assert config.mode == "enforce"


class TestSentinelConfig:
    """Test SentinelConfig model validation."""

    def test_valid_config(self, test_config):
        """Test config fixture is valid."""
        assert test_config.mode == "enforce"
        assert len(test_config.whitelist.commands) > 0
        assert len(test_config.blacklist.commands) > 0

    def test_config_serialization(self, test_config):
        """Config can be serialized and deserialized."""
        data = test_config.model_dump()
        restored = SentinelConfig(**data)
        assert restored.mode == test_config.mode
        assert restored.risk_thresholds.block == test_config.risk_thresholds.block
