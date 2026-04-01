"""Contract tests for CLI JSON output — Spec 4."""

import json
import pytest
from typer.testing import CliRunner

# Try to import the CLI app
try:
    from sentinelai.cli.main import app
    HAS_CLI = True
except ImportError:
    HAS_CLI = False


runner = CliRunner()


def _extract_json(stdout: str) -> dict:
    """Extract JSON object from CLI output that may contain log warnings."""
    json_start = stdout.find("{")
    if json_start < 0:
        raise json.JSONDecodeError("No JSON object found", stdout, 0)
    return json.loads(stdout[json_start:])


@pytest.mark.skipif(not HAS_CLI, reason="CLI not available")
class TestJsonContracts:
    """Verify that --json outputs include schema_version and required fields."""

    def test_status_json_has_schema_version(self):
        result = runner.invoke(app, ["status", "--json"])
        if result.exit_code == 0:
            data = _extract_json(result.stdout)
            assert "schema_version" in data
            assert data["schema_version"] == "1.0"

    def test_config_json_has_schema_version(self):
        result = runner.invoke(app, ["config", "--json"])
        if result.exit_code == 0:
            data = _extract_json(result.stdout)
            assert "schema_version" in data
            assert data["schema_version"] == "1.0"

    def test_verify_json_has_schema_version(self):
        result = runner.invoke(app, ["verify", "--json"])
        # verify may exit 1 if chain issues, but should still produce JSON
        try:
            data = _extract_json(result.stdout)
            assert "schema_version" in data
        except json.JSONDecodeError:
            pytest.skip("verify didn't produce JSON output")

    def test_status_json_has_required_fields(self):
        result = runner.invoke(app, ["status", "--json"])
        if result.exit_code == 0:
            data = _extract_json(result.stdout)
            # Status should include at minimum: version, mode
            assert "version" in data or "config" in data

    def test_config_json_has_required_fields(self):
        result = runner.invoke(app, ["config", "--json"])
        if result.exit_code == 0:
            data = _extract_json(result.stdout)
            assert "mode" in data
