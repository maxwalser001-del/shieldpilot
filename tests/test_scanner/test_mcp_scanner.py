"""Tests for the MCP Security Scanner.

Each test class covers one detection category.  Fixtures provide
MCP config dicts / JSON strings that contain known-bad patterns
so we can assert specific findings are produced (and clean configs
produce no findings).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from sentinelai.scanner.mcp_scanner import (
    MCPFindingCategory,
    MCPFindingSeverity,
    MCPScanner,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_json(servers: dict) -> str:
    return json.dumps({"mcpServers": servers}, indent=2)


def _write_config(tmp_path: Path, servers: dict, filename: str = "mcp.json") -> Path:
    p = tmp_path / filename
    p.write_text(_config_json(servers))
    return p


def _categories(result) -> set:
    return {f.category for f in result.findings}


def _severities(result) -> set:
    return {f.severity for f in result.findings}


# ---------------------------------------------------------------------------
# SSRF detection
# ---------------------------------------------------------------------------

class TestSSRFDetection:
    """SSRF: URL fields pointing to internal network addresses."""

    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_loopback_127(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "my-server": {"url": "http://127.0.0.1:8080/api"}
        })
        result = scanner.scan_file(path)
        ssrf = [f for f in result.findings if f.category == MCPFindingCategory.SSRF]
        assert ssrf, "Expected SSRF finding for 127.0.0.1"
        assert ssrf[0].server_name == "my-server"

    def test_localhost(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "srv": {"url": "http://localhost:3000"}
        })
        result = scanner.scan_file(path)
        ssrf = [f for f in result.findings if f.category == MCPFindingCategory.SSRF]
        assert ssrf, "Expected SSRF finding for localhost"

    def test_link_local_imds(self, scanner, tmp_path):
        """169.254.169.254 is the AWS IMDS endpoint — extremely dangerous."""
        path = _write_config(tmp_path, {
            "meta": {"url": "http://169.254.169.254/latest/meta-data/"}
        })
        result = scanner.scan_file(path)
        ssrf = [f for f in result.findings if f.category == MCPFindingCategory.SSRF]
        assert ssrf, "Expected SSRF finding for IMDS address"

    def test_rfc1918_10_block(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "internal": {"url": "http://10.0.0.5/service"}
        })
        result = scanner.scan_file(path)
        assert any(f.category == MCPFindingCategory.SSRF for f in result.findings)

    def test_rfc1918_192_168(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "intranet": {"url": "http://192.168.1.100/mcp"}
        })
        result = scanner.scan_file(path)
        assert any(f.category == MCPFindingCategory.SSRF for f in result.findings)

    def test_rfc1918_172_16(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "corp": {"url": "http://172.20.0.1/api"}
        })
        result = scanner.scan_file(path)
        assert any(f.category == MCPFindingCategory.SSRF for f in result.findings)

    def test_clean_external_url_no_ssrf(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "public": {
                "url": "https://api.example.com/mcp",
                "headers": {"Authorization": "Bearer mytoken"},
            }
        })
        result = scanner.scan_file(path)
        ssrf = [f for f in result.findings if f.category == MCPFindingCategory.SSRF]
        assert not ssrf, "Should not flag external public URLs"


# ---------------------------------------------------------------------------
# Missing auth detection
# ---------------------------------------------------------------------------

class TestMissingAuthDetection:
    """Remote servers without any authentication configuration."""

    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_remote_url_no_auth(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "remote": {"url": "https://api.example.com/mcp"}
        })
        result = scanner.scan_file(path)
        auth = [f for f in result.findings if f.category == MCPFindingCategory.MISSING_AUTH]
        assert auth, "Expected MISSING_AUTH for remote URL with no auth"
        assert auth[0].severity == MCPFindingSeverity.HIGH

    def test_remote_with_auth_header_ok(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "secured": {
                "url": "https://api.example.com/mcp",
                "headers": {"Authorization": "Bearer tok123"},
            }
        })
        result = scanner.scan_file(path)
        auth = [f for f in result.findings if f.category == MCPFindingCategory.MISSING_AUTH]
        assert not auth, "Should not flag server with Authorization header"

    def test_remote_with_api_key_ok(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "secured": {
                "url": "https://api.example.com/mcp",
                "headers": {"x-api-key": "my-key"},
            }
        })
        result = scanner.scan_file(path)
        auth = [f for f in result.findings if f.category == MCPFindingCategory.MISSING_AUTH]
        assert not auth

    def test_local_command_no_auth_expected(self, scanner, tmp_path):
        """stdio-based (command) servers don't need network auth."""
        path = _write_config(tmp_path, {
            "local": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}
        })
        result = scanner.scan_file(path)
        auth = [f for f in result.findings if f.category == MCPFindingCategory.MISSING_AUTH]
        # May have other findings but not MISSING_AUTH for a command-based server
        assert not auth, "Should not require auth on local command-based servers"


# ---------------------------------------------------------------------------
# Hardcoded secrets detection
# ---------------------------------------------------------------------------

class TestHardcodedSecrets:
    """Secrets embedded in env vars or command args."""

    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_aws_access_key_in_env(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "aws-tools": {
                "command": "npx",
                "args": ["-y", "mcp-server-aws"],
                "env": {
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                },
            }
        })
        result = scanner.scan_file(path)
        secrets = [f for f in result.findings if f.category == MCPFindingCategory.HARDCODED_SECRET]
        assert secrets, "Expected HARDCODED_SECRET for AWS key in env"
        assert any(f.severity == MCPFindingSeverity.CRITICAL for f in secrets)

    def test_openai_api_key_in_env(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "openai": {
                "command": "npx",
                "args": ["-y", "mcp-server-openai"],
                "env": {"OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"},
            }
        })
        result = scanner.scan_file(path)
        secrets = [f for f in result.findings if f.category == MCPFindingCategory.HARDCODED_SECRET]
        assert secrets, "Expected HARDCODED_SECRET for OpenAI key"

    def test_github_pat_in_env(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456ab"},
            }
        })
        result = scanner.scan_file(path)
        secrets = [f for f in result.findings if f.category == MCPFindingCategory.HARDCODED_SECRET]
        assert secrets, "Expected HARDCODED_SECRET for GitHub PAT"

    def test_clean_env_var_placeholder(self, scanner, tmp_path):
        """Placeholders like 'YOUR_API_KEY_HERE' should not trigger."""
        path = _write_config(tmp_path, {
            "safe": {
                "command": "npx",
                "args": ["-y", "some-server"],
                "env": {"API_KEY": "YOUR_API_KEY_HERE"},
            }
        })
        result = scanner.scan_file(path)
        secrets = [f for f in result.findings if f.category == MCPFindingCategory.HARDCODED_SECRET]
        assert not secrets, "Placeholder values should not be flagged"

    def test_secret_in_args(self, scanner, tmp_path):
        """Secrets passed directly as command args."""
        path = _write_config(tmp_path, {
            "inline": {
                "command": "node",
                "args": ["server.js", "--token", "sk-reallylongactualtoken1234567890abcdefghijk"],
            }
        })
        result = scanner.scan_file(path)
        secrets = [f for f in result.findings if f.category == MCPFindingCategory.HARDCODED_SECRET]
        assert secrets, "Expected HARDCODED_SECRET for secret in args"


# ---------------------------------------------------------------------------
# Over-privileged tool detection
# ---------------------------------------------------------------------------

class TestOverprivilegedTools:
    """MCP servers granting shell, exec, or filesystem write access."""

    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_shell_tool_critical(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "dangerous": {
                "command": "npx",
                "args": ["-y", "mcp-server-dangerous"],
                "tools": ["shell", "read_file"],
            }
        })
        result = scanner.scan_file(path)
        priv = [f for f in result.findings if f.category == MCPFindingCategory.OVERPRIVILEGED]
        assert priv
        shell_findings = [f for f in priv if "shell" in f.evidence.lower()]
        assert shell_findings
        assert shell_findings[0].severity == MCPFindingSeverity.CRITICAL

    def test_exec_tool_critical(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "execserver": {
                "command": "npx",
                "args": ["-y", "mcp-server-exec"],
                "tools": [{"name": "exec_command", "description": "Run arbitrary commands"}],
            }
        })
        result = scanner.scan_file(path)
        priv = [f for f in result.findings if f.category == MCPFindingCategory.OVERPRIVILEGED]
        assert priv

    def test_filesystem_write_high(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "fs-server": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                "tools": ["read_file", "write_file", "list_directory"],
            }
        })
        result = scanner.scan_file(path)
        priv = [f for f in result.findings if f.category == MCPFindingCategory.OVERPRIVILEGED]
        write_findings = [f for f in priv if "write" in f.evidence.lower()]
        assert write_findings
        assert write_findings[0].severity == MCPFindingSeverity.HIGH

    def test_bash_c_inline_critical(self, scanner, tmp_path):
        """bash -c '...' in command is a code-injection vector."""
        path = _write_config(tmp_path, {
            "shell-inline": {
                "command": "bash",
                "args": ["-c", "node /path/to/server.js"],
            }
        })
        result = scanner.scan_file(path)
        priv = [f for f in result.findings if f.category == MCPFindingCategory.OVERPRIVILEGED]
        assert priv
        assert any(f.severity == MCPFindingSeverity.CRITICAL for f in priv)

    def test_clean_readonly_tools_ok(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "readonly": {
                "command": "npx",
                "args": ["-y", "some-server"],
                "tools": ["read_file", "list_directory", "search"],
            }
        })
        result = scanner.scan_file(path)
        priv = [f for f in result.findings if f.category == MCPFindingCategory.OVERPRIVILEGED]
        assert not priv, "Read-only tools should not be flagged"


# ---------------------------------------------------------------------------
# Insecure transport detection
# ---------------------------------------------------------------------------

class TestInsecureTransport:
    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_http_external_flagged(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "http-server": {
                "url": "http://api.example.com/mcp",
                "headers": {"Authorization": "Bearer tok"},
            }
        })
        result = scanner.scan_file(path)
        transport = [f for f in result.findings if f.category == MCPFindingCategory.INSECURE_TRANSPORT]
        assert transport
        assert transport[0].severity == MCPFindingSeverity.MEDIUM

    def test_https_external_ok(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "https-server": {
                "url": "https://api.example.com/mcp",
                "headers": {"Authorization": "Bearer tok"},
            }
        })
        result = scanner.scan_file(path)
        transport = [f for f in result.findings if f.category == MCPFindingCategory.INSECURE_TRANSPORT]
        assert not transport

    def test_http_localhost_not_flagged(self, scanner, tmp_path):
        """HTTP on localhost is acceptable (already flagged as SSRF separately)."""
        path = _write_config(tmp_path, {
            "local": {"url": "http://localhost:3000"}
        })
        result = scanner.scan_file(path)
        transport = [f for f in result.findings if f.category == MCPFindingCategory.INSECURE_TRANSPORT]
        assert not transport, "HTTP on localhost should not trigger insecure transport (flagged as SSRF)"


# ---------------------------------------------------------------------------
# Dependency vulnerability checks
# ---------------------------------------------------------------------------

class TestDependencyVulnerabilities:
    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_compromised_npm_package(self, scanner, tmp_path):
        pkg_json = {
            "name": "my-mcp-server",
            "version": "1.0.0",
            "dependencies": {
                "event-stream": "3.3.4",
                "express": "4.18.2",
            },
        }
        p = tmp_path / "package.json"
        p.write_text(json.dumps(pkg_json))
        findings = list(scanner._check_dependency_file(p))
        assert findings
        assert any(f.category == MCPFindingCategory.VULNERABLE_DEPENDENCY for f in findings)
        assert any("event-stream" in f.evidence for f in findings)
        assert any(f.severity == MCPFindingSeverity.CRITICAL for f in findings)

    def test_clean_npm_package_ok(self, scanner, tmp_path):
        pkg_json = {
            "name": "safe-server",
            "dependencies": {"express": "4.18.2", "ws": "8.13.0"},
        }
        p = tmp_path / "package.json"
        p.write_text(json.dumps(pkg_json))
        findings = list(scanner._check_dependency_file(p))
        assert not findings

    def test_typosquat_npm(self, scanner, tmp_path):
        pkg_json = {
            "name": "victim",
            "dependencies": {"coa": "2.0.2"},  # hijacked in 2021
        }
        p = tmp_path / "package.json"
        p.write_text(json.dumps(pkg_json))
        findings = list(scanner._check_dependency_file(p))
        assert findings
        assert any(f.severity == MCPFindingSeverity.CRITICAL for f in findings)

    def test_malicious_pypi_package(self, scanner, tmp_path):
        req = "colourama==0.4.4\nrequests>=2.28\n"
        p = tmp_path / "requirements.txt"
        p.write_text(req)
        findings = list(scanner._check_dependency_file(p))
        assert findings
        assert any("colourama" in f.evidence for f in findings)

    def test_clean_pypi_ok(self, scanner, tmp_path):
        req = "fastapi>=0.104\nhttpx>=0.25\npydantic>=2.5\n"
        p = tmp_path / "requirements.txt"
        p.write_text(req)
        findings = list(scanner._check_dependency_file(p))
        assert not findings


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

class TestDirectoryScan:
    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_scan_directory_finds_configs(self, scanner, tmp_path):
        # Create two config files in subdirectories
        sub1 = tmp_path / "server-a"
        sub1.mkdir()
        (sub1 / "mcp.json").write_text(_config_json({
            "ssrf-server": {"url": "http://127.0.0.1:9000"}
        }))
        sub2 = tmp_path / "server-b"
        sub2.mkdir()
        (sub2 / "mcp.json").write_text(_config_json({
            "clean": {"command": "npx", "args": ["-y", "safe-server"]}
        }))

        result = scanner.scan_directory(tmp_path)
        assert len(result.scanned_files) >= 2
        ssrf = [f for f in result.findings if f.category == MCPFindingCategory.SSRF]
        assert ssrf

    def test_scan_directory_dep_files(self, scanner, tmp_path):
        (tmp_path / "mcp.json").write_text(_config_json({}))
        pkg = {"dependencies": {"event-stream": "3.3.4"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))

        result = scanner.scan_directory(tmp_path)
        vuln = [f for f in result.findings if f.category == MCPFindingCategory.VULNERABLE_DEPENDENCY]
        assert vuln


# ---------------------------------------------------------------------------
# JSON output / data model
# ---------------------------------------------------------------------------

class TestScanResultModel:
    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_to_dict_schema(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "bad": {"url": "http://127.0.0.1:8080"}
        })
        result = scanner.scan_file(path)
        d = result.to_dict()
        assert "scanned_files" in d
        assert "findings" in d
        assert "summary" in d
        assert "timestamp" in d
        assert "execution_time_ms" in d
        # Each finding has required keys
        for f in d["findings"]:
            for key in ("category", "severity", "server_name", "file_path",
                        "line_number", "description", "evidence", "recommendation"):
                assert key in f, f"Missing key '{key}' in finding dict"

    def test_summary_counts(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "mixed": {
                "url": "http://127.0.0.1:9090",       # SSRF → HIGH
                "env": {"API_KEY": "sk-" + "x" * 40},  # SECRET → CRITICAL
            }
        })
        result = scanner.scan_file(path)
        summary = result.summary
        assert summary["CRITICAL"] >= 1
        assert summary["HIGH"] >= 1

    def test_highest_severity(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "crit": {
                "command": "bash",
                "args": ["-c", "node server.js"],
            }
        })
        result = scanner.scan_file(path)
        assert result.highest_severity == MCPFindingSeverity.CRITICAL

    def test_no_findings_clean_config(self, scanner, tmp_path):
        path = _write_config(tmp_path, {
            "safe": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/allowed"],
            }
        })
        result = scanner.scan_file(path)
        assert not result.has_findings


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    @pytest.fixture()
    def scanner(self):
        return MCPScanner()

    def test_invalid_json_returns_info_finding(self, scanner, tmp_path):
        p = tmp_path / "mcp.json"
        p.write_text("{this is not valid json")
        result = scanner.scan_file(p)
        assert result.findings  # Should have an info-level finding

    def test_empty_config(self, scanner, tmp_path):
        p = tmp_path / "mcp.json"
        p.write_text("{}")
        result = scanner.scan_file(p)
        # No servers → no findings
        assert not result.findings

    def test_servers_format_alternative(self, scanner, tmp_path):
        """Support 'servers' root key in addition to 'mcpServers'."""
        p = tmp_path / "mcp.json"
        p.write_text(json.dumps({
            "servers": {
                "ssrf-srv": {"url": "http://10.0.0.1/api"}
            }
        }))
        result = scanner.scan_file(p)
        ssrf = [f for f in result.findings if f.category == MCPFindingCategory.SSRF]
        assert ssrf

    def test_line_numbers_nonzero(self, scanner, tmp_path):
        """Line numbers should be populated for findings in multiline configs."""
        path = _write_config(tmp_path, {
            "bad": {
                "url": "http://127.0.0.1:8080",
                "env": {"API_KEY": "AKIAIOSFODNN7EXAMPLE"},
            }
        })
        result = scanner.scan_file(path)
        for f in result.findings:
            assert f.line_number > 0, f"Finding '{f.description}' has line_number=0"
