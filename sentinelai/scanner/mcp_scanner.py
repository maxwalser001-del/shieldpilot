"""MCP Server Security Scanner.

Scans Model Context Protocol (MCP) server configuration files for common
security vulnerabilities:

  - SSRF: URL parameters pointing to internal/loopback networks
  - Missing auth: MCP server endpoints with no authentication configured
  - Hardcoded secrets: API keys, tokens, passwords in plain text
  - Over-privileged tools: Shell access, filesystem write, or exec permissions
  - Insecure transport: HTTP instead of HTTPS for remote endpoints
  - Vulnerable dependencies: Known bad packages in package.json / requirements.txt

Usage::

    from sentinelai.scanner.mcp_scanner import MCPScanner

    scanner = MCPScanner()
    result = scanner.scan_file(Path("claude_desktop_config.json"))
    result = scanner.scan_directory(Path("./mcp-servers/"))
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Severity / Category enums
# ---------------------------------------------------------------------------

class MCPFindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


class MCPFindingCategory(str, Enum):
    SSRF = "ssrf"
    MISSING_AUTH = "missing_auth"
    HARDCODED_SECRET = "hardcoded_secret"
    OVERPRIVILEGED = "overprivileged"
    INSECURE_TRANSPORT = "insecure_transport"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MCPFinding:
    """A single security finding in an MCP config."""

    category: MCPFindingCategory
    severity: MCPFindingSeverity
    server_name: str          # MCP server identifier, or "" for file-level issues
    file_path: str            # absolute path of the scanned file
    line_number: int          # 1-based, 0 = unknown
    description: str
    evidence: str             # the suspicious value / snippet
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "server_name": self.server_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class MCPScanResult:
    """Aggregated result of scanning one or more MCP config files."""

    scanned_files: List[str] = field(default_factory=list)
    findings: List[MCPFinding] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_time_ms: float = 0.0

    @property
    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in MCPFindingSeverity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def highest_severity(self) -> Optional[MCPFindingSeverity]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: f.severity.order).severity

    def to_dict(self) -> dict:
        return {
            "scanned_files": self.scanned_files,
            "summary": self.summary,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "findings": [f.to_dict() for f in self.findings],
            "timestamp": self.timestamp.isoformat(),
            "execution_time_ms": round(self.execution_time_ms, 2),
        }


# ---------------------------------------------------------------------------
# Internal pattern helpers
# ---------------------------------------------------------------------------

# SSRF: IPv4 private / loopback / link-local ranges
_INTERNAL_IP_RE = re.compile(
    r"(?:"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}"       # loopback
    r"|0\.0\.0\.0"                             # unspecified
    r"|169\.254\.\d{1,3}\.\d{1,3}"            # link-local (IMDS)
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"         # RFC-1918 /8
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"  # RFC-1918 /12
    r"|192\.168\.\d{1,3}\.\d{1,3}"            # RFC-1918 /24
    r"|::1"                                    # IPv6 loopback
    r"|localhost"                              # hostname
    r")",
    re.IGNORECASE,
)

# Secrets: key/token/password followed by a value that looks like a real secret
_SECRET_KEY_RE = re.compile(
    r"(?i)"
    r"(?:api[_-]?(?:key|secret)|secret[_-]?(?:key|access)|access[_-]?(?:token|key)"
    r"|auth[_-]?token|password|passwd|private[_-]?key|client[_-]?secret"
    r"|bearer|credentials?|token|secret)"
)

_SECRET_VALUE_RE = re.compile(
    r"(?:"
    # AWS access key
    r"AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|AROA[0-9A-Z]{16}"
    # OpenAI / Anthropic style
    r"|sk-[a-zA-Z0-9]{20,}"
    # GitHub PAT
    r"|ghp_[a-zA-Z0-9]{36}"
    r"|gho_[a-zA-Z0-9]{36}"
    r"|github_pat_[a-zA-Z0-9_]{82}"
    # Generic long token (32+ alphanumeric/dash)
    r"|[a-zA-Z0-9+/=_\-]{32,}"
    r")"
)

# Over-privileged tool permissions keywords
_OVERPRIVILEGED_TOOLS: List[Tuple[str, str, MCPFindingSeverity]] = [
    ("shell", "Tool grants shell command execution", MCPFindingSeverity.CRITICAL),
    ("exec", "Tool grants arbitrary code execution", MCPFindingSeverity.CRITICAL),
    ("filesystem_write", "Tool grants unrestricted filesystem write access", MCPFindingSeverity.HIGH),
    ("file_write", "Tool grants file write access", MCPFindingSeverity.HIGH),
    ("write_file", "Tool grants file write access", MCPFindingSeverity.HIGH),
    ("delete_file", "Tool grants file deletion", MCPFindingSeverity.HIGH),
    ("network_request", "Tool grants arbitrary outbound network requests", MCPFindingSeverity.MEDIUM),
    ("process_spawn", "Tool can spawn child processes", MCPFindingSeverity.HIGH),
    ("sudo", "Tool may execute with elevated privileges", MCPFindingSeverity.CRITICAL),
    ("run_command", "Tool can run system commands", MCPFindingSeverity.CRITICAL),
    ("computer_use", "Tool has computer-use (screen/keyboard) access", MCPFindingSeverity.HIGH),
]

# Known vulnerable / malicious npm packages (representative sample of typosquats
# and supply-chain-compromised packages — not exhaustive).
_KNOWN_BAD_NPM: Dict[str, Tuple[str, MCPFindingSeverity]] = {
    "event-stream": ("Compromised in 2018; injected cryptocurrency theft payload", MCPFindingSeverity.CRITICAL),
    "eslint-scope": ("Compromised in 2018; exfiltrated npm tokens", MCPFindingSeverity.CRITICAL),
    "flatmap-stream": ("Malicious payload targeting BitPay", MCPFindingSeverity.CRITICAL),
    "crossenv": ("Typosquat of cross-env; exfiltrates env vars", MCPFindingSeverity.CRITICAL),
    "node-opencv": ("Typosquat; backdoored", MCPFindingSeverity.HIGH),
    "nodemailer-js": ("Typosquat of nodemailer; malicious", MCPFindingSeverity.HIGH),
    "babelcli": ("Typosquat of babel-cli; credential stealer", MCPFindingSeverity.HIGH),
    "d3.js": ("Typosquat of d3; runs arbitrary code on install", MCPFindingSeverity.HIGH),
    "jquery.js": ("Typosquat of jquery; exfiltrates data", MCPFindingSeverity.HIGH),
    "coa": ("Hijacked in 2021; injected malicious postinstall", MCPFindingSeverity.CRITICAL),
    "rc": ("Hijacked in 2021; same incident as coa", MCPFindingSeverity.CRITICAL),
    "ua-parser-js": ("Hijacked in 2021; drops crypto miner + backdoor", MCPFindingSeverity.CRITICAL),
}

# Known vulnerable / malicious PyPI packages
_KNOWN_BAD_PYPI: Dict[str, Tuple[str, MCPFindingSeverity]] = {
    "colourama": ("Typosquat of colorama; exfiltrates clipboard", MCPFindingSeverity.CRITICAL),
    "python-dateutil2": ("Typosquat of python-dateutil", MCPFindingSeverity.HIGH),
    "jeIlyfish": ("Typosquat of jellyfish (capital I); steals SSH keys", MCPFindingSeverity.CRITICAL),
    "jeilyfish": ("Typosquat of jellyfish; steals SSH keys", MCPFindingSeverity.CRITICAL),
    "python3-dateutil": ("Typosquat; executed on install", MCPFindingSeverity.HIGH),
    "diango": ("Typosquat of django", MCPFindingSeverity.MEDIUM),
    "djnago": ("Typosquat of django", MCPFindingSeverity.MEDIUM),
    "reqeusts": ("Typosquat of requests", MCPFindingSeverity.MEDIUM),
    "urllib4": ("Typosquat of urllib3; malicious code on install", MCPFindingSeverity.HIGH),
    "setup-tools": ("Typosquat of setuptools; exfiltrates tokens", MCPFindingSeverity.HIGH),
    "importantpackage": ("Test exfiltration package; never legitimate", MCPFindingSeverity.CRITICAL),
    "loguru-mcp": ("Observed supply-chain compromise vector", MCPFindingSeverity.HIGH),
}


# ---------------------------------------------------------------------------
# Line-number helper
# ---------------------------------------------------------------------------

def _find_line(text: str, value: str) -> int:
    """Return 1-based line number of the first occurrence of *value* in *text*, or 0."""
    idx = text.find(str(value))
    if idx == -1:
        return 0
    return text[:idx].count("\n") + 1


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class MCPScanner:
    """Security scanner for MCP server configuration files.

    Supports the Claude Desktop config format (``mcpServers`` key) and the
    generic ``servers`` dict format.  Also scans ``package.json`` and
    ``requirements.txt`` files found alongside configs.
    """

    # Config filenames that are likely to contain MCP server definitions
    MCP_CONFIG_NAMES = {
        "claude_desktop_config.json",
        "claude-desktop-config.json",
        "mcp_config.json",
        "mcp-config.json",
        "mcp_servers.json",
        "mcp-servers.json",
        ".mcp.json",
        "mcp.json",
        "config.json",  # broad but included for directory scans
    }

    def scan_file(self, path: Path) -> MCPScanResult:
        """Scan a single MCP config file and return findings."""
        start = time.perf_counter()
        result = MCPScanResult()
        path = Path(path).resolve()
        result.scanned_files.append(str(path))

        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.findings.append(MCPFinding(
                category=MCPFindingCategory.MISSING_AUTH,
                severity=MCPFindingSeverity.INFO,
                server_name="",
                file_path=str(path),
                line_number=0,
                description=f"Could not read file: {exc}",
                evidence="",
                recommendation="Verify file permissions.",
            ))
            result.execution_time_ms = (time.perf_counter() - start) * 1000
            return result

        # Try parsing as JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.findings.append(MCPFinding(
                category=MCPFindingCategory.MISSING_AUTH,
                severity=MCPFindingSeverity.INFO,
                server_name="",
                file_path=str(path),
                line_number=exc.lineno or 0,
                description="File is not valid JSON — cannot perform deep inspection",
                evidence=str(exc),
                recommendation="Fix JSON syntax errors.",
            ))
            result.execution_time_ms = (time.perf_counter() - start) * 1000
            return result

        # Extract server map from known root key variants
        servers: Dict[str, dict] = {}
        for root_key in ("mcpServers", "servers", "mcp_servers"):
            if isinstance(data.get(root_key), dict):
                servers = data[root_key]
                break

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            for finding in self._check_server(server_name, server_cfg, str(path), raw):
                result.findings.append(finding)

        # Scan all env values at the top-level too (some configs put global env there)
        top_env = data.get("env", {})
        if isinstance(top_env, dict):
            for finding in self._check_env_dict("(global)", top_env, str(path), raw):
                result.findings.append(finding)

        result.execution_time_ms = (time.perf_counter() - start) * 1000
        return result

    def scan_directory(self, path: Path) -> MCPScanResult:
        """Recursively scan a directory for MCP config files.

        Looks for filenames matching ``MCP_CONFIG_NAMES``, as well as any
        ``package.json`` and ``requirements.txt`` files for dependency checks.
        """
        start = time.perf_counter()
        merged = MCPScanResult()
        root = Path(path).resolve()

        config_files = list(self._find_config_files(root))
        dep_files = list(root.rglob("package.json")) + list(root.rglob("requirements.txt"))

        for cfg in config_files:
            sub = self.scan_file(cfg)
            merged.scanned_files.extend(sub.scanned_files)
            merged.findings.extend(sub.findings)

        for dep in dep_files:
            for finding in self._check_dependency_file(dep):
                merged.findings.append(finding)
            if str(dep) not in merged.scanned_files:
                merged.scanned_files.append(str(dep))

        merged.execution_time_ms = (time.perf_counter() - start) * 1000
        return merged

    # ------------------------------------------------------------------
    # Per-server checks
    # ------------------------------------------------------------------

    def _check_server(
        self,
        name: str,
        cfg: dict,
        file_path: str,
        raw: str,
    ) -> Iterator[MCPFinding]:
        yield from self._check_ssrf(name, cfg, file_path, raw)
        yield from self._check_auth(name, cfg, file_path, raw)
        yield from self._check_env_dict(name, cfg.get("env", {}), file_path, raw)
        yield from self._check_permissions(name, cfg, file_path, raw)
        yield from self._check_transport(name, cfg, file_path, raw)
        yield from self._check_command_secrets(name, cfg, file_path, raw)

    # SSRF ---------------------------------------------------------------

    def _check_ssrf(
        self, name: str, cfg: dict, file_path: str, raw: str
    ) -> Iterator[MCPFinding]:
        """Detect URL fields that point to internal network addresses."""
        for key in ("url", "baseUrl", "base_url", "endpoint", "host", "address", "target"):
            value = cfg.get(key)
            if not isinstance(value, str):
                continue
            match = _INTERNAL_IP_RE.search(value)
            if match:
                yield MCPFinding(
                    category=MCPFindingCategory.SSRF,
                    severity=MCPFindingSeverity.HIGH,
                    server_name=name,
                    file_path=file_path,
                    line_number=_find_line(raw, value),
                    description=(
                        f"MCP server '{name}' has a URL pointing to an internal network address. "
                        "If this config is user-controlled or fetched from an untrusted source, "
                        "an attacker could use it to probe internal services (SSRF)."
                    ),
                    evidence=f"{key}: {value}",
                    recommendation=(
                        "Validate and allowlist URLs before connecting. "
                        "Block requests to RFC-1918 ranges and loopback addresses "
                        "unless the server is intentionally local."
                    ),
                )

        # Also check nested transport / connection sub-objects
        for sub_key in ("transport", "connection", "server"):
            sub = cfg.get(sub_key)
            if isinstance(sub, dict):
                yield from self._check_ssrf(name, sub, file_path, raw)

    # Auth ---------------------------------------------------------------

    def _check_auth(
        self, name: str, cfg: dict, file_path: str, raw: str
    ) -> Iterator[MCPFinding]:
        """Warn when a remote server has no authentication configuration."""
        url = cfg.get("url") or cfg.get("baseUrl") or cfg.get("base_url")
        if not url:
            return  # local stdio/command-based server — auth n/a

        auth_keys = {"auth", "authentication", "token", "api_key", "apiKey",
                     "headers", "bearer", "credentials"}
        has_auth = bool(auth_keys & set(cfg.keys()))

        # Check nested headers for Authorization
        headers = cfg.get("headers", {})
        if isinstance(headers, dict):
            lower_headers = {k.lower() for k in headers}
            if "authorization" in lower_headers or "x-api-key" in lower_headers:
                has_auth = True

        if not has_auth:
            yield MCPFinding(
                category=MCPFindingCategory.MISSING_AUTH,
                severity=MCPFindingSeverity.HIGH,
                server_name=name,
                file_path=file_path,
                line_number=_find_line(raw, name),
                description=(
                    f"Remote MCP server '{name}' has no authentication configured. "
                    "Any process with access to this config can connect to the server "
                    "without credentials."
                ),
                evidence=f"url: {url}  (no auth/headers/token key present)",
                recommendation=(
                    "Add an 'headers' field with an 'Authorization: Bearer <token>' entry, "
                    "or configure API key authentication."
                ),
            )

    # Env / secrets ------------------------------------------------------

    def _check_env_dict(
        self, name: str, env: object, file_path: str, raw: str
    ) -> Iterator[MCPFinding]:
        """Scan an env dict for hardcoded secrets."""
        if not isinstance(env, dict):
            return
        for key, value in env.items():
            if not isinstance(value, str) or not value.strip():
                continue
            if _SECRET_KEY_RE.search(key) and _SECRET_VALUE_RE.search(value):
                yield MCPFinding(
                    category=MCPFindingCategory.HARDCODED_SECRET,
                    severity=MCPFindingSeverity.CRITICAL,
                    server_name=name,
                    file_path=file_path,
                    line_number=_find_line(raw, value[:20]),
                    description=(
                        f"Hardcoded secret found in env for MCP server '{name}'. "
                        "Storing secrets in config files risks leaking them via "
                        "version control or filesystem access."
                    ),
                    evidence=f"{key}: {value[:8]}***",
                    recommendation=(
                        "Replace the hardcoded value with an environment variable reference. "
                        "Use a secrets manager (1Password, Vault, AWS Secrets Manager) "
                        "or a .env file excluded from version control."
                    ),
                )

    def _check_command_secrets(
        self, name: str, cfg: dict, file_path: str, raw: str
    ) -> Iterator[MCPFinding]:
        """Detect secrets embedded directly in command args."""
        args = cfg.get("args", [])
        if not isinstance(args, list):
            return
        for arg in args:
            if not isinstance(arg, str):
                continue
            # Skip args that are clearly not secrets: flags, package names, paths
            if arg.startswith(("-", "@", "/", "./", "~/", "~\\", ".\\")):
                continue
            if _SECRET_VALUE_RE.search(arg) and len(arg) >= 20:
                yield MCPFinding(
                    category=MCPFindingCategory.HARDCODED_SECRET,
                    severity=MCPFindingSeverity.HIGH,
                    server_name=name,
                    file_path=file_path,
                    line_number=_find_line(raw, arg[:20]),
                    description=(
                        f"Possible secret embedded in command args for MCP server '{name}'."
                    ),
                    evidence=f"arg: {arg[:8]}***",
                    recommendation=(
                        "Pass secrets via environment variables, not command-line arguments. "
                        "Command args are visible in process listings."
                    ),
                )

    # Permissions --------------------------------------------------------

    def _check_permissions(
        self, name: str, cfg: dict, file_path: str, raw: str
    ) -> Iterator[MCPFinding]:
        """Flag tools that grant dangerous capabilities."""
        tools_raw = cfg.get("tools") or cfg.get("capabilities") or []
        tools: List[str] = []

        if isinstance(tools_raw, list):
            for t in tools_raw:
                if isinstance(t, str):
                    tools.append(t.lower())
                elif isinstance(t, dict):
                    tools.append((t.get("name") or t.get("type") or "").lower())
        elif isinstance(tools_raw, dict):
            tools = [k.lower() for k in tools_raw.keys()]

        for keyword, description, severity in _OVERPRIVILEGED_TOOLS:
            for tool in tools:
                if keyword in tool:
                    yield MCPFinding(
                        category=MCPFindingCategory.OVERPRIVILEGED,
                        severity=severity,
                        server_name=name,
                        file_path=file_path,
                        line_number=_find_line(raw, tool),
                        description=f"MCP server '{name}': {description}",
                        evidence=f"tool: {tool}",
                        recommendation=(
                            "Apply the principle of least privilege. "
                            "Remove or restrict capabilities to the minimum required. "
                            "Require explicit user confirmation for dangerous operations."
                        ),
                    )
                    break  # one finding per keyword per server

        # Also check command itself: running shell interpreters is a red flag
        command = cfg.get("command", "")
        if isinstance(command, str):
            shell_bins = {"bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh", "python", "node"}
            if command.split("/")[-1].lower() in shell_bins:
                # Running a shell directly is only suspicious if args look like -c "..."
                args = cfg.get("args", [])
                if isinstance(args, list) and args and args[0] in ("-c", "/c", "-Command"):
                    yield MCPFinding(
                        category=MCPFindingCategory.OVERPRIVILEGED,
                        severity=MCPFindingSeverity.CRITICAL,
                        server_name=name,
                        file_path=file_path,
                        line_number=_find_line(raw, command),
                        description=(
                            f"MCP server '{name}' runs a shell interpreter with inline commands "
                            "(e.g. bash -c '...'). This is a common code-injection vector."
                        ),
                        evidence=f"command: {command} {' '.join(str(a) for a in args[:3])}",
                        recommendation=(
                            "Use a dedicated MCP server binary instead of inline shell scripts. "
                            "Never pass user-controlled data as shell arguments."
                        ),
                    )

    # Transport ----------------------------------------------------------

    def _check_transport(
        self, name: str, cfg: dict, file_path: str, raw: str
    ) -> Iterator[MCPFinding]:
        """Warn on plaintext HTTP for remote endpoints (outside localhost)."""
        url = cfg.get("url") or cfg.get("baseUrl") or cfg.get("base_url")
        if not isinstance(url, str):
            return

        # Only flag HTTP on non-local hosts
        if url.lower().startswith("http://") and not _INTERNAL_IP_RE.search(url):
            yield MCPFinding(
                category=MCPFindingCategory.INSECURE_TRANSPORT,
                severity=MCPFindingSeverity.MEDIUM,
                server_name=name,
                file_path=file_path,
                line_number=_find_line(raw, url),
                description=(
                    f"MCP server '{name}' communicates over plaintext HTTP. "
                    "Credentials and tool responses are transmitted unencrypted."
                ),
                evidence=f"url: {url}",
                recommendation="Use HTTPS (TLS) for all remote MCP server connections.",
            )

    # ------------------------------------------------------------------
    # Dependency checks
    # ------------------------------------------------------------------

    def _check_dependency_file(self, path: Path) -> Iterator[MCPFinding]:
        """Check package.json or requirements.txt for known bad packages."""
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        if path.name == "package.json":
            yield from self._check_npm_deps(path, raw)
        elif path.name == "requirements.txt":
            yield from self._check_pypi_deps(path, raw)

    def _check_npm_deps(self, path: Path, raw: str) -> Iterator[MCPFinding]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return

        all_deps: Dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            if isinstance(data.get(section), dict):
                all_deps.update(data[section])

        for pkg, (reason, severity) in _KNOWN_BAD_NPM.items():
            if pkg in all_deps:
                yield MCPFinding(
                    category=MCPFindingCategory.VULNERABLE_DEPENDENCY,
                    severity=severity,
                    server_name="",
                    file_path=str(path),
                    line_number=_find_line(raw, f'"{pkg}"'),
                    description=f"Known dangerous npm package: {pkg}",
                    evidence=f"{pkg}@{all_deps[pkg]} — {reason}",
                    recommendation=(
                        f"Remove '{pkg}' immediately and audit for data exfiltration. "
                        "Check npm advisory database for a safe alternative."
                    ),
                )

    def _check_pypi_deps(self, path: Path, raw: str) -> Iterator[MCPFinding]:
        for line_no, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip version specifiers: requests>=2.28  →  requests
            pkg = re.split(r"[>=<!;\[]", line)[0].strip().lower()
            if pkg in _KNOWN_BAD_PYPI:
                reason, severity = _KNOWN_BAD_PYPI[pkg]
                yield MCPFinding(
                    category=MCPFindingCategory.VULNERABLE_DEPENDENCY,
                    severity=severity,
                    server_name="",
                    file_path=str(path),
                    line_number=line_no,
                    description=f"Known dangerous PyPI package: {pkg}",
                    evidence=f"{line} — {reason}",
                    recommendation=(
                        f"Remove '{pkg}' immediately. "
                        "Check PyPI advisory database for a safe alternative."
                    ),
                )

    # ------------------------------------------------------------------
    # Directory traversal
    # ------------------------------------------------------------------

    def _find_config_files(self, root: Path) -> Iterator[Path]:
        """Yield MCP config files found under *root*."""
        for candidate in root.rglob("*.json"):
            if candidate.name in self.MCP_CONFIG_NAMES:
                yield candidate
