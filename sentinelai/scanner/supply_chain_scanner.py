"""Supply chain dependency scanner.

Scans requirements.txt, package.json, and pyproject.toml for:
- Known malicious / previously-compromised packages
- Unpinned dependency versions (float-attack surface)
- Typosquatting candidates (Levenshtein distance 1-2 from popular packages)
- GPL / copyleft licenses in projects declared as Apache-2.0 / MIT / BSD

Usage::

    scanner = SupplyChainScanner()
    report = scanner.scan_file(Path("requirements.txt"))
    if report.has_findings:
        for f in report.findings:
            print(f.severity, f.package, f.description)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SupplyChainFinding:
    """A single dependency security finding."""

    package: str
    finding_type: str       # malicious | unpinned | typosquat | license_conflict
    severity: str           # critical | high | medium | low
    description: str
    recommendation: str
    source_file: str = ""
    version: str = ""
    similar_to: str = ""    # populated for typosquat findings
    license: str = ""       # populated for license findings


@dataclass
class SupplyChainReport:
    """Aggregated result of a supply-chain audit across one or more files."""

    source_files: List[str]
    findings: List[SupplyChainFinding]
    total_packages: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "timestamp": self.timestamp,
            "source_files": self.source_files,
            "total_packages": self.total_packages,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findings": [
                {
                    "package": f.package,
                    "version": f.version,
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "source_file": f.source_file,
                    "similar_to": f.similar_to,
                    "license": f.license,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Known malicious PyPI packages (from public security advisories)
# ---------------------------------------------------------------------------

# Each entry: package_name (lowercase) → description of the incident
_KNOWN_MALICIOUS_PYPI: Dict[str, str] = {
    # Confirmed malicious packages removed from PyPI
    "colourama": "Typosquat of 'colorama'; contained credential-stealing backdoor (2018 PyPI incident)",
    "python-openssl": "Typosquat of 'pyOpenSSL'; installs malicious payload instead of the real SSL library",
    "jeIlyfish": "Typosquat of 'jellyfish' (capital I); data-exfiltration backdoor (PyPI 2019)",
    "acqusition": "Malicious package removed from PyPI; executes data-exfiltration script on install",
    "setup-tools": "Typosquat of 'setuptools'; backdoored installer (PyPI removal)",
    "bzip": "Typosquat of 'bzip2'; contains exfiltration code executed at install time",
    "libpython": "Fake libpython package; downloads and executes remote code execution payload",
    "python2": "Fake Python 2 compatibility shim; data-stealing payload (PyPI removal)",
    "urllib4": "Typosquat of 'urllib3'; credential harvesting on import",
    "requets": "Typosquat of 'requests' (swapped 's'); injects backdoor on import",
    "request": "Fake single-module shim for 'requests'; exfiltrates env vars on install",
    "python-requests": "Typosquat of 'requests'; fake package that runs malicious postinstall",
    "pycrypt": "Typosquat of 'pycryptodome'; ships broken crypto + keylogger payload",
    "nmap-python": "Typosquat of 'python-nmap'; malicious port-scan wrapper (PyPI removal)",
    "loguru2": "Fake extension of 'loguru'; collects and ships log data to external server",
    "fastapi2": "Fake 'fastapi' version shim; data-exfiltration on install",
    "aiohttp3": "Typosquat of 'aiohttp'; strips TLS verification and proxies traffic",
    "cryptography2": "Fake 'cryptography' extension; keylogger payload on import",
    "django-settings": "Malicious django settings helper; reads and exfiltrates SECRET_KEY",
    "importlib2": "Fake importlib shim; hijacks module resolution for code injection",
    "diagrams-core": "Fake 'diagrams' sub-package; phone-home data exfiltration",
    "mock-services": "Fake mocking utility; contains reverse-shell payload",
    "jinja3": "Typosquat of 'jinja2' / future placeholder used to ship malware",
    "pytorch-nightly": "Compromised nightly build; contained malicious torchtriton package (2022)",
    "torchtriton": "Dependency confusion attack package; used in pytorch-nightly compromise",
    "ctx": "Compromised PyPI package; exfiltrated AWS credentials via env var harvest (2022)",
    "phpass": "Typosquat of PHP password-hashing library mis-published on PyPI; malicious",
    "python-mysql": "Typosquat of 'mysqlclient'; fake MySQL connector with exfil payload",
    "pyflakes2": "Fake pyflakes extension; runs remote code during linting",
    "solana": "Compromised version published by attacker; private key theft (2022 incident)",
    "browserify-sign": "Vulnerable version with ECDSA signature bypass (CVE-2023-46234 PyPI port)",
    "httplib3": "Typosquat of 'httplib2'; credential-harvesting on first HTTP call",
    "prettytable2": "Fake prettytable extension; installs and executes remote dropper",
    "aiodns2": "Typosquat of 'aiodns'; DNS resolver that ships queries to attacker server",
    # From mcp_scanner known-bad list (cross-coverage)
    "python-dateutil2": "Typosquat of 'python-dateutil'; executes remote payload on install",
    "jeilyfish": "Typosquat of 'jellyfish' (lowercase variant); steals SSH keys",
    "python3-dateutil": "Typosquat of 'python-dateutil'; malicious install hook",
    "diango": "Typosquat of 'django'; installs malicious package in place of web framework",
    "djnago": "Typosquat of 'django'; data-exfiltration payload",
    "reqeusts": "Typosquat of 'requests' (transposed u/e); drops backdoor on import",
    "importantpackage": "Test exfiltration package; never a legitimate dependency",
    "loguru-mcp": "Observed supply-chain compromise vector targeting MCP server environments",
}

# ---------------------------------------------------------------------------
# Known malicious npm packages (from public security advisories)
# ---------------------------------------------------------------------------

_KNOWN_MALICIOUS_NPM: Dict[str, str] = {
    # Confirmed compromised / malicious npm packages
    "event-stream": "Compromised in 2018 to steal bitcoin wallets via malicious flatmap-stream dependency",
    "flatmap-stream": "Injected into event-stream as a backdoor to steal Copay bitcoin wallet keys (2018)",
    "crossenv": "Typosquat of 'cross-env'; steals environment variables including API keys",
    "node-opencv2": "Typosquat of 'node-opencv'; ships OS-specific malicious binary",
    "nodemailer-js": "Typosquat of 'nodemailer'; exfiltrates SMTP credentials on first send",
    "discord.js-self": "Malicious self-bot package; harvests Discord tokens and sends to attacker",
    "babelcli": "Typosquat of 'babel-cli'; steals npm credentials and posts to external URL",
    "getcookies": "Malicious npm package; extracts and exfiltrates browser cookies (2018)",
    "electron-native-notify": "Malicious package; executes remote code via native notification API",
    "load-from-cwd-or-npm": "Malicious wrapper; executes attacker-controlled script from CDN",
    "noblox.js-proxy": "Malicious Roblox API wrapper; harvests and exfiltrates Roblox tokens",
    "rc": "Compromised version published by dependency-confusion attack targeting private packages",
    "ua-parser-js": "Compromised in 2021; versions 0.7.29, 0.8.0, 1.0.0 install cryptominer + RAT",
    "coa": "Compromised in 2021 (versions 2.0.3, 2.0.4, 2.1.1, 2.1.3); installs password stealer",
    "colors": "Sabotaged by author in v1.4.44-liberty-2; infinite loop DoS payload",
    "faker": "Sabotaged by author in v6.6.6; infinite loop DoS payload (2022)",
    "node-ipc": "Author-sabotaged in 2022; destructive payload targeting Russian/Belarusian IPs",
    "web3-connector": "Fake Web3 connector; harvests wallet private keys on connect",
    "solana-web3": "Typosquat of '@solana/web3.js'; steals wallet seeds",
    "ethers-utils": "Typosquat of 'ethers'; wallet seed exfiltration",
    "@apidoc/markdown": "Malicious scoped package; installs remote access trojan",
    "antd-mobile-v5": "Fake Ant Design Mobile extension; collects sensitive component data",
    "jest-standard": "Typosquat of 'jest'; runs malicious script during test setup",
    "mocha-chai": "Typosquat of 'mocha' + 'chai'; runs backdoor in test environment",
    # From mcp_scanner known-bad npm list (cross-coverage)
    "eslint-scope": "Compromised in 2018; exfiltrated npm tokens from developer machines",
    "d3.js": "Typosquat of 'd3'; installs arbitrary code on npm install",
    "jquery.js": "Typosquat of 'jquery'; exfiltrates data and injects scripts",
}

# ---------------------------------------------------------------------------
# Popular packages used for typosquatting distance checks
# ---------------------------------------------------------------------------

_POPULAR_PYPI: List[str] = [
    "requests", "flask", "django", "numpy", "pandas", "boto3",
    "tensorflow", "torch", "cryptography", "pillow", "pillow",
    "beautifulsoup4", "scrapy", "celery", "fastapi", "sqlalchemy",
    "pydantic", "uvicorn", "aiohttp", "pytest", "setuptools",
    "urllib3", "httpx", "paramiko", "fabric", "ansible",
    "colorama", "rich", "typer", "click", "jinja2",
    "pycryptodome", "pyopenssl", "loguru", "attrs", "mypy",
]

_POPULAR_NPM: List[str] = [
    "express", "react", "vue", "angular", "lodash", "axios",
    "webpack", "babel-core", "babel-cli", "jest", "mocha", "chai",
    "eslint", "prettier", "typescript", "nodemailer", "passport",
    "jsonwebtoken", "dotenv", "cross-env", "node-fetch", "sharp",
    "socket.io", "mongoose", "sequelize", "knex", "pg", "mysql2",
    "redis", "ioredis", "winston", "morgan", "cors", "helmet",
    "moment", "dayjs", "uuid", "nanoid", "zod", "yup",
]

# ---------------------------------------------------------------------------
# Known copyleft-licensed PyPI packages (GPL / AGPL / SSPL)
# Flagged when the project's own declared license is permissive.
# ---------------------------------------------------------------------------

# Format: lowercase_package_name → (spdx_id, short_note)
_KNOWN_COPYLEFT_PYPI: Dict[str, Tuple[str, str]] = {
    "mysql-connector-python": ("GPL-2.0-only", "Oracle MySQL connector uses GPL-2.0"),
    "mysqlclient": ("GPL-1.0-or-later", "C-extension MySQL wrapper; GPL"),
    "mysql-python": ("GPL", "Legacy MySQL-Python adapter; GPL"),
    "gdbm": ("GPL-2.0-or-later", "GNU dbm bindings; GPL"),
    "gnureadline": ("GPL-3.0-or-later", "GNU Readline Python bindings; GPL-3.0"),
    "gpgme": ("GPL-2.0-or-later", "GnuPG Made Easy Python bindings; GPL"),
    "pyaudio": ("MIT", ""),  # actually MIT, not copyleft — exclude
}
# Remove non-copyleft entries added by mistake
_KNOWN_COPYLEFT_PYPI = {
    k: v for k, v in _KNOWN_COPYLEFT_PYPI.items() if v[0] not in ("MIT",)
}

# Licenses considered copyleft / incompatible with permissive projects
_COPYLEFT_SPDX = {
    "GPL-1.0", "GPL-1.0+", "GPL-1.0-only", "GPL-1.0-or-later",
    "GPL-2.0", "GPL-2.0+", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0+", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0",
    "EUPL-1.0", "EUPL-1.1", "EUPL-1.2",
}

# Permissive licenses that trigger the copyleft compatibility check
_PERMISSIVE_SPDX = {
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unlicense", "0BSD", "MPL-2.0",
}

# ---------------------------------------------------------------------------
# Pinning detection regexes
# ---------------------------------------------------------------------------

# requirements.txt line pattern: extracts (package_name, extras, version_spec)
_REQ_LINE_RE = re.compile(
    r"""
    ^
    (?P<pkg>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)  # package name
    (?:\[(?P<extras>[^\]]*)\])?                              # [extras] optional
    \s*
    (?P<spec>[><=!~^][^\s;#]*)?                              # version specifier optional
    """,
    re.VERBOSE,
)

# Strict-pin check: == only (e.g. requests==2.31.0)
_STRICT_PIN_RE = re.compile(r"^==\d")

# pyproject.toml dependency line patterns
_PYPROJECT_DEP_RE = re.compile(
    r'^"?(?P<pkg>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[.*?\])?\s*(?P<spec>[><=!~^][^"]*)?',
)

# ---------------------------------------------------------------------------
# Levenshtein distance (inline, no external deps)
# ---------------------------------------------------------------------------


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (0 if c1 == c2 else 1)))
        prev = curr
    return prev[-1]


# ---------------------------------------------------------------------------
# SupplyChainScanner
# ---------------------------------------------------------------------------


class SupplyChainScanner:
    """Scan dependency files for supply-chain security risks.

    Supported file types
    --------------------
    * ``requirements.txt`` (and any ``*requirements*.txt``)
    * ``package.json``
    * ``pyproject.toml``

    Usage::

        scanner = SupplyChainScanner()
        report = scanner.scan_file(Path("requirements.txt"))

        # Or pass a project directory — all supported files are discovered
        report = scanner.scan_directory(Path("/my/project"))
    """

    def __init__(self, project_license: Optional[str] = None) -> None:
        """
        Parameters
        ----------
        project_license:
            The SPDX identifier of the host project's license (e.g. "Apache-2.0").
            When set, copyleft dependencies trigger a ``license_conflict`` finding.
            If ``None`` the scanner will try to read it from a scanned
            ``pyproject.toml``.
        """
        self._project_license: Optional[str] = project_license

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: Path) -> SupplyChainReport:
        """Scan a single dependency file and return a report."""
        name = path.name.lower()
        content = path.read_text(encoding="utf-8", errors="replace")

        if name == "package.json":
            findings, total = self._scan_package_json(content, str(path))
        elif name == "pyproject.toml":
            findings, total = self._scan_pyproject_toml(content, str(path))
        elif "requirements" in name and name.endswith(".txt"):
            findings, total = self._scan_requirements_txt(content, str(path))
        else:
            raise ValueError(
                f"Unsupported file: {path.name}. "
                "Supported: requirements*.txt, package.json, pyproject.toml"
            )

        return SupplyChainReport(
            source_files=[str(path)],
            findings=findings,
            total_packages=total,
        )

    def scan_requirements_content(
        self, content: str, source: str = "<requirements.txt>"
    ) -> SupplyChainReport:
        """Scan raw requirements.txt content (useful for API / testing)."""
        findings, total = self._scan_requirements_txt(content, source)
        return SupplyChainReport(source_files=[source], findings=findings, total_packages=total)

    def scan_package_json_content(
        self, content: str, source: str = "<package.json>"
    ) -> SupplyChainReport:
        """Scan raw package.json content (useful for API / testing)."""
        findings, total = self._scan_package_json(content, source)
        return SupplyChainReport(source_files=[source], findings=findings, total_packages=total)

    def scan_pyproject_toml_content(
        self, content: str, source: str = "<pyproject.toml>"
    ) -> SupplyChainReport:
        """Scan raw pyproject.toml content (useful for API / testing)."""
        findings, total = self._scan_pyproject_toml(content, source)
        return SupplyChainReport(source_files=[source], findings=findings, total_packages=total)

    def scan_directory(self, directory: Path) -> SupplyChainReport:
        """Discover and scan all supported dependency files in *directory*."""
        candidates: List[Path] = []
        for pattern in ("requirements*.txt", "package.json", "pyproject.toml"):
            candidates.extend(directory.glob(pattern))

        if not candidates:
            return SupplyChainReport(
                source_files=[],
                findings=[],
                total_packages=0,
            )

        all_findings: List[SupplyChainFinding] = []
        total = 0
        sources: List[str] = []

        for path in sorted(candidates):
            try:
                sub = self.scan_file(path)
                all_findings.extend(sub.findings)
                total += sub.total_packages
                sources.append(str(path))
            except (ValueError, OSError):
                continue

        return SupplyChainReport(
            source_files=sources,
            findings=all_findings,
            total_packages=total,
        )

    # ------------------------------------------------------------------
    # requirements.txt
    # ------------------------------------------------------------------

    def _scan_requirements_txt(
        self, content: str, source: str
    ) -> Tuple[List[SupplyChainFinding], int]:
        findings: List[SupplyChainFinding] = []
        total = 0

        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Skip blanks, comments, options (-r, --index-url, etc.)
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            m = _REQ_LINE_RE.match(line)
            if not m:
                continue

            pkg_raw = m.group("pkg")
            spec = (m.group("spec") or "").strip()
            pkg = pkg_raw.lower().replace("_", "-")
            total += 1

            findings.extend(self._check_malicious_pypi(pkg, pkg_raw, spec, source))
            findings.extend(self._check_unpinned(pkg, pkg_raw, spec, source, ecosystem="pypi"))
            findings.extend(self._check_typosquat_pypi(pkg, pkg_raw, spec, source))
            findings.extend(self._check_license_pypi(pkg, pkg_raw, spec, source))

        return findings, total

    # ------------------------------------------------------------------
    # package.json
    # ------------------------------------------------------------------

    def _scan_package_json(
        self, content: str, source: str
    ) -> Tuple[List[SupplyChainFinding], int]:
        findings: List[SupplyChainFinding] = []
        total = 0

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            findings.append(SupplyChainFinding(
                package="<package.json>",
                finding_type="parse_error",
                severity="low",
                description=f"Could not parse package.json: {exc}",
                recommendation="Fix JSON syntax errors in package.json.",
                source_file=source,
            ))
            return findings, 0

        dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
        for section in dep_sections:
            deps: Dict[str, str] = data.get(section, {})
            for pkg_raw, version_spec in deps.items():
                pkg = pkg_raw.lower()
                total += 1

                findings.extend(self._check_malicious_npm(pkg, pkg_raw, version_spec, source))
                findings.extend(self._check_unpinned_npm(pkg, pkg_raw, version_spec, source))
                findings.extend(self._check_typosquat_npm(pkg, pkg_raw, version_spec, source))

        return findings, total

    # ------------------------------------------------------------------
    # pyproject.toml
    # ------------------------------------------------------------------

    def _scan_pyproject_toml(
        self, content: str, source: str
    ) -> Tuple[List[SupplyChainFinding], int]:
        findings: List[SupplyChainFinding] = []
        packages: List[Tuple[str, str, str]] = []  # (pkg_raw, pkg_lower, version_spec)

        # Try stdlib tomllib (3.11+) then tomli
        project_license: Optional[str] = self._project_license
        try:
            try:
                import tomllib  # type: ignore[import]
                data = tomllib.loads(content)
            except ModuleNotFoundError:
                import tomli as tomllib  # type: ignore[import, no-redef]
                data = tomllib.loads(content)

            # Detect project license
            if project_license is None:
                lic = (
                    data.get("project", {}).get("license", {})
                )
                if isinstance(lic, dict):
                    project_license = lic.get("text") or lic.get("file", "")
                elif isinstance(lic, str):
                    project_license = lic

            # [project] dependencies
            for dep in data.get("project", {}).get("dependencies", []):
                m = _PYPROJECT_DEP_RE.match(dep.strip().strip('"'))
                if m:
                    pr = m.group("pkg")
                    spec = (m.group("spec") or "").strip().strip('"')
                    packages.append((pr, pr.lower().replace("_", "-"), spec))

            # [tool.poetry.dependencies]
            for pkg_raw, val in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
                if pkg_raw.lower() == "python":
                    continue
                spec = val if isinstance(val, str) else (val.get("version", "") if isinstance(val, dict) else "")
                packages.append((pkg_raw, pkg_raw.lower().replace("_", "-"), spec))

        except Exception:
            # TOML parser unavailable or file malformed — fall back to regex
            packages = list(self._parse_pyproject_toml_regex(content))
            # Try to grab license from text
            if project_license is None:
                lic_m = re.search(r'license\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
                if lic_m:
                    project_license = lic_m.group(1)

        total = len(packages)
        for pkg_raw, pkg, spec in packages:
            findings.extend(self._check_malicious_pypi(pkg, pkg_raw, spec, source))
            findings.extend(self._check_unpinned(pkg, pkg_raw, spec, source, ecosystem="pypi"))
            findings.extend(self._check_typosquat_pypi(pkg, pkg_raw, spec, source))
            if project_license and project_license.strip() in _PERMISSIVE_SPDX:
                findings.extend(self._check_license_pypi(pkg, pkg_raw, spec, source))

        return findings, total

    @staticmethod
    def _parse_pyproject_toml_regex(content: str):
        """Minimal regex-based pyproject.toml dependency extractor (fallback)."""
        # Match lines inside [project] dependencies = [...] or
        # [tool.poetry.dependencies] key = "value"
        dep_block = re.search(
            r'\[project\].*?dependencies\s*=\s*\[(.*?)\]',
            content, re.DOTALL | re.IGNORECASE
        )
        if dep_block:
            for raw in re.findall(r'"([^"]+)"', dep_block.group(1)):
                m = _PYPROJECT_DEP_RE.match(raw.strip())
                if m:
                    pr = m.group("pkg")
                    spec = (m.group("spec") or "").strip()
                    yield pr, pr.lower().replace("_", "-"), spec

        poetry_block = re.search(
            r'\[tool\.poetry\.dependencies\](.*?)(?:\[|\Z)',
            content, re.DOTALL
        )
        if poetry_block:
            for line in poetry_block.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pm = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["\']([^"\']*)["\']', line)
                if pm:
                    pr = pm.group(1)
                    if pr.lower() != "python":
                        spec = pm.group(2)
                        yield pr, pr.lower().replace("_", "-"), spec

    # ------------------------------------------------------------------
    # Check helpers
    # ------------------------------------------------------------------

    def _check_malicious_pypi(
        self, pkg: str, pkg_raw: str, spec: str, source: str
    ) -> List[SupplyChainFinding]:
        desc = _KNOWN_MALICIOUS_PYPI.get(pkg)
        if not desc:
            return []
        return [SupplyChainFinding(
            package=pkg_raw,
            finding_type="malicious",
            severity="critical",
            description=desc,
            recommendation=(
                f"Remove '{pkg_raw}' immediately. "
                "If you intended a different package, double-check the name on PyPI."
            ),
            source_file=source,
            version=spec,
        )]

    def _check_malicious_npm(
        self, pkg: str, pkg_raw: str, spec: str, source: str
    ) -> List[SupplyChainFinding]:
        desc = _KNOWN_MALICIOUS_NPM.get(pkg)
        if not desc:
            return []
        return [SupplyChainFinding(
            package=pkg_raw,
            finding_type="malicious",
            severity="critical",
            description=desc,
            recommendation=(
                f"Remove '{pkg_raw}' immediately. "
                "Check npm advisories and use 'npm audit' to verify."
            ),
            source_file=source,
            version=spec,
        )]

    def _check_unpinned(
        self, pkg: str, pkg_raw: str, spec: str, source: str, ecosystem: str
    ) -> List[SupplyChainFinding]:
        if not spec or not spec.strip():
            return [SupplyChainFinding(
                package=pkg_raw,
                finding_type="unpinned",
                severity="medium",
                description=(
                    f"'{pkg_raw}' has no version pin. "
                    "Unpinned dependencies are vulnerable to dependency confusion "
                    "and version-float supply chain attacks."
                ),
                recommendation=f"Pin to an exact version: {pkg_raw}==<version> (pip) or {pkg_raw}@<version> (npm).",
                source_file=source,
                version="",
            )]
        # Warn on non-strict pins (>=, ~=, ^, etc.)
        if not _STRICT_PIN_RE.match(spec):
            return [SupplyChainFinding(
                package=pkg_raw,
                finding_type="unpinned",
                severity="low",
                description=(
                    f"'{pkg_raw}' uses a loose version specifier '{spec}'. "
                    "This allows automatic upgrades that could introduce malicious versions."
                ),
                recommendation=(
                    f"Consider pinning to an exact version "
                    f"(e.g. {pkg_raw}=={spec.lstrip('><=!~^ ')}) "
                    "or using a lock file (pip-compile / poetry.lock / package-lock.json)."
                ),
                source_file=source,
                version=spec,
            )]
        return []

    def _check_unpinned_npm(
        self, pkg: str, pkg_raw: str, spec: str, source: str
    ) -> List[SupplyChainFinding]:
        """npm uses semver ranges; an exact pin starts with a digit or '='."""
        if not spec or spec in ("*", "latest", ""):
            return [SupplyChainFinding(
                package=pkg_raw,
                finding_type="unpinned",
                severity="medium",
                description=(
                    f"'{pkg_raw}' has no version pin ('{spec}'). "
                    "Always-latest pinning or wildcard allows automatic upgrades to malicious versions."
                ),
                recommendation=f"Pin to an exact version (e.g. \"{pkg_raw}\": \"1.2.3\") and commit package-lock.json.",
                source_file=source,
                version=spec,
            )]
        # Semver ranges: ^, ~, >=, >, < are loose
        if spec and spec[0] in ("^", "~", ">", "<"):
            return [SupplyChainFinding(
                package=pkg_raw,
                finding_type="unpinned",
                severity="low",
                description=(
                    f"'{pkg_raw}' uses loose semver range '{spec}'. "
                    "Ranges allow automatic upgrades which could introduce compromised versions."
                ),
                recommendation=(
                    f"Consider locking to an exact version and committing package-lock.json. "
                    "Use 'npm ci' in CI/CD instead of 'npm install'."
                ),
                source_file=source,
                version=spec,
            )]
        return []

    def _check_typosquat_pypi(
        self, pkg: str, pkg_raw: str, spec: str, source: str
    ) -> List[SupplyChainFinding]:
        # Skip if already flagged as known-malicious
        if pkg in _KNOWN_MALICIOUS_PYPI:
            return []
        for popular in _POPULAR_PYPI:
            dist = _levenshtein(pkg, popular)
            if 1 <= dist <= 2:
                return [SupplyChainFinding(
                    package=pkg_raw,
                    finding_type="typosquat",
                    severity="high",
                    description=(
                        f"'{pkg_raw}' is {dist} character edit(s) away from the popular "
                        f"package '{popular}'. This is a common typosquatting pattern."
                    ),
                    recommendation=(
                        f"Verify this is the correct package name. "
                        f"Did you mean '{popular}'? Check PyPI directly."
                    ),
                    source_file=source,
                    version=spec,
                    similar_to=popular,
                )]
        return []

    def _check_typosquat_npm(
        self, pkg: str, pkg_raw: str, spec: str, source: str
    ) -> List[SupplyChainFinding]:
        # Skip if already flagged
        if pkg in _KNOWN_MALICIOUS_NPM:
            return []
        # Strip @scope prefix for distance calculation
        base_pkg = pkg.split("/")[-1] if "/" in pkg else pkg
        for popular in _POPULAR_NPM:
            dist = _levenshtein(base_pkg, popular)
            if 1 <= dist <= 2:
                return [SupplyChainFinding(
                    package=pkg_raw,
                    finding_type="typosquat",
                    severity="high",
                    description=(
                        f"'{pkg_raw}' is {dist} character edit(s) away from the popular "
                        f"npm package '{popular}'. This is a common typosquatting pattern."
                    ),
                    recommendation=(
                        f"Verify this is the correct package. "
                        f"Did you mean '{popular}'? Check npmjs.com directly."
                    ),
                    source_file=source,
                    version=spec,
                    similar_to=popular,
                )]
        return []

    def _check_license_pypi(
        self, pkg: str, pkg_raw: str, spec: str, source: str
    ) -> List[SupplyChainFinding]:
        entry = _KNOWN_COPYLEFT_PYPI.get(pkg)
        if not entry:
            return []
        spdx_id, note = entry
        return [SupplyChainFinding(
            package=pkg_raw,
            finding_type="license_conflict",
            severity="medium",
            description=(
                f"'{pkg_raw}' is licensed under {spdx_id} ({note}). "
                "Including a copyleft dependency may impose license obligations on "
                "your project if you distribute the combined work."
            ),
            recommendation=(
                "Review your license compatibility obligations. "
                "Consider an alternative package with a permissive license, "
                "or consult legal counsel before distribution."
            ),
            source_file=source,
            version=spec,
            license=spdx_id,
        )]
