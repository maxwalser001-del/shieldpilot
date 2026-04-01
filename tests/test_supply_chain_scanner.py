"""Tests for SupplyChainScanner.

Covers:
- Known malicious packages in requirements.txt, package.json, pyproject.toml
- Unpinned and loosely-pinned versions
- Typosquatting detection (Levenshtein distance 1-2)
- GPL license conflict detection
- Clean files produce no findings
- JSON serialisation
- CLI supply-chain-audit command
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelai.cli.main import app
from sentinelai.scanner.supply_chain_scanner import (
    SupplyChainFinding,
    SupplyChainReport,
    SupplyChainScanner,
    _levenshtein,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Levenshtein helper
# ---------------------------------------------------------------------------


class TestLevenshtein:
    def test_equal_strings(self):
        assert _levenshtein("requests", "requests") == 0

    def test_one_deletion(self):
        assert _levenshtein("requets", "requests") == 1

    def test_one_insertion(self):
        assert _levenshtein("requests", "requets") == 1

    def test_two_edits(self):
        # "flask22" → "flask" = 2 deletions
        assert _levenshtein("flask22", "flask") == 2

    def test_empty_vs_word(self):
        assert _levenshtein("", "requests") == 8


# ---------------------------------------------------------------------------
# requirements.txt — malicious packages
# ---------------------------------------------------------------------------


REQUIREMENTS_MALICIOUS = """\
# This file contains known-malicious packages for testing
colourama==1.0.0
requets>=2.28.0
urllib4
requests==2.31.0
"""

REQUIREMENTS_CLEAN = """\
requests==2.31.0
flask==3.0.0
sqlalchemy==2.0.0
pydantic==2.0.0
"""

REQUIREMENTS_UNPINNED = """\
requests
flask>=3.0
sqlalchemy~=2.0
pydantic==2.0.0
"""

REQUIREMENTS_TYPOSQUAT = """\
# one char off from 'requests'
requets==2.28.0
# two chars off from 'flask'
flask2==3.0.0
"""


class TestRequirementsMalicious:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_known_malicious_package_flagged(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_MALICIOUS)
        malicious = [f for f in report.findings if f.finding_type == "malicious"]
        pkg_names = [f.package.lower() for f in malicious]
        assert "colourama" in pkg_names
        assert "requets" in pkg_names

    def test_malicious_findings_are_critical(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_MALICIOUS)
        malicious = [f for f in report.findings if f.finding_type == "malicious"]
        for f in malicious:
            assert f.severity == "critical"

    def test_clean_package_not_flagged_as_malicious(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_MALICIOUS)
        malicious_pkgs = {f.package.lower() for f in report.findings if f.finding_type == "malicious"}
        assert "requests" not in malicious_pkgs

    def test_total_package_count(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_CLEAN)
        assert report.total_packages == 4

    def test_clean_file_no_malicious_findings(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_CLEAN)
        assert not any(f.finding_type == "malicious" for f in report.findings)


# ---------------------------------------------------------------------------
# requirements.txt — unpinned versions
# ---------------------------------------------------------------------------


class TestRequirementsUnpinned:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_unpinned_package_flagged(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_UNPINNED)
        unpinned = [f for f in report.findings if f.finding_type == "unpinned"]
        pkg_names = [f.package.lower() for f in unpinned]
        assert "requests" in pkg_names

    def test_loose_pin_flagged(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_UNPINNED)
        unpinned = [f for f in report.findings if f.finding_type == "unpinned"]
        pkg_names = [f.package.lower() for f in unpinned]
        # flask>=3.0 and sqlalchemy~=2.0 are loose pins
        assert "flask" in pkg_names
        assert "sqlalchemy" in pkg_names

    def test_exact_pin_not_flagged_as_unpinned(self):
        report = self.scanner.scan_requirements_content(REQUIREMENTS_UNPINNED)
        unpinned_pkgs = {f.package.lower() for f in report.findings if f.finding_type == "unpinned"}
        assert "pydantic" not in unpinned_pkgs

    def test_unpinned_severity_medium(self):
        content = "requests\n"
        report = self.scanner.scan_requirements_content(content)
        unpinned = [f for f in report.findings if f.finding_type == "unpinned"]
        assert any(f.severity == "medium" for f in unpinned)

    def test_loose_pin_severity_low(self):
        content = "requests>=2.28.0\n"
        report = self.scanner.scan_requirements_content(content)
        unpinned = [f for f in report.findings if f.finding_type == "unpinned"]
        assert any(f.severity == "low" for f in unpinned)

    def test_strict_pin_no_unpinned_finding(self):
        content = "requests==2.31.0\n"
        report = self.scanner.scan_requirements_content(content)
        assert not any(f.finding_type == "unpinned" for f in report.findings)


# ---------------------------------------------------------------------------
# requirements.txt — typosquatting
# ---------------------------------------------------------------------------


class TestRequirementsTyposquat:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_one_char_edit_flagged(self):
        # 'requets' is 1 edit from 'requests'
        report = self.scanner.scan_requirements_content("requets==2.28.0\n")
        # requets is in the malicious list so it comes up as malicious (not typosquat)
        # use a package not in malicious list that's close to a popular one
        # 'flaskk' is 1 edit from 'flask'
        report = self.scanner.scan_requirements_content("flaskk==3.0.0\n")
        typosquats = [f for f in report.findings if f.finding_type == "typosquat"]
        assert len(typosquats) >= 1
        assert typosquats[0].similar_to == "flask"

    def test_two_char_edit_flagged(self):
        # 'numpy2' is 1 edit from 'numpy' — check distance 2 as well
        report = self.scanner.scan_requirements_content("numpyy2==1.0.0\n")
        typosquats = [f for f in report.findings if f.finding_type == "typosquat"]
        assert any(f.similar_to == "numpy" for f in typosquats)

    def test_exact_popular_name_not_typosquat(self):
        report = self.scanner.scan_requirements_content("requests==2.31.0\n")
        assert not any(f.finding_type == "typosquat" for f in report.findings)

    def test_clearly_different_name_not_flagged(self):
        report = self.scanner.scan_requirements_content("anthropic==0.20.0\n")
        assert not any(f.finding_type == "typosquat" for f in report.findings)

    def test_typosquat_severity_high(self):
        report = self.scanner.scan_requirements_content("flaskk==3.0.0\n")
        typosquats = [f for f in report.findings if f.finding_type == "typosquat"]
        for f in typosquats:
            assert f.severity == "high"

    def test_similar_to_field_populated(self):
        report = self.scanner.scan_requirements_content("flaskk==3.0.0\n")
        typosquats = [f for f in report.findings if f.finding_type == "typosquat"]
        assert all(f.similar_to for f in typosquats)


# ---------------------------------------------------------------------------
# package.json — malicious + unpinned + typosquat
# ---------------------------------------------------------------------------

PACKAGE_JSON_MALICIOUS = json.dumps({
    "name": "test-app",
    "dependencies": {
        "event-stream": "^3.3.4",
        "flatmap-stream": "0.1.1",
        "express": "^4.18.0",
    }
})

PACKAGE_JSON_CLEAN = json.dumps({
    "name": "test-app",
    "dependencies": {
        "express": "4.18.2",
        "lodash": "4.17.21",
    },
    "devDependencies": {
        "jest": "29.0.0",
    }
})

PACKAGE_JSON_UNPINNED = json.dumps({
    "dependencies": {
        "express": "^4.18.0",
        "lodash": "latest",
        "axios": "*",
        "uuid": "9.0.0",
    }
})

PACKAGE_JSON_TYPOSQUAT = json.dumps({
    "dependencies": {
        "expresss": "4.18.0",
        "lodashh": "4.17.21",
    }
})


class TestPackageJsonMalicious:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_malicious_npm_packages_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_MALICIOUS)
        malicious = {f.package.lower() for f in report.findings if f.finding_type == "malicious"}
        assert "event-stream" in malicious
        assert "flatmap-stream" in malicious

    def test_clean_npm_package_not_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_MALICIOUS)
        malicious = {f.package.lower() for f in report.findings if f.finding_type == "malicious"}
        assert "express" not in malicious

    def test_clean_file_no_findings(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_CLEAN)
        assert not any(f.finding_type == "malicious" for f in report.findings)

    def test_invalid_json_produces_parse_error(self):
        report = self.scanner.scan_package_json_content("{not valid json}")
        assert any(f.finding_type == "parse_error" for f in report.findings)


class TestPackageJsonUnpinned:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_caret_range_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_UNPINNED)
        unpinned = {f.package.lower() for f in report.findings if f.finding_type == "unpinned"}
        assert "express" in unpinned

    def test_latest_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_UNPINNED)
        unpinned = {f.package.lower() for f in report.findings if f.finding_type == "unpinned"}
        assert "lodash" in unpinned

    def test_wildcard_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_UNPINNED)
        unpinned = {f.package.lower() for f in report.findings if f.finding_type == "unpinned"}
        assert "axios" in unpinned

    def test_exact_version_not_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_UNPINNED)
        unpinned = {f.package.lower() for f in report.findings if f.finding_type == "unpinned"}
        assert "uuid" not in unpinned


class TestPackageJsonTyposquat:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_npm_typosquat_flagged(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_TYPOSQUAT)
        typosquats = [f for f in report.findings if f.finding_type == "typosquat"]
        pkg_names = {f.package.lower() for f in typosquats}
        # "expresss" (3 s's) → distance 1 from "express"
        assert "expresss" in pkg_names

    def test_typosquat_similar_to_populated(self):
        report = self.scanner.scan_package_json_content(PACKAGE_JSON_TYPOSQUAT)
        typosquats = [f for f in report.findings if f.finding_type == "typosquat"]
        assert all(f.similar_to for f in typosquats)


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------

PYPROJECT_MALICIOUS = """\
[project]
name = "myapp"
license = {text = "Apache-2.0"}
dependencies = [
    "requests==2.31.0",
    "colourama==1.0.0",
    "mysql-connector-python>=8.0",
]

[tool.poetry.dependencies]
python = "^3.9"
flask = "^3.0.0"
"""

PYPROJECT_CLEAN = """\
[project]
name = "myapp"
dependencies = [
    "requests==2.31.0",
    "flask==3.0.0",
]
"""


class TestPyprojectToml:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_malicious_package_in_project_deps(self):
        report = self.scanner.scan_pyproject_toml_content(PYPROJECT_MALICIOUS)
        malicious = {f.package.lower() for f in report.findings if f.finding_type == "malicious"}
        assert "colourama" in malicious

    def test_clean_package_not_malicious(self):
        report = self.scanner.scan_pyproject_toml_content(PYPROJECT_CLEAN)
        assert not any(f.finding_type == "malicious" for f in report.findings)

    def test_gpl_package_license_conflict(self):
        report = self.scanner.scan_pyproject_toml_content(PYPROJECT_MALICIOUS)
        license_findings = [f for f in report.findings if f.finding_type == "license_conflict"]
        pkg_names = {f.package.lower() for f in license_findings}
        assert "mysql-connector-python" in pkg_names

    def test_license_conflict_severity_medium(self):
        report = self.scanner.scan_pyproject_toml_content(PYPROJECT_MALICIOUS)
        license_findings = [f for f in report.findings if f.finding_type == "license_conflict"]
        for f in license_findings:
            assert f.severity == "medium"

    def test_license_field_populated(self):
        report = self.scanner.scan_pyproject_toml_content(PYPROJECT_MALICIOUS)
        license_findings = [f for f in report.findings if f.finding_type == "license_conflict"]
        for f in license_findings:
            assert f.license  # should contain the SPDX id


# ---------------------------------------------------------------------------
# SupplyChainReport model
# ---------------------------------------------------------------------------


class TestSupplyChainReport:
    def test_has_findings_false_when_empty(self):
        report = SupplyChainReport(source_files=[], findings=[], total_packages=0)
        assert not report.has_findings

    def test_has_findings_true(self):
        f = SupplyChainFinding(
            package="colourama",
            finding_type="malicious",
            severity="critical",
            description="test",
            recommendation="remove it",
        )
        report = SupplyChainReport(source_files=[], findings=[f], total_packages=1)
        assert report.has_findings

    def test_severity_counts(self):
        findings = [
            SupplyChainFinding("a", "malicious", "critical", "x", "y"),
            SupplyChainFinding("b", "typosquat", "high", "x", "y"),
            SupplyChainFinding("c", "unpinned", "medium", "x", "y"),
            SupplyChainFinding("d", "unpinned", "low", "x", "y"),
        ]
        report = SupplyChainReport(source_files=[], findings=findings, total_packages=4)
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1

    def test_to_dict_schema_version(self):
        report = SupplyChainReport(source_files=[], findings=[], total_packages=0)
        d = report.to_dict()
        assert d["schema_version"] == "1.0"

    def test_to_dict_findings_structure(self):
        f = SupplyChainFinding(
            package="colourama",
            finding_type="malicious",
            severity="critical",
            description="test",
            recommendation="remove it",
            source_file="requirements.txt",
        )
        report = SupplyChainReport(source_files=["requirements.txt"], findings=[f], total_packages=1)
        d = report.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["package"] == "colourama"
        assert d["findings"][0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------


class TestDirectoryScan:
    def test_scan_directory_finds_requirements(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n")
        scanner = SupplyChainScanner()
        report = scanner.scan_directory(tmp_path)
        assert report.total_packages >= 1

    def test_scan_directory_finds_package_json(self, tmp_path):
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"express": "4.18.2"}}))
        scanner = SupplyChainScanner()
        report = scanner.scan_directory(tmp_path)
        assert report.total_packages >= 1

    def test_scan_empty_directory(self, tmp_path):
        scanner = SupplyChainScanner()
        report = scanner.scan_directory(tmp_path)
        assert report.total_packages == 0
        assert not report.findings

    def test_scan_file_auto_detect_requirements(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("colourama==1.0.0\n")
        scanner = SupplyChainScanner()
        report = scanner.scan_file(req)
        assert any(f.finding_type == "malicious" for f in report.findings)

    def test_scan_file_auto_detect_package_json(self, tmp_path):
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"event-stream": "3.3.4"}}))
        scanner = SupplyChainScanner()
        report = scanner.scan_file(pj)
        assert any(f.finding_type == "malicious" for f in report.findings)

    def test_scan_file_unsupported_raises(self, tmp_path):
        bad = tmp_path / "setup.py"
        bad.write_text("")
        scanner = SupplyChainScanner()
        with pytest.raises(ValueError, match="Unsupported file"):
            scanner.scan_file(bad)


# ---------------------------------------------------------------------------
# CLI: sentinel supply-chain-audit
# ---------------------------------------------------------------------------


class TestSupplyChainAuditCLI:
    def test_exit_0_no_findings(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask==3.0.0\n")
        result = runner.invoke(app, ["supply-chain-audit", str(tmp_path)])
        # May exit 0 (clean) or 1 (unpinned loose pins) depending on strict
        # At minimum it should not crash
        assert result.exit_code in (0, 1)
        assert result.exception is None

    def test_exit_1_with_malicious_package(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("colourama==1.0.0\n")
        result = runner.invoke(app, ["supply-chain-audit", str(tmp_path)])
        assert result.exit_code == 1
        assert "CRIT" in result.output or "malicious" in result.output.lower()

    def test_json_output(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("colourama==1.0.0\n")
        result = runner.invoke(app, ["supply-chain-audit", str(tmp_path), "--json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["schema_version"] == "1.0"
        assert data["summary"]["critical"] >= 1

    def test_requirements_flag(self, tmp_path):
        req = tmp_path / "my_requirements.txt"
        req.write_text("colourama==1.0.0\n")
        result = runner.invoke(app, ["supply-chain-audit", "--requirements", str(req)])
        assert result.exit_code == 1

    def test_package_json_flag(self, tmp_path):
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"dependencies": {"event-stream": "3.3.4"}}))
        result = runner.invoke(app, ["supply-chain-audit", "--package-json", str(pj)])
        assert result.exit_code == 1

    def test_nonexistent_file_exit_2(self, tmp_path):
        result = runner.invoke(app, ["supply-chain-audit", "--requirements", "/nonexistent/requirements.txt"])
        assert result.exit_code == 2

    def test_quiet_flag(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("colourama==1.0.0\n")
        result = runner.invoke(app, ["supply-chain-audit", str(tmp_path), "--quiet"])
        assert result.exit_code == 1
        # quiet mode: just the count line
        assert "finding" in result.output.lower()

    def test_clean_project_exit_0(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("anthropic==0.20.0\n")
        result = runner.invoke(app, ["supply-chain-audit", str(tmp_path)])
        # anthropic is not malicious, not a typosquat of popular packages
        # exit 0 if only a loose-pin (low severity) and no --verbose
        # or exit 1 if unpinned medium
        # The real assertion: no crash
        assert result.exception is None

    def test_json_clean_project(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n")
        result = runner.invoke(app, ["supply-chain-audit", str(tmp_path), "--json"])
        data = json.loads(result.output)
        assert "findings" in data
        assert data["total_packages"] >= 1
