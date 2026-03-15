"""Tests for detector #83: Mutable Token Metadata"""
import json
import subprocess
import sys

import pytest

SCANNER = "src/scanner.py"
VULN_CONTRACT = "test-contracts/mutable-metadata-test.clar"
SAFE_CONTRACT = "test-contracts/immutable-metadata-test.clar"


def run_scan(contract, extra_args=None):
    cmd = [sys.executable, SCANNER, contract, "--format", "json", "--no-save"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)


def get_mutable_findings(report):
    return [f for f in report["findings"] if "Mutable Token Metadata" in f["title"]]


class TestMutableTokenMetadata:
    def test_detects_mutable_get_name(self):
        report = run_scan(VULN_CONTRACT)
        titles = [f["title"] for f in get_mutable_findings(report)]
        assert any("get-name" in t for t in titles), f"Expected get-name finding, got: {titles}"

    def test_detects_mutable_get_symbol(self):
        report = run_scan(VULN_CONTRACT)
        titles = [f["title"] for f in get_mutable_findings(report)]
        assert any("get-symbol" in t for t in titles), f"Expected get-symbol finding, got: {titles}"

    def test_detects_mutable_get_decimals(self):
        report = run_scan(VULN_CONTRACT)
        titles = [f["title"] for f in get_mutable_findings(report)]
        assert any("get-decimals" in t for t in titles), f"Expected get-decimals finding, got: {titles}"

    def test_detects_mutable_get_token_uri(self):
        report = run_scan(VULN_CONTRACT)
        titles = [f["title"] for f in get_mutable_findings(report)]
        assert any("get-token-uri" in t for t in titles), f"Expected get-token-uri finding, got: {titles}"

    def test_all_four_metadata_functions_flagged(self):
        report = run_scan(VULN_CONTRACT)
        findings = get_mutable_findings(report)
        assert len(findings) == 4, f"Expected 4 mutable metadata findings, got {len(findings)}"

    def test_severity_is_medium(self):
        report = run_scan(VULN_CONTRACT)
        findings = get_mutable_findings(report)
        for f in findings:
            assert f["severity"] == "MEDIUM", f"Expected MEDIUM severity, got {f['severity']}"

    def test_category_is_token_safety(self):
        report = run_scan(VULN_CONTRACT)
        findings = get_mutable_findings(report)
        for f in findings:
            assert f["category"] == "Token Safety", f"Expected Token Safety category, got {f['category']}"

    def test_no_false_positive_on_constant_metadata(self):
        report = run_scan(SAFE_CONTRACT)
        findings = get_mutable_findings(report)
        assert len(findings) == 0, f"Expected 0 findings on safe contract, got {len(findings)}"

    def test_confirms_setter_exists(self):
        """Findings for vars with setters should note the setter exists."""
        report = run_scan(VULN_CONTRACT)
        name_finding = [f for f in get_mutable_findings(report) if "get-name" in f["title"]][0]
        assert "var-set" in name_finding["description"], "Should mention var-set exists for token-name"
