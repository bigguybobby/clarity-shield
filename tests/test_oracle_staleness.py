"""Tests for detector #80: Stale Oracle Price Dependency."""
import json
import subprocess
import sys

SCANNER = "src/scanner.py"
CONTRACT = "test-contracts/oracle-staleness-test.clar"


def run_scan(contract=CONTRACT, extra_args=None):
    cmd = [sys.executable, SCANNER, contract, "-f", "json", "--no-save"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)


def get_oracle_findings(data):
    return [f for f in data["findings"]
            if f.get("category") == "Oracle Safety"
            and "Stale Oracle Price" in f.get("title", "")]


class TestStaleOraclePriceDependency:
    """Detector #80 — Stale Oracle Price Dependency."""

    def test_detects_oracle_call_without_freshness(self):
        """Should flag external oracle call without staleness check."""
        data = run_scan()
        findings = get_oracle_findings(data)
        titles = [f["title"] for f in findings]
        assert any("liquidate-position" in t for t in titles), f"Expected liquidate-position finding, got: {titles}"

    def test_detects_price_var_without_freshness(self):
        """Should flag price variable read in financial op without staleness check."""
        data = run_scan()
        findings = get_oracle_findings(data)
        titles = [f["title"] for f in findings]
        assert any("borrow-against-collateral" in t for t in titles), f"Expected borrow-against-collateral finding, got: {titles}"

    def test_safe_oracle_with_block_height_check(self):
        """Should NOT flag oracle call with block-height freshness validation."""
        data = run_scan()
        findings = get_oracle_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("safe-liquidate" in t for t in titles), f"False positive on safe-liquidate: {titles}"

    def test_safe_with_staleness_check(self):
        """Should NOT flag price read with staleness/age check."""
        data = run_scan()
        findings = get_oracle_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("safe-borrow" in t for t in titles), f"False positive on safe-borrow: {titles}"

    def test_safe_read_only_price_no_financial_op(self):
        """Should NOT flag price variable read without financial operations."""
        data = run_scan()
        findings = get_oracle_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("check-price-info" in t for t in titles), f"False positive on check-price-info: {titles}"

    def test_finding_has_oracle_safety_category(self):
        """Findings should have Oracle Safety category."""
        data = run_scan()
        findings = get_oracle_findings(data)
        assert len(findings) > 0
        for f in findings:
            assert f["category"] == "Oracle Safety"

    def test_finding_has_remediation(self):
        """Findings should include remediation guidance."""
        data = run_scan()
        findings = get_oracle_findings(data)
        assert len(findings) > 0
        for f in findings:
            rec = f["recommendation"].lower()
            assert "staleness" in rec or "freshness" in rec, f"Missing remediation: {f['recommendation']}"

    def test_correct_total_findings(self):
        """Should detect exactly 2 vulnerable functions."""
        data = run_scan()
        findings = get_oracle_findings(data)
        assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}: {[f['title'] for f in findings]}"
