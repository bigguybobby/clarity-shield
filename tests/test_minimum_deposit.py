"""Tests for detector #85 — Missing Minimum Deposit Amount"""
import json
import subprocess
import sys
import os
import pytest

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'minimum-deposit-test.clar')


def run_scan(contract_path=CONTRACT, extra_args=None):
    """Run the scanner and return parsed JSON findings."""
    cmd = [sys.executable, SCANNER, contract_path, '--format', 'json']
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    # Read report from file
    stem = os.path.splitext(os.path.basename(contract_path))[0]
    report_path = os.path.join(os.path.dirname(SCANNER), '..', 'findings', f'{stem}_report.json')
    with open(report_path) as f:
        data = json.load(f)
    return data['findings']


def get_85_findings(findings):
    """Filter to only detector #85 findings."""
    return [f for f in findings if 'Minimum Deposit' in f['title']]


class TestMinimumDepositDetector:
    """Test suite for Missing Minimum Deposit Amount detector (#85)."""

    def test_detects_vulnerable_deposit(self):
        """Deposit without min check should be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert any("'deposit'" in t for t in titles), "Should flag unprotected deposit"

    def test_detects_vulnerable_stake(self):
        """Stake without min check should be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert any("'stake'" in t for t in titles), "Should flag unprotected stake"

    def test_detects_vulnerable_add_liquidity(self):
        """add-liquidity without min check should be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert any("'add-liquidity'" in t for t in titles), "Should flag unprotected add-liquidity"

    def test_safe_deposit_not_flagged(self):
        """deposit-safe with MIN-DEPOSIT constant should not be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert not any("'deposit-safe'" in t for t in titles), "Should not flag deposit-safe"

    def test_safe_stake_not_flagged(self):
        """stake-safe with min-stake check should not be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert not any("'stake-safe'" in t for t in titles), "Should not flag stake-safe"

    def test_safe_provide_liquidity_not_flagged(self):
        """provide-liquidity with >= u100000 check should not be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert not any("'provide-liquidity'" in t for t in titles), "Should not flag provide-liquidity"

    def test_non_deposit_function_not_flagged(self):
        """transfer-tokens (not a deposit function) should not be flagged."""
        findings = get_85_findings(run_scan())
        titles = [f['title'] for f in findings]
        assert not any("'transfer-tokens'" in t for t in titles), "Should not flag transfer-tokens"

    def test_severity_is_medium(self):
        """All #85 findings should be MEDIUM severity."""
        findings = get_85_findings(run_scan())
        for f in findings:
            assert f['severity'] == 'MEDIUM', f"Expected MEDIUM, got {f['severity']}"

    def test_category_is_defi_safety(self):
        """All #85 findings should be in DeFi Safety category."""
        findings = get_85_findings(run_scan())
        for f in findings:
            assert f['category'] == 'DeFi Safety', f"Expected DeFi Safety, got {f['category']}"

    def test_exactly_three_findings(self):
        """Should find exactly 3 vulnerable functions in test contract."""
        findings = get_85_findings(run_scan())
        assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}: {[f['title'] for f in findings]}"
