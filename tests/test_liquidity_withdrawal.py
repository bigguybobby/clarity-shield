"""Tests for detector #81: Unprotected Liquidity Withdrawal."""
import json
import subprocess
import sys

SCANNER = "src/scanner.py"
CONTRACT = "test-contracts/liquidity-withdrawal-test.clar"


def run_scan(contract=CONTRACT, extra_args=None):
    cmd = [sys.executable, SCANNER, contract, "-f", "json", "--no-save"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)


def get_findings(data):
    return [f for f in data["findings"]
            if "Unprotected Liquidity Withdrawal" in f.get("title", "")]


class TestUnprotectedLiquidityWithdrawal:
    """Detector #81 — Unprotected Liquidity Withdrawal."""

    def test_detects_unprotected_withdraw_liquidity(self):
        data = run_scan()
        findings = get_findings(data)
        titles = [f["title"] for f in findings]
        assert any("withdraw-liquidity" in t for t in titles), \
            f"Should flag withdraw-liquidity. Got: {titles}"

    def test_detects_emergency_withdraw(self):
        data = run_scan()
        findings = get_findings(data)
        titles = [f["title"] for f in findings]
        assert any("emergency-withdraw" in t for t in titles), \
            f"Should flag emergency-withdraw. Got: {titles}"

    def test_safe_proportional_lp_burn(self):
        data = run_scan()
        findings = get_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("remove-liquidity" in t for t in titles), \
            "Should NOT flag remove-liquidity (has LP token burn)"

    def test_safe_timelock_withdrawal(self):
        data = run_scan()
        findings = get_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("withdraw-pool" in t for t in titles), \
            "Should NOT flag withdraw-pool (has timelock)"

    def test_safe_multisig_withdrawal(self):
        data = run_scan()
        findings = get_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("admin-withdraw" in t for t in titles), \
            "Should NOT flag admin-withdraw (has multi-sig)"

    def test_finding_severity_is_high(self):
        data = run_scan()
        findings = get_findings(data)
        for f in findings:
            assert f["severity"] == "HIGH", \
                f"Expected HIGH severity, got {f['severity']}"

    def test_finding_category_is_defi_safety(self):
        data = run_scan()
        findings = get_findings(data)
        for f in findings:
            assert f["category"] == "DeFi Safety", \
                f"Expected DeFi Safety, got {f['category']}"

    def test_exactly_two_findings(self):
        data = run_scan()
        findings = get_findings(data)
        assert len(findings) == 2, \
            f"Expected 2 findings, got {len(findings)}: {[f['title'] for f in findings]}"
