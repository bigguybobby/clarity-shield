"""Tests for #87 Missing Withdrawal Cooldown detector."""
import subprocess, json, os, sys

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'withdrawal-cooldown-test.clar')


def run_scan(contract_path=CONTRACT, extra_args=None):
    """Run the scanner and return parsed JSON findings."""
    cmd = [sys.executable, SCANNER, contract_path, '--format', 'json']
    if extra_args:
        cmd.extend(extra_args)
    subprocess.run(cmd, capture_output=True, text=True)
    stem = os.path.splitext(os.path.basename(contract_path))[0]
    report_path = os.path.join(os.path.dirname(SCANNER), '..', 'findings', f'{stem}_report.json')
    with open(report_path) as f:
        data = json.load(f)
    return data['findings']


def get_87_findings(findings=None):
    """Filter to only detector #87 findings."""
    if findings is None:
        findings = run_scan()
    return [f for f in findings if 'Cooldown' in f.get('title', '')]


class TestMissingWithdrawalCooldown:
    """Test #87: Missing Withdrawal Cooldown / Flash Deposit Attack Risk."""

    def test_detects_vulnerable_withdraw(self):
        """Should flag 'withdraw' — no cooldown, transfers STX."""
        findings = get_87_findings()
        titles = [f['title'] for f in findings]
        assert any("withdraw" in t.lower() and "Cooldown" in t for t in titles), \
            f"Expected finding for 'withdraw', got: {titles}"

    def test_detects_vulnerable_unstake(self):
        """Should flag 'unstake' — stores deposit-block but never checks it."""
        findings = get_87_findings()
        titles = [f['title'] for f in findings]
        assert any("unstake" in t.lower() and "Cooldown" in t for t in titles), \
            f"Expected finding for 'unstake', got: {titles}"

    def test_safe_exit_pool_not_flagged(self):
        """Should NOT flag 'exit-pool' — has block-height cooldown check."""
        findings = get_87_findings()
        titles = [f['title'] for f in findings]
        assert not any("exit-pool" in t.lower() for t in titles), \
            f"exit-pool should be safe, got: {titles}"

    def test_safe_redeem_not_flagged(self):
        """Should NOT flag 'redeem' — references cooldown-blocks variable."""
        findings = get_87_findings()
        titles = [f['title'] for f in findings]
        assert not any("'redeem'" in t.lower() for t in titles), \
            f"redeem should be safe, got: {titles}"

    def test_safe_remove_liquidity_not_flagged(self):
        """Should NOT flag 'remove-liquidity' — has lock-period constant."""
        findings = get_87_findings()
        titles = [f['title'] for f in findings]
        assert not any("remove-liquidity" in t.lower() for t in titles), \
            f"remove-liquidity should be safe, got: {titles}"

    def test_safe_claim_and_withdraw_not_flagged(self):
        """Should NOT flag 'claim-and-withdraw' — has unbonding check."""
        findings = get_87_findings()
        titles = [f['title'] for f in findings]
        assert not any("claim-and-withdraw" in t.lower() for t in titles), \
            f"claim-and-withdraw should be safe, got: {titles}"

    def test_exactly_two_findings(self):
        """Should find exactly 2 vulnerable functions."""
        findings = get_87_findings()
        assert len(findings) == 2, \
            f"Expected 2 findings, got {len(findings)}: {[f['title'] for f in findings]}"

    def test_severity_is_high(self):
        """All findings should be HIGH severity."""
        findings = get_87_findings()
        for f in findings:
            assert f['severity'] == 'HIGH', f"Expected HIGH, got {f['severity']}"

    def test_category_is_defi_safety(self):
        """All findings should be in DeFi Safety category."""
        findings = get_87_findings()
        for f in findings:
            assert f['category'] == 'DeFi Safety', f"Expected DeFi Safety, got {f['category']}"

    def test_recommendation_mentions_block_height(self):
        """Recommendations should mention block-height."""
        findings = get_87_findings()
        for f in findings:
            assert 'block-height' in f['recommendation'], \
                f"Should mention block-height: {f['recommendation']}"
