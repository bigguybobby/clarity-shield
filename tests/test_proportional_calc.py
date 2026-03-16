"""Tests for #86 Unsafe Proportional Calculation detector."""
import subprocess, json, os, sys

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'proportional-calc-test.clar')


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


def get_86_findings(findings=None):
    """Filter to only detector #86 findings."""
    if findings is None:
        findings = run_scan()
    return [f for f in findings if 'Proportional Calculation' in f.get('title', '')]


class TestUnsafeProportionalCalc:
    """Test #86: Unsafe Proportional Calculation / Division by Zero Risk."""

    def test_detects_division_by_var_get_total_deposits(self):
        """Should flag deposit-shares: divides by var-get total-deposits without zero check."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert any('deposit-shares' in t for t in names), \
            f"Expected finding for 'deposit-shares', got: {names}"

    def test_detects_division_by_ft_get_supply(self):
        """Should flag calculate-reward: divides by ft-get-supply without zero check."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert any('calculate-reward' in t for t in names), \
            f"Expected finding for 'calculate-reward', got: {names}"

    def test_detects_division_by_var_get_total_staked(self):
        """Should flag claim-proportional: divides by var-get total-staked without zero check."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert any('claim-proportional' in t for t in names), \
            f"Expected finding for 'claim-proportional', got: {names}"

    def test_safe_with_asserts_zero_check(self):
        """Should NOT flag safe-deposit: has asserts! (> ... u0) guard."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert not any('safe-deposit' in t and 'safe-deposit-with-branch' not in t
                       for t in names), \
            f"Unexpected finding for 'safe-deposit': {names}"

    def test_safe_with_if_branch(self):
        """Should NOT flag safe-deposit-with-branch: has if (is-eq ... u0) branch."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert not any('safe-deposit-with-branch' in t for t in names), \
            f"Unexpected finding for 'safe-deposit-with-branch': {names}"

    def test_safe_division_by_constant(self):
        """Should NOT flag calculate-fee: divides by constant u1000, not a var."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert not any('calculate-fee' in t for t in names), \
            f"Unexpected finding for 'calculate-fee': {names}"

    def test_no_division_function_ignored(self):
        """Should NOT flag simple-transfer: no division at all."""
        findings = get_86_findings()
        names = [f['title'] for f in findings]
        assert not any('simple-transfer' in t for t in names), \
            f"Unexpected finding for 'simple-transfer': {names}"

    def test_severity_is_high(self):
        """Division by zero in DeFi proportional calcs should be HIGH severity."""
        findings = get_86_findings()
        assert len(findings) > 0, "Expected at least one finding"
        for f in findings:
            assert f['severity'] == 'HIGH', \
                f"Expected HIGH severity, got {f['severity']} for {f['title']}"

    def test_category_is_defi_safety(self):
        """Category should be DeFi Safety."""
        findings = get_86_findings()
        assert len(findings) > 0, "Expected at least one finding"
        for f in findings:
            assert f['category'] == 'DeFi Safety', \
                f"Expected 'DeFi Safety' category, got {f['category']} for {f['title']}"

    def test_exactly_three_vulnerable_functions(self):
        """Should detect exactly 3 vulnerable functions."""
        findings = get_86_findings()
        assert len(findings) == 3, \
            f"Expected 3 findings, got {len(findings)}: {[f['title'] for f in findings]}"
