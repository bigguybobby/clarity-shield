"""Tests for detector #90: Unchecked Transfer Return Value — Silent Failure Risk."""
import subprocess, json, os, sys

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'unchecked-transfer-test.clar')


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


def get_90_findings(findings=None):
    """Filter to only detector #90 findings."""
    if findings is None:
        findings = run_scan()
    return [f for f in findings if 'Unchecked Transfer' in f.get('title', '')]


class TestUncheckedTransferReturn:
    """Test #90: Unchecked Transfer Return Value / Silent Failure Risk."""

    def test_detects_unchecked_stx_transfer(self):
        """withdraw-unchecked calls stx-transfer? without checking — should flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert any("withdraw-unchecked" in t for t in flagged_funcs), \
            f"Expected withdraw-unchecked to be flagged. Got: {flagged_funcs}"


    def test_detects_unchecked_nft_transfer(self):
        """claim-nft-unchecked calls nft-transfer? without checking — should flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert any("claim-nft-unchecked" in t for t in flagged_funcs), \
            f"Expected claim-nft-unchecked to be flagged. Got: {flagged_funcs}"

    def test_safe_withdraw_with_try(self):
        """withdraw-safe-try uses try! — should NOT flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("withdraw-safe-try" in t for t in flagged_funcs), \
            f"withdraw-safe-try should not be flagged. Got: {flagged_funcs}"

    def test_safe_escrow_with_unwrap(self):
        """release-escrow-safe-unwrap uses unwrap! — should NOT flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("release-escrow-safe-unwrap" in t for t in flagged_funcs), \
            f"release-escrow-safe-unwrap should not be flagged. Got: {flagged_funcs}"

    def test_safe_claim_with_asserts(self):
        """claim-nft-safe-asserts uses asserts! — should NOT flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("claim-nft-safe-asserts" in t for t in flagged_funcs), \
            f"claim-nft-safe-asserts should not be flagged. Got: {flagged_funcs}"

    def test_safe_withdraw_with_match(self):
        """withdraw-safe-match uses match — should NOT flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("withdraw-safe-match" in t for t in flagged_funcs), \
            f"withdraw-safe-match should not be flagged. Got: {flagged_funcs}"

    def test_safe_withdraw_with_let(self):
        """withdraw-safe-let uses let + asserts! — should NOT flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("withdraw-safe-let" in t for t in flagged_funcs), \
            f"withdraw-safe-let should not be flagged. Got: {flagged_funcs}"

    def test_get_balance_not_flagged(self):
        """get-balance has no transfers — should NOT flag."""
        findings = get_90_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("get-balance" in t for t in flagged_funcs), \
            f"get-balance should not be flagged. Got: {flagged_funcs}"

    def test_finding_severity_is_high(self):
        """Unchecked transfer findings should be HIGH severity."""
        findings = get_90_findings()
        assert len(findings) > 0, "Expected at least one unchecked transfer finding"
        for f in findings:
            assert f['severity'] == 'HIGH', f"Expected HIGH severity, got {f['severity']}"

    def test_finding_has_fund_safety_category(self):
        """Unchecked transfer findings should have Fund Safety category."""
        findings = get_90_findings()
        assert len(findings) > 0
        for f in findings:
            assert f['category'] == 'Fund Safety', f"Expected Fund Safety category, got {f['category']}"

    def test_finding_has_recommendation(self):
        """Findings should include actionable recommendations (try!, unwrap!, etc.)."""
        findings = get_90_findings()
        assert len(findings) > 0
        for f in findings:
            rec = f.get('recommendation', '').lower()
            assert any(keyword in rec for keyword in ['try!', 'unwrap!', 'match', 'asserts!']), \
                f"Recommendation should mention error-checking constructs. Got: {f.get('recommendation', '')}"

    def test_exactly_three_vulnerable_functions(self):
        """Should find exactly 3 vulnerable functions."""
        findings = get_90_findings()
        expected_count = 3
        assert len(findings) == expected_count, \
            f"Expected exactly {expected_count} unchecked transfer findings, got {len(findings)}: {[f['title'] for f in findings]}"
