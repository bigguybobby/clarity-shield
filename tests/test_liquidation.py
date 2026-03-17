"""Tests for detector #88: Unprotected Liquidation — Oracle Manipulation Risk."""
import subprocess, json, os, sys

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'liquidation-test.clar')


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


def get_88_findings(findings=None):
    """Filter to only detector #88 findings."""
    if findings is None:
        findings = run_scan()
    return [f for f in findings if 'Unprotected Liquidation' in f.get('title', '')]


class TestUnprotectedLiquidation:
    """Test #88: Unprotected Liquidation / Oracle Manipulation Risk."""

    def test_detects_vulnerable_liquidate(self):
        """Should flag 'liquidate' — no protections at all."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert any("'liquidate'" in t for t in titles), \
            f"Expected 'liquidate' finding, got: {titles}"

    def test_detects_vulnerable_force_close(self):
        """Should flag 'force-close' — price read but no safeguards."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert any("force-close" in t for t in titles), \
            f"Expected 'force-close' finding, got: {titles}"

    def test_exactly_two_findings(self):
        """Should find exactly 2 vulnerable functions."""
        findings = get_88_findings()
        assert len(findings) == 2, \
            f"Expected 2 findings, got {len(findings)}: {[f['title'] for f in findings]}"

    def test_no_false_positive_deviation_check(self):
        """Should NOT flag function with price deviation threshold."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert not any("deviation-check" in t for t in titles)

    def test_no_false_positive_twap(self):
        """Should NOT flag function with TWAP pricing."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert not any("twap" in t for t in titles)

    def test_no_false_positive_grace_period(self):
        """Should NOT flag function with grace period."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert not any("grace" in t for t in titles)

    def test_no_false_positive_health_factor(self):
        """Should NOT flag function with health factor check."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert not any("healthy-check" in t for t in titles)

    def test_no_false_positive_deposit(self):
        """Should NOT flag non-liquidation functions."""
        findings = get_88_findings()
        titles = [f['title'] for f in findings]
        assert not any("deposit" in t.lower() for t in titles)

    def test_severity_is_high(self):
        """Liquidation without protections should be HIGH severity."""
        findings = get_88_findings()
        for f in findings:
            assert f['severity'] == 'HIGH', f"Expected HIGH, got {f['severity']}"

    def test_category_defi_safety(self):
        """All findings should be in DeFi Safety category."""
        findings = get_88_findings()
        for f in findings:
            assert f.get('category') == 'DeFi Safety', \
                f"Expected 'DeFi Safety' category, got {f.get('category')}"
