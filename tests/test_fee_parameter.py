"""Tests for detector #78: Unvalidated Fee/Percentage Parameters."""
import json
import subprocess
import sys

SCANNER = "src/scanner.py"
CONTRACT = "test-contracts/fee-param-test.clar"


def run_scan(contract=CONTRACT, extra_args=None):
    cmd = [sys.executable, SCANNER, contract, "-f", "json", "--no-save"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)


def get_fee_findings(data):
    return [f for f in data["findings"] if "Unvalidated Fee" in f["title"]]


class TestUnvalidatedFeeParameter:
    """Detector #78 — Unvalidated Fee/Rate Parameter."""

    def test_detects_unbounded_fee_percent(self):
        data = run_scan()
        fees = get_fee_findings(data)
        names = [f["title"] for f in fees]
        assert any("fee-percent" in n and "swap-with-fee" in n for n in names)

    def test_detects_unbounded_rate_setter(self):
        data = run_scan()
        fees = get_fee_findings(data)
        names = [f["title"] for f in fees]
        assert any("new-rate" in n and "set-commission-rate" in n for n in names)

    def test_skips_bounded_fee_bps(self):
        """swap-with-bounded-fee has asserts! (<= fee-bps ...) — should not flag."""
        data = run_scan()
        fees = get_fee_findings(data)
        names = [f["title"] for f in fees]
        assert not any("swap-with-bounded-fee" in n for n in names)

    def test_skips_bounded_percentage(self):
        """set-reward-percentage has asserts! (< percentage ...) — should not flag."""
        data = run_scan()
        fees = get_fee_findings(data)
        names = [f["title"] for f in fees]
        assert not any("set-reward-percentage" in n for n in names)

    def test_skips_non_fee_params(self):
        """transfer-fixed has 'amount' param but no fee keywords — should not flag."""
        data = run_scan()
        fees = get_fee_findings(data)
        names = [f["title"] for f in fees]
        assert not any("transfer-fixed" in n for n in names)

    def test_finding_severity_is_high(self):
        data = run_scan()
        fees = get_fee_findings(data)
        assert len(fees) > 0
        for f in fees:
            assert f["severity"] == "HIGH"

    def test_finding_category_is_input_validation(self):
        data = run_scan()
        fees = get_fee_findings(data)
        assert len(fees) > 0
        for f in fees:
            assert f["category"] == "Input Validation"

    def test_exactly_two_findings(self):
        """Should flag exactly 2 vulnerable functions in the test contract."""
        data = run_scan()
        fees = get_fee_findings(data)
        assert len(fees) == 2
