"""Tests for detector #75: Missing Zero-Amount Validation."""
import json
import subprocess
import sys

SCANNER = "src/scanner.py"
CONTRACT = "test-contracts/zero-amount-test.clar"


def run_scan(contract=CONTRACT, extra_args=None):
    cmd = [sys.executable, SCANNER, contract, "--format", "json"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    report_path = f"findings/{contract.split('/')[-1].replace('.clar', '')}_report.json"
    with open(report_path) as f:
        return json.load(f)


def get_75_findings(data):
    return [f for f in data["findings"] if "Zero-Amount" in f["title"]]


class TestZeroAmountValidation:
    def test_detects_vulnerable_transfer(self):
        """#75 should flag transfer-tokens (no zero check)."""
        data = run_scan()
        titles = [f["title"] for f in get_75_findings(data)]
        assert any("transfer-tokens" in t for t in titles)

    def test_detects_vulnerable_mint(self):
        """#75 should flag mint-tokens (no zero check)."""
        data = run_scan()
        titles = [f["title"] for f in get_75_findings(data)]
        assert any("mint-tokens" in t for t in titles)

    def test_safe_transfer_not_flagged(self):
        """#75 should not flag safe-transfer (has asserts! > amount u0)."""
        data = run_scan()
        titles = [f["title"] for f in get_75_findings(data)]
        assert not any("safe-transfer" in t for t in titles)

    def test_safe_mint_not_flagged(self):
        """#75 should not flag safe-mint (has asserts! >= amount u1)."""
        data = run_scan()
        titles = [f["title"] for f in get_75_findings(data)]
        assert not any("safe-mint" in t for t in titles)

    def test_fixed_amount_not_flagged(self):
        """#75 should not flag fixed-transfer (no amount parameter)."""
        data = run_scan()
        titles = [f["title"] for f in get_75_findings(data)]
        assert not any("fixed-transfer" in t for t in titles)

    def test_finding_count(self):
        """#75 should find exactly 2 vulnerable functions."""
        data = run_scan()
        assert len(get_75_findings(data)) == 2

    def test_severity_is_medium(self):
        """#75 findings should have MEDIUM severity."""
        data = run_scan()
        for f in get_75_findings(data):
            assert f["severity"] == "MEDIUM"

    def test_category_is_input_validation(self):
        """#75 findings should be categorized as Input Validation."""
        data = run_scan()
        for f in get_75_findings(data):
            assert f["category"] == "Input Validation"
