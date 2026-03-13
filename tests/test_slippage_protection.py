"""Tests for detector #79: Missing Slippage Protection."""
import json
import subprocess
import sys

SCANNER = "src/scanner.py"
CONTRACT = "test-contracts/slippage-test.clar"


def run_scan(contract=CONTRACT, extra_args=None):
    cmd = [sys.executable, SCANNER, contract, "-f", "json", "--no-save"]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)


def get_slippage_findings(data):
    return [f for f in data["findings"]
            if f.get("category") == "DEX Safety"
            and "Missing Slippage Protection" in f.get("title", "")]


class TestMissingSlippageProtection:
    """Detector #79 — Missing Slippage Protection."""

    def test_detects_swap_without_slippage(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        titles = [f["title"] for f in findings]
        assert any("swap-x-for-y" in t for t in titles), \
            f"Should detect unprotected swap-x-for-y; got: {titles}"

    def test_detects_exchange_without_slippage(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        titles = [f["title"] for f in findings]
        assert any("exchange-tokens" in t for t in titles), \
            f"Should detect unprotected exchange-tokens; got: {titles}"

    def test_safe_swap_with_min_out(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("swap-with-min-out" in t for t in titles), \
            "Should NOT flag swap-with-min-out (has min-amount-out)"

    def test_safe_trade_with_slippage(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("trade-with-slippage" in t for t in titles), \
            "Should NOT flag trade-with-slippage (has slippage param)"

    def test_non_swap_not_flagged(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        titles = [f["title"] for f in findings]
        assert not any("deposit" in t for t in titles), \
            "Should NOT flag non-swap function 'deposit'"

    def test_severity_is_high(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        assert len(findings) > 0, "Should find at least one slippage issue"
        for f in findings:
            assert f["severity"] == "HIGH"

    def test_category_is_dex_safety(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        assert len(findings) > 0
        for f in findings:
            assert f["category"] == "DEX Safety"

    def test_exactly_two_vulnerable(self):
        data = run_scan()
        findings = get_slippage_findings(data)
        assert len(findings) == 2, \
            f"Expected 2 findings (swap-x-for-y + exchange-tokens), got {len(findings)}"
