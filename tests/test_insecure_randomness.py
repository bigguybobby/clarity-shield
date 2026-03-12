"""Tests for Insecure Randomness detector (#76)."""
import json
import subprocess
import sys

import pytest

CONTRACT = "test-contracts/insecure-randomness-test.clar"
SCANNER = "src/scanner.py"


def _run_scan(contract=CONTRACT, fmt="json"):
    result = subprocess.run(
        [sys.executable, SCANNER, contract, "--format", fmt],
        capture_output=True, text=True
    )
    return result


def _get_findings(contract=CONTRACT):
    result = _run_scan(contract, "json")
    report_path = f"findings/{contract.split('/')[-1].replace('.clar', '')}_report.json"
    with open(report_path) as f:
        return json.load(f)["findings"]


def _rng_findings(contract=CONTRACT):
    return [f for f in _get_findings(contract) if f["category"] == "Randomness"]


class TestInsecureRandomness:
    """Detector #76 — Insecure Randomness Source."""

    def test_detects_block_height_mod(self):
        """Should flag pick-winner using block-height + mod."""
        findings = _rng_findings()
        matched = [f for f in findings if "pick-winner" in f["title"]]
        assert len(matched) == 1
        assert matched[0]["severity"] == "HIGH"
        assert "block-height" in matched[0]["description"]

    def test_detects_burn_block_hash(self):
        """Should flag mint-random-nft using burn-block-height + sha256."""
        findings = _rng_findings()
        matched = [f for f in findings if "mint-random-nft" in f["title"]]
        assert len(matched) == 1
        assert matched[0]["severity"] == "HIGH"
        assert "burn-block-height" in matched[0]["description"]

    def test_safe_vrf_not_flagged(self):
        """Should NOT flag pick-winner-vrf (uses VRF marker)."""
        findings = _rng_findings()
        matched = [f for f in findings if "vrf" in f["title"].lower()]
        assert len(matched) == 0

    def test_safe_time_check_not_flagged(self):
        """Should NOT flag check-unlock (block-height without mod/hash)."""
        findings = _rng_findings()
        matched = [f for f in findings if "check-unlock" in f["title"]]
        assert len(matched) == 0

    def test_safe_commit_reveal_not_flagged(self):
        """Should NOT flag reveal-commit-reveal (no on-chain source for randomness)."""
        findings = _rng_findings()
        matched = [f for f in findings if "reveal" in f["title"].lower()]
        assert len(matched) == 0

    def test_finding_count(self):
        """Exactly 2 insecure randomness findings expected."""
        findings = _rng_findings()
        assert len(findings) == 2

    def test_recommendation_mentions_vrf(self):
        """Recommendation should suggest VRF or commit-reveal."""
        findings = _rng_findings()
        for f in findings:
            rec = f["recommendation"].lower()
            assert "vrf" in rec or "commit-reveal" in rec

    def test_category_is_randomness(self):
        """All findings should be in 'Randomness' category."""
        findings = _rng_findings()
        for f in findings:
            assert f["category"] == "Randomness"
