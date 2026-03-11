"""Tests for detector #73 — Uncapped NFT Minting."""
import json
import subprocess
import sys
import os

import pytest

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'nft-mint-cap-test.clar')


def _scan_json(contract=CONTRACT):
    """Run the scanner and return parsed JSON findings."""
    result = subprocess.run(
        [sys.executable, SCANNER, contract, '--format', 'json'],
        capture_output=True, text=True
    )
    report_path = os.path.join(
        os.path.dirname(SCANNER), '..', 'findings',
        os.path.basename(contract).replace('.clar', '_report.json')
    )
    with open(report_path) as f:
        return json.load(f)


def _nft_cap_findings(data):
    return [f for f in data['findings'] if 'Uncapped NFT Minting' in f['title']]


class TestUncappedNftMinting:
    """Detector #73: Uncapped NFT Minting."""

    @pytest.fixture(autouse=True)
    def scan(self):
        self.data = _scan_json()
        self.nft_findings = _nft_cap_findings(self.data)

    def test_detects_vulnerable_mint_free(self):
        titles = [f['title'] for f in self.nft_findings]
        assert any("mint-free" in t for t in titles), \
            "Should detect uncapped nft-mint? in mint-free"

    def test_detects_vulnerable_admin_mint(self):
        titles = [f['title'] for f in self.nft_findings]
        assert any("admin-mint" in t for t in titles), \
            "Should detect uncapped nft-mint? in admin-mint"

    def test_ignores_capped_mint(self):
        titles = [f['title'] for f in self.nft_findings]
        assert not any("mint-capped" in t for t in titles), \
            "Should NOT flag mint-capped (has MAX-SUPPLY check)"

    def test_ignores_limited_mint(self):
        titles = [f['title'] for f in self.nft_findings]
        assert not any("mint-limited" in t for t in titles), \
            "Should NOT flag mint-limited (has per-address limit)"

    def test_finding_count(self):
        assert len(self.nft_findings) == 2, \
            f"Expected exactly 2 uncapped NFT findings, got {len(self.nft_findings)}"

    def test_severity_is_high(self):
        for f in self.nft_findings:
            assert f['severity'] == 'HIGH', \
                f"Uncapped NFT minting should be HIGH severity, got {f['severity']}"

    def test_category_is_economic_safety(self):
        for f in self.nft_findings:
            assert f['category'] == 'Economic Safety', \
                f"Expected 'Economic Safety' category, got {f['category']}"

    def test_no_ft_supply_cap_false_positive(self):
        """Detector #72 should NOT fire on nft-mint? contracts (regression)."""
        ft_findings = [f for f in self.data['findings'] if 'Uncapped Token Minting' in f['title']]
        assert len(ft_findings) == 0, \
            f"Detector #72 should not flag nft-mint? as ft-mint?. Got: {ft_findings}"
