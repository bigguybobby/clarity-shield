"""Tests for detector #72 — Missing Token Supply Cap."""
import pytest
from pathlib import Path
from src.scanner import ClarityScanner

CONTRACT = str(Path(__file__).resolve().parent.parent / "test-contracts" / "supply-cap-test.clar")


def _get_findings():
    scanner = ClarityScanner(CONTRACT)
    scanner.scan()
    return scanner.findings


def _findings_72():
    return [f for f in _get_findings() if f.title.startswith("Uncapped Token Minting")]


def test_detects_uncapped_mint():
    """mint-uncapped (has auth but no cap) should trigger #72."""
    titles = [f.title for f in _findings_72()]
    assert any("mint-uncapped" in t for t in titles), f"Expected mint-uncapped finding, got {titles}"


def test_detects_claim_airdrop():
    """claim-airdrop (no auth AND no cap) should trigger #72."""
    titles = [f.title for f in _findings_72()]
    assert any("claim-airdrop" in t for t in titles), f"Expected claim-airdrop finding, got {titles}"


def test_no_false_positive_capped_mint():
    """mint-capped uses MAX-SUPPLY check — should NOT trigger."""
    titles = [f.title for f in _findings_72()]
    assert not any("mint-capped" in t for t in titles), f"False positive on capped mint: {titles}"


def test_no_false_positive_cap_keyword():
    """mint-with-cap-keyword uses supply-cap variable — should NOT trigger."""
    titles = [f.title for f in _findings_72()]
    assert not any("mint-with-cap-keyword" in t for t in titles), f"False positive on cap keyword: {titles}"


def test_exactly_two_findings():
    """Exactly 2 supply-cap findings expected."""
    findings = _findings_72()
    assert len(findings) == 2, f"Expected 2, got {len(findings)}: {[f.title for f in findings]}"


def test_severity_is_high():
    """All supply-cap findings should be HIGH severity."""
    for f in _findings_72():
        assert f.severity == "HIGH", f"Expected HIGH, got {f.severity.value} for {f.title}"


def test_category_is_economic_safety():
    """Findings should be in the Economic Safety category."""
    for f in _findings_72():
        assert f.category == "Economic Safety", f"Wrong category: {f.category}"
