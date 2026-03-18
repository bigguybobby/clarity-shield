"""Test suite for #92 Unvalidated Oracle Price Update detector."""
import pytest
from pathlib import Path
from src.scanner import ClarityScanner

TEST_CONTRACT = Path(__file__).parent.parent / "test-contracts" / "oracle-update-test.clar"


def test_detector_catches_vulnerable_direct_update():
    """Detector should flag set-price with no controls."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    vulnerable = [f for f in findings if f.title == "Unvalidated Oracle Price Update"
                  and "set-price" in f.description]
    assert len(vulnerable) >= 1, "Should detect direct price update without controls"


def test_detector_catches_vulnerable_owner_only_update():
    """Detector should flag update-btc-price with owner check but no bounds."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    vulnerable = [f for f in findings if f.title == "Unvalidated Oracle Price Update"
                  and "update-btc-price" in f.description]
    assert len(vulnerable) >= 1, "Should detect owner-only update without deviation bounds"


def test_detector_allows_deviation_bounds():
    """Detector should NOT flag update-price-with-bounds (has MAX-DEVIATION check)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    false_positive = [f for f in findings if f.title == "Unvalidated Oracle Price Update"
                      and "update-price-with-bounds" in f.description]
    assert len(false_positive) == 0, "Should not flag price update with deviation bounds"


def test_detector_allows_timelock():
    """Detector should NOT flag propose-price/execute-price-update (timelock pattern)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    false_positive = [f for f in findings if f.title == "Unvalidated Oracle Price Update"
                      and ("propose-price" in f.description or "execute-price-update" in f.description)]
    assert len(false_positive) == 0, "Should not flag timelock-protected updates"


def test_detector_allows_multisig():
    """Detector should NOT flag confirm-price-update (multi-sig confirmations)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    false_positive = [f for f in findings if f.title == "Unvalidated Oracle Price Update"
                      and "confirm-price-update" in f.description]
    assert len(false_positive) == 0, "Should not flag multi-sig protected updates"


def test_detector_ignores_non_oracle_setters():
    """Detector should NOT flag set-balance (not oracle-related)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    false_positive = [f for f in findings if f.title == "Unvalidated Oracle Price Update"
                      and "set-balance" in f.description]
    assert len(false_positive) == 0, "Should not flag non-oracle setters"


def test_severity_is_high():
    """Oracle manipulation should be HIGH severity."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    oracle_findings = [f for f in findings if f.title == "Unvalidated Oracle Price Update"]
    assert all(f.severity == "HIGH" for f in oracle_findings), "Should be HIGH severity"


def test_category_is_oracle_safety():
    """Findings should be categorized as Oracle Safety."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    oracle_findings = [f for f in findings if f.title == "Unvalidated Oracle Price Update"]
    assert all(f.category == "Oracle Safety" for f in oracle_findings), "Should be Oracle Safety category"


def test_exactly_two_vulnerable_functions():
    """Should find exactly 2 vulnerable functions: set-price + update-btc-price."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = scanner.scan()
    
    vulnerable = [f for f in findings if f.title == "Unvalidated Oracle Price Update"]
    assert len(vulnerable) == 2, f"Should find exactly 2 vulnerable functions, found {len(vulnerable)}"
