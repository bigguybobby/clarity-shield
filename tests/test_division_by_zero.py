"""Test suite for #94 Division by Zero Risk detector."""
import pytest
from pathlib import Path
from src.scanner import ClarityScanner

TEST_CONTRACT = Path(__file__).parent.parent / "test-contracts" / "division-by-zero-test.clar"


def _get_div_zero_findings(scanner):
    findings = scanner.scan()
    return [f for f in findings if f.title == "Division by Zero Risk — Potential DoS"]


def test_detector_catches_division_by_parameter():
    """Should flag public function dividing by a function parameter without zero-check."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    vulnerable_fns = [f.description for f in findings]
    assert any("calculate-share" in d for d in vulnerable_fns), \
        "Should detect calculate-share dividing by unvalidated parameter"


def test_detector_catches_division_by_data_var():
    """Should flag public function dividing by a data-var that could be zero."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    vulnerable_fns = [f.description for f in findings]
    assert any("get-price-per-share" in d for d in vulnerable_fns), \
        "Should detect get-price-per-share dividing by potentially-zero var"


def test_detector_catches_division_by_variable_expression():
    """Should flag division by arithmetic result from a data-var."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    vulnerable_fns = [f.description for f in findings]
    assert any("calculate-reward" in d for d in vulnerable_fns), \
        "Should detect calculate-reward dividing by potentially-zero var-get"


def test_detector_allows_asserts_zero_check():
    """Should NOT flag when denominator is asserted > u0."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "safe-calculate-share" in f.description]
    assert len(false_positive) == 0, "Should not flag function with asserts! zero-check"


def test_detector_allows_if_zero_check():
    """Should NOT flag when zero-case is handled with if/is-eq."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "safe-price-per-share" in f.description]
    assert len(false_positive) == 0, "Should not flag function with if zero-check"


def test_detector_allows_constant_denominator():
    """Should NOT flag division by a literal uint constant."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "calculate-percentage" in f.description]
    assert len(false_positive) == 0, "Should not flag division by constant u100"


def test_detector_ignores_read_only():
    """Should NOT flag read-only functions."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "read-share-price" in f.description]
    assert len(false_positive) == 0, "Should not flag read-only function"


def test_detector_ignores_private():
    """Should NOT flag private functions."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "internal-division" in f.description]
    assert len(false_positive) == 0, "Should not flag private function"


def test_detector_allows_asserts_before_var_division():
    """Should NOT flag when var-get denominator has asserts > u0 guard."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "calculate-fee" in f.description]
    assert len(false_positive) == 0, "Should not flag function with asserts on var-get denom"


def test_no_findings_on_simple_add():
    """Non-relevant function with no division should produce no findings."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    false_positive = [f for f in findings if "simple-add" in f.description]
    assert len(false_positive) == 0, "Should not flag function without division"


def test_finding_severity_is_medium():
    """Division-by-zero findings should be MEDIUM severity."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    assert len(findings) > 0, "Should have at least one finding"
    for f in findings:
        assert f.severity == "MEDIUM", f"Expected MEDIUM severity, got {f.severity}"


def test_finding_category():
    """Division-by-zero findings should be in Arithmetic Safety category."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    findings = _get_div_zero_findings(scanner)

    assert len(findings) > 0
    for f in findings:
        assert f.category == "Arithmetic Safety", f"Expected 'Arithmetic Safety', got {f.category}"
