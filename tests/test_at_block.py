"""Test suite for #93 Unsafe at-block Usage detector."""
import pytest
from pathlib import Path
from src.scanner import ClarityScanner

TEST_CONTRACT = Path(__file__).parent.parent / "test-contracts" / "at-block-test.clar"


def _get_at_block_findings(scanner):
    findings = scanner.scan()
    return [f for f in findings if f.title == "Unsafe at-block with User-Supplied Hash"]


def test_detector_catches_unvalidated_at_block():
    """Should flag public function using at-block with raw user-supplied hash."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    vulnerable_names = [f.description for f in at_block]
    assert any("get-historical-balance" in d for d in vulnerable_names), \
        "Should detect get-historical-balance using unvalidated at-block"


def test_detector_catches_price_lookup_at_block():
    """Should flag get-past-price using at-block with user hash."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    vulnerable_names = [f.description for f in at_block]
    assert any("get-past-price" in d for d in vulnerable_names), \
        "Should detect get-past-price using unvalidated at-block"


def test_detector_allows_trusted_hash():
    """Should NOT flag at-block using var-get (trusted source)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    false_positive = [f for f in at_block if "get-snapshot-balance" in f.description]
    assert len(false_positive) == 0, "Should not flag at-block with var-get trusted hash"


def test_detector_ignores_read_only():
    """Should NOT flag read-only functions (they can't mutate state)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    false_positive = [f for f in at_block if "read-historical-balance" in f.description]
    assert len(false_positive) == 0, "Should not flag read-only function"


def test_detector_ignores_private():
    """Should NOT flag private functions (not externally callable)."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    false_positive = [f for f in at_block if "internal-lookup" in f.description]
    assert len(false_positive) == 0, "Should not flag private function"


def test_detector_allows_validated_block_height():
    """Should NOT flag at-block with block height validation."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    false_positive = [f for f in at_block if "get-recent-balance" in f.description]
    assert len(false_positive) == 0, "Should not flag at-block with height validation"


def test_detector_ignores_non_at_block():
    """Should NOT flag functions without at-block."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    false_positive = [f for f in at_block if "simple-transfer" in f.description]
    assert len(false_positive) == 0, "Should not flag functions without at-block"


def test_severity_is_medium():
    """at-block findings should be MEDIUM severity."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    assert all(f.severity == "MEDIUM" for f in at_block), "Should be MEDIUM severity"


def test_category_is_state_safety():
    """Findings should be categorized as State Safety."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    assert all(f.category == "State Safety" for f in at_block), "Should be State Safety category"


def test_exactly_two_vulnerable_functions():
    """Should find exactly 2 vulnerable functions."""
    scanner = ClarityScanner(str(TEST_CONTRACT))
    at_block = _get_at_block_findings(scanner)

    assert len(at_block) == 2, f"Should find exactly 2 vulnerable functions, found {len(at_block)}"
