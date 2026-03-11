"""Tests for SIP-013 semi-fungible token compliance detector (#71)"""
import pytest
from pathlib import Path
from src.scanner import ClarityScanner

TEST_DIR = Path(__file__).parent.parent / "test-contracts"


class TestSIP013Compliance:
    """SIP-013 Semi-Fungible Token compliance checks"""

    def test_incomplete_sft_flags_missing_functions(self):
        """Incomplete SFT should flag missing SIP-013 functions"""
        scanner = ClarityScanner(str(TEST_DIR / "sip013-incomplete.clar"))
        findings = scanner.scan()
        sip013 = [f for f in findings if "SIP-013" in f.title]
        assert len(sip013) == 1, f"Expected 1 SIP-013 finding, got {len(sip013)}"
        finding = sip013[0]
        assert finding.severity == "MEDIUM"
        assert finding.category == "Standards Compliance"
        # Should flag exactly the 4 missing functions
        for missing_fn in ["transfer-memo", "get-overall-balance", "get-overall-supply", "get-decimals"]:
            assert missing_fn in finding.description, f"Expected '{missing_fn}' in description"

    def test_complete_sft_no_findings(self):
        """Complete SFT implementation should not trigger SIP-013 detector"""
        scanner = ClarityScanner(str(TEST_DIR / "sip013-complete.clar"))
        findings = scanner.scan()
        sip013 = [f for f in findings if "SIP-013" in f.title]
        assert len(sip013) == 0, f"Expected 0 SIP-013 findings, got {len(sip013)}: {[f.title for f in sip013]}"

    def test_non_sft_contract_skipped(self):
        """Non-SFT contracts should not trigger SIP-013 detector"""
        # Use a plain contract with no SFT patterns
        scanner = ClarityScanner(str(TEST_DIR / "safe-token.clar"))
        findings = scanner.scan()
        sip013 = [f for f in findings if "SIP-013" in f.title]
        assert len(sip013) == 0

    def test_sft_trait_reference_triggers_check(self):
        """Contract referencing sip013-semi-fungible-token trait should trigger check"""
        import tempfile, os
        contract = """;; Uses SIP-013 trait
(impl-trait .sip013-semi-fungible-token-trait.sip013-semi-fungible-token)
(define-fungible-token my-sft)
(define-public (transfer (token-id uint) (amount uint) (sender principal) (recipient principal))
  (ok true)
)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.clar', delete=False) as f:
            f.write(contract)
            f.flush()
            try:
                scanner = ClarityScanner(f.name)
                findings = scanner.scan()
                sip013 = [f for f in findings if "SIP-013" in f.title]
                assert len(sip013) == 1
                # Should list 7 missing functions (only transfer is present)
                finding = sip013[0]
                for fn in ["transfer-memo", "get-balance", "get-overall-balance",
                           "get-total-supply", "get-overall-supply", "get-token-uri", "get-decimals"]:
                    assert fn in finding.description
            finally:
                os.unlink(f.name)

    def test_sip013_finding_has_reference_link(self):
        """SIP-013 finding recommendation should reference the SIP spec"""
        scanner = ClarityScanner(str(TEST_DIR / "sip013-incomplete.clar"))
        findings = scanner.scan()
        sip013 = [f for f in findings if "SIP-013" in f.title]
        assert len(sip013) == 1
        assert "sip-013" in sip013[0].recommendation.lower()
