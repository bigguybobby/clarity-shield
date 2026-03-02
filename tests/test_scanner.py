"""
Clarity Shield — Test Suite
Tests core scanner functionality, individual detectors, and output formats.
"""

import sys
import os
import json
import tempfile
import pytest
from pathlib import Path

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from scanner import ClarityScanner, Finding, Severity, VERSION


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_contract(tmp_path):
    """Helper to create temporary .clar files for testing."""
    def _make(code: str, name: str = "test-contract.clar") -> str:
        p = tmp_path / name
        p.write_text(code)
        return str(p)
    return _make


SAFE_CONTRACT = """\
;; Well-secured token contract
(define-fungible-token safe-token)
(define-data-var contract-owner principal tx-sender)
(define-constant ERR_UNAUTHORIZED (err u403))

(define-private (is-owner)
  (is-eq tx-sender (var-get contract-owner)))

(define-public (mint (amount uint) (recipient principal))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (ft-mint? safe-token amount recipient)))

(define-public (transfer (amount uint) (recipient principal))
  (begin
    (asserts! (> amount u0) (err u400))
    (try! (ft-transfer? safe-token amount tx-sender recipient))
    (ok true)))
"""

VULNERABLE_CONTRACT = """\
;; Vulnerable token contract
(define-fungible-token vuln-token)
(define-data-var contract-owner principal 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)

;; No auth check — anyone can mint
(define-public (mint (amount uint) (recipient principal))
  (ft-mint? vuln-token amount recipient))

;; Uses contract-caller instead of tx-sender
(define-public (admin-set-owner (new-owner principal))
  (begin
    (asserts! (is-eq contract-caller (var-get contract-owner)) (err u403))
    (ok (var-set contract-owner new-owner))))

;; Unchecked unwrap
(define-public (risky-get (id uint))
  (ok (unwrap-panic (map-get? data-store {id: id}))))
"""


# ---------------------------------------------------------------------------
# Core functionality
# ---------------------------------------------------------------------------

class TestScannerBasics:
    """Test scanner initialisation and core methods."""

    def test_version_string(self):
        assert VERSION == "2.3.0"

    def test_scanner_loads_contract(self, tmp_contract):
        path = tmp_contract(SAFE_CONTRACT)
        scanner = ClarityScanner(path)
        assert scanner.contract_name == "test-contract"
        assert len(scanner.lines) > 0

    def test_scan_returns_findings_list(self, tmp_contract):
        path = tmp_contract(SAFE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        assert isinstance(findings, list)
        for f in findings:
            assert isinstance(f, Finding)

    def test_finding_to_dict(self):
        f = Finding(
            severity="HIGH",
            title="Test",
            description="desc",
            line=1,
            code_snippet="code",
            recommendation="fix it",
            category="Test",
            confidence="HIGH",
        )
        d = f.to_dict()
        assert d["severity"] == "HIGH"
        assert d["title"] == "Test"

    def test_empty_contract(self, tmp_contract):
        path = tmp_contract(";; empty contract\n")
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Detector: tx-sender vs contract-caller (#1)
# ---------------------------------------------------------------------------

class TestTxSenderDetector:
    def test_flags_contract_caller_auth(self, tmp_contract):
        code = """\
(define-data-var owner principal tx-sender)
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq contract-caller (var-get owner)) (err u1))
    (ok (var-set owner new-owner))))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        titles = [f.title for f in findings]
        assert any("contract-caller" in t.lower() or "tx-sender" in t.lower() for t in titles)

    def test_no_flag_on_tx_sender(self, tmp_contract):
        code = """\
(define-data-var owner principal tx-sender)
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u1))
    (ok (var-set owner new-owner))))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        tx_sender_findings = [f for f in findings if "tx-sender" in f.title.lower() and "contract-caller" in f.title.lower()]
        assert len(tx_sender_findings) == 0


# ---------------------------------------------------------------------------
# Detector: unwrap safety (#2)
# ---------------------------------------------------------------------------

class TestUnwrapDetector:
    def test_flags_unwrap_panic(self, tmp_contract):
        code = """\
(define-map data-store {id: uint} {value: uint})
(define-public (risky-get (id uint))
  (ok (unwrap-panic (map-get? data-store {id: id}))))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        assert any("unwrap" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Detector: unprotected mint (#29) — false positive fix
# ---------------------------------------------------------------------------

class TestUnprotectedMintDetector:
    def test_no_false_positive_with_is_owner(self, tmp_contract):
        """Mint protected by (asserts! (is-owner) ...) should NOT trigger."""
        code = """\
(define-fungible-token my-token)
(define-data-var contract-owner principal tx-sender)
(define-private (is-owner)
  (is-eq tx-sender (var-get contract-owner)))
(define-public (mint (amount uint) (recipient principal))
  (begin
    (asserts! (is-owner) (err u403))
    (ft-mint? my-token amount recipient)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        unprotected_mint = [f for f in findings if f.title == "Unprotected Mint Function"]
        assert len(unprotected_mint) == 0, \
            f"False positive: 'Unprotected Mint Function' fired despite is-owner guard"

    def test_no_false_positive_with_is_admin(self, tmp_contract):
        """Mint protected by (asserts! (is-admin) ...) should NOT trigger."""
        code = """\
(define-fungible-token my-token)
(define-public (mint (amount uint) (recipient principal))
  (begin
    (asserts! (is-admin) (err u403))
    (ft-mint? my-token amount recipient)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        unprotected_mint = [f for f in findings if f.title == "Unprotected Mint Function"]
        assert len(unprotected_mint) == 0


# ---------------------------------------------------------------------------
# Detector: hardcoded principals (#6)
# ---------------------------------------------------------------------------

class TestHardcodedPrincipals:
    def test_flags_hardcoded_principal(self, tmp_contract):
        code = """\
(define-data-var owner principal 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        assert any("hardcoded" in f.title.lower() or "principal" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------

class TestOutputFormats:
    def test_json_output(self, tmp_contract):
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        # Verify all findings serialise to JSON
        for f in findings:
            d = f.to_dict()
            json.dumps(d)  # should not raise

    def test_severity_values(self, tmp_contract):
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for f in findings:
            assert f.severity in valid, f"Invalid severity: {f.severity}"


# ---------------------------------------------------------------------------
# Vulnerable vs safe comparison
# ---------------------------------------------------------------------------

class TestVulnerableVsSafe:
    def test_vulnerable_has_more_findings(self, tmp_contract):
        safe_path = tmp_contract(SAFE_CONTRACT, "safe.clar")
        vuln_path = tmp_contract(VULNERABLE_CONTRACT, "vuln.clar")
        safe_scanner = ClarityScanner(safe_path)
        vuln_scanner = ClarityScanner(vuln_path)
        safe_findings = safe_scanner.scan()
        vuln_findings = vuln_scanner.scan()
        assert len(vuln_findings) >= len(safe_findings), \
            f"Vulnerable contract ({len(vuln_findings)} findings) should have >= safe ({len(safe_findings)})"

    def test_vulnerable_has_critical_or_high(self, tmp_contract):
        vuln_path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(vuln_path)
        findings = scanner.scan()
        sevs = {f.severity for f in findings}
        assert "CRITICAL" in sevs or "HIGH" in sevs


# ---------------------------------------------------------------------------
# Test contract files in repo
# ---------------------------------------------------------------------------

class TestRepoContracts:
    """Run scanner against actual test-contracts in the repo."""

    CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "test-contracts"

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts").is_dir(),
        reason="test-contracts/ directory not found"
    )
    def test_scan_all_test_contracts_no_crash(self):
        """Scanner should not crash on any test contract."""
        for clar_file in sorted(self.CONTRACTS_DIR.glob("*.clar")):
            scanner = ClarityScanner(str(clar_file))
            findings = scanner.scan()  # should not raise
            assert isinstance(findings, list), f"Crash on {clar_file.name}"

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts").is_dir(),
        reason="test-contracts/ directory not found"
    )
    def test_vulnerable_contracts_have_findings(self):
        """Every vulnerable-*.clar should have at least one finding."""
        for clar_file in sorted(self.CONTRACTS_DIR.glob("vulnerable-*.clar")):
            scanner = ClarityScanner(str(clar_file))
            findings = scanner.scan()
            assert len(findings) > 0, f"No findings for {clar_file.name}"
