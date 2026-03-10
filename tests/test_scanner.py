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


# ---------------------------------------------------------------------------
# Regression: look-ahead bleed across function boundaries (#29, #34)
# ---------------------------------------------------------------------------

class TestLookAheadBleedFix:
    """
    Detectors 29 (unprotected mint) and 34 (unprotected burn) previously used
    a 15-line raw look-ahead that could bleed into the next function, causing
    false negatives when the adjacent function had auth checks.
    """

    BLEED_CONTRACT = Path(__file__).resolve().parent.parent / "test-contracts" / "bleed-test.clar"

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts" / "bleed-test.clar").is_file(),
        reason="bleed-test.clar not found"
    )
    def test_unprotected_mint_detected_despite_adjacent_auth(self):
        """Unprotected mint must be flagged even when the next function has auth."""
        scanner = ClarityScanner(str(self.BLEED_CONTRACT))
        scanner.scan()
        titles = [f.title for f in scanner.findings]
        assert "Unprotected Mint Function" in titles, (
            "False negative: unprotected mint-public not detected (look-ahead bleed)"
        )

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts" / "bleed-test.clar").is_file(),
        reason="bleed-test.clar not found"
    )
    def test_unprotected_burn_detected_despite_adjacent_auth(self):
        """Unprotected burn must be flagged even when the next function has auth."""
        scanner = ClarityScanner(str(self.BLEED_CONTRACT))
        scanner.scan()
        titles = [f.title for f in scanner.findings]
        assert "Unprotected Burn Function" in titles, (
            "False negative: unprotected burn-public not detected (look-ahead bleed)"
        )

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts" / "bleed-test.clar").is_file(),
        reason="bleed-test.clar not found"
    )
    def test_protected_functions_not_flagged(self):
        """admin-transfer and admin-burn have auth — must NOT be flagged as unprotected."""
        scanner = ClarityScanner(str(self.BLEED_CONTRACT))
        scanner.scan()
        unprotected = [f for f in scanner.findings if f.title in (
            "Unprotected Mint Function", "Unprotected Burn Function"
        )]
        flagged_lines = {f.line for f in unprotected}
        # admin-transfer is at line 17, admin-burn at line 27 — neither should be flagged
        assert 17 not in flagged_lines, "False positive: admin-transfer flagged as unprotected"
        assert 27 not in flagged_lines, "False positive: admin-burn flagged as unprotected"


# ---------------------------------------------------------------------------
# SARIF output format validation
# ---------------------------------------------------------------------------

class TestSARIFOutput:
    """Validate SARIF 2.1.0 output structure for GitHub Code Scanning integration."""

    def test_sarif_valid_json(self, tmp_contract):
        """SARIF output must be valid JSON."""
        from scanner import generate_sarif
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        sarif_str = generate_sarif({"test-contract": findings})
        sarif = json.loads(sarif_str)
        assert isinstance(sarif, dict)

    def test_sarif_schema_and_version(self, tmp_contract):
        """SARIF must declare schema and version 2.1.0."""
        from scanner import generate_sarif
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        sarif = json.loads(generate_sarif({"test-contract": findings}))
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_sarif_has_runs_with_tool(self, tmp_contract):
        """SARIF must have runs[] with tool driver info."""
        from scanner import generate_sarif
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        sarif = json.loads(generate_sarif({"test-contract": findings}))
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "Clarity Shield"
        assert "version" in run["tool"]["driver"]
        assert "rules" in run["tool"]["driver"]

    def test_sarif_results_match_findings(self, tmp_contract):
        """Each finding should produce a SARIF result with correct fields."""
        from scanner import generate_sarif
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        sarif = json.loads(generate_sarif({"test-contract": findings}))
        results = sarif["runs"][0]["results"]
        assert len(results) == len(findings)
        for r in results:
            assert "ruleId" in r
            assert r["level"] in ("error", "warning", "note")
            assert "message" in r
            assert "locations" in r
            loc = r["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert "region" in loc
            assert "startLine" in loc["region"]

    def test_sarif_empty_findings(self):
        """SARIF with no findings should still be valid."""
        from scanner import generate_sarif
        sarif = json.loads(generate_sarif({}))
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_severity_mapping(self, tmp_contract):
        """CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note."""
        from scanner import generate_sarif
        path = tmp_contract(VULNERABLE_CONTRACT)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        sarif = json.loads(generate_sarif({"test-contract": findings}))
        results = sarif["runs"][0]["results"]
        severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                        "LOW": "note", "INFO": "note"}
        for r, f in zip(results, findings):
            expected = severity_map.get(f.severity, "warning")
            assert r["level"] == expected, \
                f"Severity {f.severity} should map to '{expected}', got '{r['level']}'"


# ---------------------------------------------------------------------------
# Detector-specific regression tests (#3, #4, #13, #38)
# ---------------------------------------------------------------------------

class TestReentrancyDetector:
    """Detector #13: State changes after external contract calls."""

    REGRESSION_CONTRACT = Path(__file__).resolve().parent.parent / "test-contracts" / "detector-regression.clar"

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts" / "detector-regression.clar").is_file(),
        reason="detector-regression.clar not found"
    )
    def test_flags_state_change_after_contract_call(self):
        """map-set after contract-call? in withdraw-unsafe must trigger reentrancy finding."""
        scanner = ClarityScanner(str(self.REGRESSION_CONTRACT))
        scanner.scan()
        reentrancy = [f for f in scanner.findings if "reentrancy" in f.title.lower() or "state change after" in f.title.lower()]
        unsafe_hits = [f for f in reentrancy if "withdraw-unsafe" in f.title]
        assert len(unsafe_hits) > 0, "Reentrancy detector missed state change after contract-call? in withdraw-unsafe"

    @pytest.mark.skipif(
        not (Path(__file__).resolve().parent.parent / "test-contracts" / "detector-regression.clar").is_file(),
        reason="detector-regression.clar not found"
    )
    def test_no_flag_state_change_before_contract_call(self):
        """map-set before contract-call? in withdraw-safe should NOT trigger reentrancy."""
        scanner = ClarityScanner(str(self.REGRESSION_CONTRACT))
        scanner.scan()
        reentrancy = [f for f in scanner.findings if "reentrancy" in f.title.lower() or "state change after" in f.title.lower()]
        safe_hits = [f for f in reentrancy if "withdraw-safe" in f.title]
        assert len(safe_hits) == 0, "False positive: withdraw-safe flagged for reentrancy despite correct ordering"


class TestArithmeticSafetyDetector:
    """Detector #3: Unchecked arithmetic on uint values."""

    def test_flags_unchecked_uint_arithmetic(self, tmp_contract):
        """Arithmetic on uint without bounds check should trigger."""
        code = """\
(define-public (add-amounts (a uint) (b uint))
  (ok (+ a uint b uint)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        overflow = [f for f in findings if "overflow" in f.title.lower() or "arithmetic" in f.title.lower()]
        assert len(overflow) > 0, "Arithmetic safety detector missed unchecked uint addition"

    def test_no_flag_checked_arithmetic(self, tmp_contract):
        """Arithmetic with asserts! bounds check should NOT trigger."""
        code = """\
(define-public (add-safe (a uint) (b uint))
  (begin
    (asserts! (<= (+ a b) u1000000) (err u500))
    (ok (+ a b))))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        overflow = [f for f in findings if "overflow" in f.title.lower() or "arithmetic" in f.title.lower()]
        assert len(overflow) == 0, "False positive: checked arithmetic flagged as unsafe"


class TestPublicFunctionAuthDetector:
    """Detector #4: Missing auth checks in sensitive public functions."""

    def test_flags_unprotected_admin_setter(self, tmp_contract):
        """Public set-* function with var-set and no auth should trigger."""
        code = """\
(define-data-var fee-rate uint u100)
(define-public (set-fee-rate (new-rate uint))
  (begin
    (var-set fee-rate new-rate)
    (ok true)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        auth_missing = [f for f in findings if "authorization" in f.title.lower() or "missing auth" in f.title.lower()]
        assert len(auth_missing) > 0, "Auth detector missed unprotected set-fee-rate"

    def test_no_flag_protected_admin_setter(self, tmp_contract):
        """Public admin function with tx-sender check should NOT trigger."""
        code = """\
(define-data-var admin principal tx-sender)
(define-data-var fee-rate uint u100)
(define-public (admin-set-fee (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u401))
    (var-set fee-rate new-rate)
    (ok true)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        auth_missing = [f for f in findings if "authorization" in f.title.lower() and "admin-set-fee" in f.title.lower()]
        assert len(auth_missing) == 0, "False positive: protected admin function flagged as missing auth"


class TestDoSDetector:
    """Detector #38: External calls inside loops (DoS vector)."""

    def test_flags_external_call_in_fold(self, tmp_contract):
        """stx-transfer? inside fold should trigger DoS warning."""
        code = """\
(define-public (distribute (recipients (list 200 principal)))
  (begin
    (fold send-one recipients u0)
    (ok true)))

(define-private (send-one (recipient principal) (idx uint))
  (begin
    (unwrap-panic (stx-transfer? u100 tx-sender recipient))
    (+ idx u1)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        dos = [f for f in findings if "denial of service" in f.title.lower() or "loop" in f.title.lower()]
        assert len(dos) > 0, "DoS detector missed external call in fold"

    def test_no_flag_fold_without_external_call(self, tmp_contract):
        """Pure computation in fold should NOT trigger DoS warning."""
        code = """\
(define-public (sum-list (values (list 200 uint)))
  (ok (fold + values u0)))
"""
        path = tmp_contract(code)
        scanner = ClarityScanner(path)
        findings = scanner.scan()
        dos = [f for f in findings if "denial of service" in f.title.lower()]
        assert len(dos) == 0, "False positive: pure fold flagged as DoS"


class TestCodeQuality:
    """Meta-tests to catch code quality regressions in scanner.py"""

    def test_no_duplicate_method_definitions(self):
        """Ensure no methods are defined twice in ClarityScanner (Python silently uses the last)"""
        import re
        from pathlib import Path
        scanner_path = Path(__file__).parent.parent / "src" / "scanner.py"
        content = scanner_path.read_text()
        # Find all method defs at class level (4-space indent)
        methods = re.findall(r'^    def (\w+)\(', content, re.MULTILINE)
        seen = {}
        duplicates = []
        for m in methods:
            if m in seen:
                duplicates.append(m)
            seen[m] = True
        assert duplicates == [], f"Duplicate method definitions found in scanner.py: {duplicates}"

    def test_all_detector_specs_have_methods(self):
        """Every detector in DETECTOR_SPECS must have a corresponding method"""
        from src.scanner import ClarityScanner
        for detector_id, method_name in ClarityScanner.DETECTOR_SPECS:
            assert hasattr(ClarityScanner, method_name), \
                f"Detector #{detector_id} references missing method '{method_name}'"

    def test_detector_ids_are_unique(self):
        """All detector IDs in DETECTOR_SPECS must be unique"""
        from src.scanner import ClarityScanner
        ids = [d[0] for d in ClarityScanner.DETECTOR_SPECS]
        assert len(ids) == len(set(ids)), \
            f"Duplicate detector IDs: {[x for x in ids if ids.count(x) > 1]}"
