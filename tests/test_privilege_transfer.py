"""Tests for detector #77 — Single-Step Privilege Transfer."""
import pytest
from src.scanner import ClarityScanner


@pytest.fixture
def scan_results():
    s = ClarityScanner('test-contracts/privilege-transfer-test.clar')
    s.scan()
    return [f for f in s.findings if 'Single-Step Privilege Transfer' in f.title]


def test_detects_single_step_admin_transfer(scan_results):
    """Should flag transfer-admin which sets admin-address without two-step."""
    admin_findings = [f for f in scan_results if 'transfer-admin' in f.title]
    assert len(admin_findings) == 1
    assert admin_findings[0].severity == 'HIGH'


def test_skips_owner_with_two_step_pattern(scan_results):
    """Should NOT flag set-owner because contract-owner has pending-owner/accept pattern."""
    owner_findings = [f for f in scan_results if 'set-owner' in f.title]
    assert len(owner_findings) == 0


def test_skips_tx_sender_self_set(scan_results):
    """Should NOT flag reclaim-ownership which sets owner to tx-sender (not arbitrary)."""
    reclaim = [f for f in scan_results if 'reclaim-ownership' in f.title]
    assert len(reclaim) == 0


def test_finding_has_access_control_category(scan_results):
    """Finding should be categorized as Access Control."""
    assert len(scan_results) > 0
    for f in scan_results:
        assert f.category == 'Access Control'


def test_finding_mentions_two_step_in_recommendation(scan_results):
    """Recommendation should suggest two-step transfer pattern."""
    assert len(scan_results) > 0
    for f in scan_results:
        assert 'two-step' in f.recommendation.lower()
        assert 'pending' in f.recommendation.lower() or 'propose' in f.recommendation.lower()


def test_no_findings_on_safe_only_contract(tmp_path):
    """Contract with only two-step transfers should have zero findings."""
    safe_contract = tmp_path / "safe-owner.clar"
    safe_contract.write_text("""
(define-data-var contract-owner principal tx-sender)
(define-data-var pending-owner (optional principal) none)

(define-public (propose-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set pending-owner (some new-owner))
    (ok true)
  )
)

(define-public (accept-ownership)
  (let ((pending (unwrap! (var-get pending-owner) (err u404))))
    (asserts! (is-eq tx-sender pending) (err u403))
    (var-set contract-owner pending)
    (var-set pending-owner none)
    (ok true)
  )
)
""")
    s = ClarityScanner(str(safe_contract))
    s.scan()
    priv_findings = [f for f in s.findings if 'Single-Step Privilege Transfer' in f.title]
    assert len(priv_findings) == 0


def test_flags_all_single_step_vars_in_vulnerable_contract(tmp_path):
    """Contract with multiple privilege vars and no two-step should flag all."""
    vuln_contract = tmp_path / "vuln-multi-owner.clar"
    vuln_contract.write_text("""
(define-data-var contract-owner principal tx-sender)
(define-data-var admin principal tx-sender)

(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set contract-owner new-owner)
    (ok true)
  )
)

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u401))
    (var-set admin new-admin)
    (ok true)
  )
)
""")
    s = ClarityScanner(str(vuln_contract))
    s.scan()
    priv_findings = [f for f in s.findings if 'Single-Step Privilege Transfer' in f.title]
    assert len(priv_findings) == 2
    titles = {f.title for f in priv_findings}
    assert any('set-owner' in t for t in titles)
    assert any('set-admin' in t for t in titles)


def test_no_findings_on_contract_without_privilege_vars(tmp_path):
    """Contract without owner/admin data-vars should have no findings."""
    no_priv = tmp_path / "no-priv.clar"
    no_priv.write_text("""
(define-data-var counter uint u0)

(define-public (increment)
  (begin
    (var-set counter (+ (var-get counter) u1))
    (ok (var-get counter))
  )
)
""")
    s = ClarityScanner(str(no_priv))
    s.scan()
    priv_findings = [f for f in s.findings if 'Single-Step Privilege Transfer' in f.title]
    assert len(priv_findings) == 0
