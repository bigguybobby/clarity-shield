"""Tests for Signature Replay Vulnerability detector (#91)."""
import pytest
from src.scanner import ClarityScanner


@pytest.fixture
def findings():
    s = ClarityScanner("test-contracts/signature-replay-test.clar")
    return s.scan()


def _sig_findings(findings):
    return [f for f in findings if "Replay" in f.title]


# --- Vulnerable function detection ---

def test_detects_secp256k1_recover_without_nonce(findings):
    """Should flag secp256k1-recover? usage without replay guard."""
    titles = [f.title for f in _sig_findings(findings)]
    assert any("execute-signed-action" in t for t in titles)


def test_detects_secp256k1_verify_without_nonce(findings):
    """Should flag secp256k1-verify usage without replay guard."""
    titles = [f.title for f in _sig_findings(findings)]
    assert any("verify-and-transfer" in t for t in titles)


def test_vulnerable_count(findings):
    """Should find exactly 2 vulnerable functions."""
    assert len(_sig_findings(findings)) == 2


def test_severity_is_high(findings):
    """Signature replay vulnerabilities should be HIGH severity."""
    for f in _sig_findings(findings):
        assert f.severity == "HIGH"


def test_category_is_cryptographic_safety(findings):
    """Should be categorized as Cryptographic Safety."""
    for f in _sig_findings(findings):
        assert f.category == "Cryptographic Safety"


# --- Safe function verification ---

def test_nonce_map_not_flagged(findings):
    """Function with nonce map tracking should not be flagged."""
    titles = [f.title for f in _sig_findings(findings)]
    assert not any("execute-with-nonce" in t for t in titles)


def test_used_signatures_map_not_flagged(findings):
    """Function with used-signatures map should not be flagged."""
    titles = [f.title for f in _sig_findings(findings)]
    assert not any("execute-once" in t for t in titles)


def test_sequence_var_not_flagged(findings):
    """Function with sequence number guard should not be flagged."""
    titles = [f.title for f in _sig_findings(findings)]
    assert not any("guarded-verify" in t for t in titles)


# --- Edge cases ---

def test_read_only_not_flagged(findings):
    """Read-only functions with signature verification should not be flagged."""
    titles = [f.title for f in _sig_findings(findings)]
    assert not any("check-signature" in t for t in titles)


def test_no_signature_not_flagged(findings):
    """Functions without signature operations should not be flagged."""
    titles = [f.title for f in _sig_findings(findings)]
    assert not any("simple-transfer" in t for t in titles)


def test_finding_has_recommendation(findings):
    """Findings should include actionable recommendations."""
    for f in _sig_findings(findings):
        assert "nonce" in f.recommendation.lower() or "replay" in f.recommendation.lower()
