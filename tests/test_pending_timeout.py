"""Tests for detector #84: Missing Timeout for Pending Operations."""
import pytest
from src.scanner import ClarityScanner


CONTRACT = "test-contracts/pending-timeout-test.clar"
D84_TITLE = "Missing Timeout for Pending Operation"


@pytest.fixture
def findings():
    scanner = ClarityScanner(CONTRACT)
    scanner.scan()
    return scanner.findings


def _d84(findings):
    """Return only detector #84 findings."""
    return [f for f in findings if D84_TITLE in f.title]


def _d84_for(findings, func_name):
    """Return #84 findings for a specific function."""
    return [f for f in _d84(findings) if func_name in f.title]


class TestPendingTimeout:
    """Detector #84 — pending/escrow maps without block-height deadline."""

    def test_detects_pending_order_without_timeout(self, findings):
        hits = _d84_for(findings, "create-order")
        assert len(hits) == 1
        assert hits[0].severity == "HIGH"

    def test_detects_escrow_without_timeout(self, findings):
        hits = _d84_for(findings, "create-escrow")
        assert len(hits) == 1
        assert hits[0].severity == "HIGH"

    def test_detects_proposal_without_timeout(self, findings):
        hits = _d84_for(findings, "submit-proposal")
        assert len(hits) == 1
        assert hits[0].severity == "HIGH"

    def test_safe_order_with_deadline_no_finding(self, findings):
        hits = _d84_for(findings, "create-safe-order")
        assert len(hits) == 0

    def test_safe_escrow_with_expires_at_no_finding(self, findings):
        hits = _d84_for(findings, "create-safe-escrow")
        assert len(hits) == 0

    def test_non_pending_map_no_finding(self, findings):
        """Regular map (user-balances) should NOT trigger detector #84."""
        hits = _d84_for(findings, "deposit")
        assert len(hits) == 0

    def test_finding_has_fund_safety_category(self, findings):
        for h in _d84(findings):
            assert h.category == "Fund Safety"

    def test_finding_recommendation_mentions_deadline(self, findings):
        hits = _d84(findings)
        assert len(hits) > 0
        for h in hits:
            assert "deadline" in h.recommendation.lower() or "block-height" in h.recommendation.lower()

    def test_total_pending_timeout_findings(self, findings):
        """Exactly 3 vulnerable functions should be flagged."""
        assert len(_d84(findings)) == 3
