"""Tests for detector #82: Missing Emergency Pause Mechanism."""
import pytest
from src.scanner import ClarityScanner


VULNERABLE_CONTRACT = "test-contracts/emergency-pause-test.clar"
SAFE_PAUSE_CONTRACT = "test-contracts/emergency-pause-safe.clar"
SAFE_FEW_OPS_CONTRACT = "test-contracts/emergency-pause-few-ops.clar"


@pytest.fixture
def vulnerable_findings():
    scanner = ClarityScanner(VULNERABLE_CONTRACT)
    scanner.check_missing_emergency_pause()
    return scanner.findings


@pytest.fixture
def safe_pause_findings():
    scanner = ClarityScanner(SAFE_PAUSE_CONTRACT)
    scanner.check_missing_emergency_pause()
    return scanner.findings


@pytest.fixture
def safe_few_ops_findings():
    scanner = ClarityScanner(SAFE_FEW_OPS_CONTRACT)
    scanner.check_missing_emergency_pause()
    return scanner.findings


def test_vulnerable_contract_flagged(vulnerable_findings):
    """Contract with 4 financial ops and no pause should be flagged."""
    assert len(vulnerable_findings) == 1


def test_finding_severity(vulnerable_findings):
    """Finding should be MEDIUM severity."""
    assert vulnerable_findings[0].severity == "MEDIUM"


def test_finding_category(vulnerable_findings):
    """Finding should be in Governance category."""
    assert vulnerable_findings[0].category == "Governance"


def test_finding_title(vulnerable_findings):
    """Finding title should mention emergency pause."""
    assert "Emergency Pause" in vulnerable_findings[0].title


def test_finding_mentions_function_count(vulnerable_findings):
    """Finding description should mention the number of financial functions."""
    assert "4 public functions" in vulnerable_findings[0].description


def test_safe_pause_contract_not_flagged(safe_pause_findings):
    """Contract with is-paused mechanism should not be flagged."""
    assert len(safe_pause_findings) == 0


def test_safe_few_ops_not_flagged(safe_few_ops_findings):
    """Contract with only 2 financial ops (below threshold) should not be flagged."""
    assert len(safe_few_ops_findings) == 0


def test_full_scan_includes_detector():
    """Full scan of vulnerable contract should include #82 finding."""
    scanner = ClarityScanner(VULNERABLE_CONTRACT)
    scanner.scan()
    pause_findings = [f for f in scanner.findings if "Emergency Pause" in f.title]
    assert len(pause_findings) >= 1
