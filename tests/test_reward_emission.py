"""Tests for detector #74: Unbounded Reward Emission."""
import pytest
from pathlib import Path
from src.scanner import ClarityScanner

CONTRACT = str(Path(__file__).resolve().parent.parent / "test-contracts" / "reward-emission-test.clar")


def _scan():
    scanner = ClarityScanner(CONTRACT)
    scanner.scan()
    return [f for f in scanner.findings if "Unbounded Reward Emission" in f.title]


def test_detects_unguarded_claim_rewards():
    """#1 claim-rewards with no cooldown should be flagged."""
    findings = _scan()
    titles = [f.title for f in findings]
    assert any("claim-rewards" in t for t in titles), f"Expected claim-rewards finding, got: {titles}"


def test_detects_unguarded_harvest_yield():
    """#2 harvest-yield with ft-transfer but no guard should be flagged."""
    findings = _scan()
    titles = [f.title for f in findings]
    assert any("harvest-yield" in t for t in titles), f"Expected harvest-yield finding, got: {titles}"


def test_safe_claim_with_cooldown():
    """#3 claim-daily with block-height cooldown should NOT be flagged."""
    findings = _scan()
    titles = [f.title for f in findings]
    assert not any("claim-daily" in t for t in titles), f"claim-daily should be safe: {titles}"


def test_safe_distribute_with_assert():
    """#4 distribute-rewards with asserts! guard should NOT be flagged."""
    findings = _scan()
    titles = [f.title for f in findings]
    assert not any("distribute-rewards" in t for t in titles), f"distribute-rewards should be safe: {titles}"


def test_non_reward_function_ignored():
    """#5 send-payment is not a reward function, should NOT trigger."""
    findings = _scan()
    titles = [f.title for f in findings]
    assert not any("send-payment" in t for t in titles), f"send-payment should be ignored: {titles}"


def test_finding_count():
    """Exactly 2 vulnerable reward functions should be found."""
    findings = _scan()
    assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}: {[f.title for f in findings]}"


def test_finding_severity():
    """All unbounded reward findings should be HIGH severity."""
    findings = _scan()
    for f in findings:
        assert f.severity == "HIGH", f"Expected HIGH severity, got {f.severity}"


def test_finding_category():
    """All unbounded reward findings should be in Economic Safety category."""
    findings = _scan()
    for f in findings:
        assert f.category == "Economic Safety", f"Expected Economic Safety, got {f.category}"
