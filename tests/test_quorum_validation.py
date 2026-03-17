"""Tests for detector #89: Missing Quorum Validation — Low-Turnout Attack Risk."""
import subprocess, json, os, sys

SCANNER = os.path.join(os.path.dirname(__file__), '..', 'src', 'scanner.py')
CONTRACT = os.path.join(os.path.dirname(__file__), '..', 'test-contracts', 'quorum-test.clar')


def run_scan(contract_path=CONTRACT, extra_args=None):
    """Run the scanner and return parsed JSON findings."""
    cmd = [sys.executable, SCANNER, contract_path, '--format', 'json']
    if extra_args:
        cmd.extend(extra_args)
    subprocess.run(cmd, capture_output=True, text=True)
    stem = os.path.splitext(os.path.basename(contract_path))[0]
    report_path = os.path.join(os.path.dirname(SCANNER), '..', 'findings', f'{stem}_report.json')
    with open(report_path) as f:
        data = json.load(f)
    return data['findings']


def get_89_findings(findings=None):
    """Filter to only detector #89 findings."""
    if findings is None:
        findings = run_scan()
    return [f for f in findings if 'Quorum' in f.get('title', '')]


class TestMissingQuorumValidation:
    """Test #89: Missing Quorum Validation / Low-Turnout Attack Risk."""

    def test_detects_execute_proposal_without_quorum(self):
        """execute-proposal has majority check but no quorum — should flag."""
        findings = get_89_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert any("execute-proposal" in t for t in flagged_funcs), \
            f"Expected execute-proposal to be flagged. Got: {flagged_funcs}"

    def test_detects_finalize_without_quorum(self):
        """finalize has no quorum check — should flag."""
        findings = get_89_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert any("finalize" in t for t in flagged_funcs), \
            f"Expected finalize to be flagged. Got: {flagged_funcs}"

    def test_safe_execute_with_quorum_threshold(self):
        """execute-with-quorum has QUORUM-THRESHOLD check — should NOT flag."""
        findings = get_89_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("execute-with-quorum" in t for t in flagged_funcs), \
            f"execute-with-quorum should not be flagged. Got: {flagged_funcs}"

    def test_safe_conclude_with_min_votes(self):
        """conclude-vote has MIN-VOTES check — should NOT flag."""
        findings = get_89_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("conclude-vote" in t for t in flagged_funcs), \
            f"conclude-vote should not be flagged. Got: {flagged_funcs}"

    def test_safe_resolve_with_participation_threshold(self):
        """resolve-proposal has participation-threshold check — should NOT flag."""
        findings = get_89_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("resolve-proposal" in t for t in flagged_funcs), \
            f"resolve-proposal should not be flagged. Got: {flagged_funcs}"

    def test_cast_vote_not_flagged(self):
        """cast-vote is not an execution function — should NOT flag."""
        findings = get_89_findings()
        flagged_funcs = [f['title'] for f in findings]
        assert not any("cast-vote" in t for t in flagged_funcs), \
            f"cast-vote should not be flagged. Got: {flagged_funcs}"

    def test_finding_severity_is_high(self):
        """Quorum findings should be HIGH severity."""
        findings = get_89_findings()
        assert len(findings) > 0, "Expected at least one quorum finding"
        for f in findings:
            assert f['severity'] == 'HIGH', f"Expected HIGH severity, got {f['severity']}"

    def test_finding_has_governance_category(self):
        """Quorum findings should have Governance category."""
        findings = get_89_findings()
        assert len(findings) > 0
        for f in findings:
            assert f['category'] == 'Governance', f"Expected Governance category, got {f['category']}"

    def test_finding_has_recommendation(self):
        """Quorum findings should include actionable recommendations."""
        findings = get_89_findings()
        assert len(findings) > 0
        for f in findings:
            assert 'quorum' in f.get('recommendation', '').lower(), \
                f"Recommendation should mention quorum. Got: {f.get('recommendation', '')}"

    def test_exactly_two_vulnerable_functions(self):
        """Should find exactly 2 vulnerable functions (execute-proposal, finalize)."""
        findings = get_89_findings()
        assert len(findings) == 2, \
            f"Expected exactly 2 quorum findings, got {len(findings)}: {[f['title'] for f in findings]}"
