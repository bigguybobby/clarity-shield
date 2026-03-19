"""Tests for compute_security_score() and its integration into reports."""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner import compute_security_score, Finding, generate_report


def _make_finding(severity: str) -> Finding:
    return Finding(
        severity=severity,
        title=f"Test {severity}",
        description="desc",
        line=1,
        code_snippet="(code)",
        recommendation="fix it",
        category="Test",
    )


class TestComputeSecurityScore:
    """Unit tests for the scoring function."""

    def test_perfect_score_no_findings(self):
        grade, score = compute_security_score([])
        assert grade == "A"
        assert score == 100

    def test_single_critical_drops_25(self):
        grade, score = compute_security_score([_make_finding("CRITICAL")])
        assert score == 75
        assert grade == "C"

    def test_single_high_drops_15(self):
        grade, score = compute_security_score([_make_finding("HIGH")])
        assert score == 85
        assert grade == "B"

    def test_single_medium_drops_8(self):
        grade, score = compute_security_score([_make_finding("MEDIUM")])
        assert score == 92
        assert grade == "A"

    def test_single_low_drops_3(self):
        grade, score = compute_security_score([_make_finding("LOW")])
        assert score == 97
        assert grade == "A"

    def test_single_info_drops_1(self):
        grade, score = compute_security_score([_make_finding("INFO")])
        assert score == 99
        assert grade == "A"

    def test_score_does_not_go_below_zero(self):
        findings = [_make_finding("CRITICAL")] * 10
        grade, score = compute_security_score(findings)
        assert score == 0
        assert grade == "F"

    def test_grade_boundaries(self):
        # Exactly 90 -> A
        findings_10 = [_make_finding("LOW")] * 3 + [_make_finding("INFO")]  # 100 - 9 - 1 = 90
        grade, score = compute_security_score(findings_10)
        assert score == 90
        assert grade == "A"

        # 89 -> B
        findings_11 = findings_10 + [_make_finding("INFO")]  # 89
        grade, score = compute_security_score(findings_11)
        assert score == 89
        assert grade == "B"

        # 80 -> B
        findings_80 = [_make_finding("MEDIUM")] * 2 + [_make_finding("LOW")] * 1 + [_make_finding("INFO")]  # 100-16-3-1=80
        grade, score = compute_security_score(findings_80)
        assert score == 80
        assert grade == "B"

        # 79 -> C
        findings_79 = findings_80 + [_make_finding("INFO")]
        grade, score = compute_security_score(findings_79)
        assert score == 79
        assert grade == "C"

    def test_grade_d_boundary(self):
        # Score 60 -> D
        findings = [_make_finding("CRITICAL")] + [_make_finding("HIGH")]  # 100-25-15=60
        grade, score = compute_security_score(findings)
        assert score == 60
        assert grade == "D"

    def test_grade_f(self):
        # Score 59 -> F
        findings = [_make_finding("CRITICAL")] + [_make_finding("HIGH")] + [_make_finding("INFO")]
        grade, score = compute_security_score(findings)
        assert score == 59
        assert grade == "F"

    def test_mixed_severities(self):
        findings = [
            _make_finding("CRITICAL"),   # -25
            _make_finding("HIGH"),       # -15
            _make_finding("MEDIUM"),     # -8
            _make_finding("LOW"),        # -3
            _make_finding("INFO"),       # -1
        ]
        grade, score = compute_security_score(findings)
        assert score == 48  # 100 - 25 - 15 - 8 - 3 - 1
        assert grade == "F"


class TestScoreInReports:
    """Verify score appears in report outputs."""

    def test_json_report_includes_score(self):
        findings = [_make_finding("HIGH")]
        report_json = generate_report(findings, "test-contract", "json")
        report = json.loads(report_json)
        assert "security_score" in report
        assert "security_grade" in report
        assert report["security_score"] == 85
        assert report["security_grade"] == "B"

    def test_json_report_perfect_score(self):
        report_json = generate_report([], "clean-contract", "json")
        report = json.loads(report_json)
        assert report["security_score"] == 100
        assert report["security_grade"] == "A"

    def test_markdown_report_includes_score(self):
        findings = [_make_finding("CRITICAL")]
        report_md = generate_report(findings, "vuln-contract", "markdown")
        assert "Security Score" in report_md
        assert "C (75/100)" in report_md
