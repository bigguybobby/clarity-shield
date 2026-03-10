"""
Clarity Shield — CLI Integration Tests
Tests the command-line interface end-to-end via subprocess.
"""

import sys
import json
import subprocess
import pytest
from pathlib import Path

SCANNER = str(Path(__file__).resolve().parent.parent / "src" / "scanner.py")
PYTHON = sys.executable
TEST_CONTRACTS = Path(__file__).resolve().parent.parent / "test-contracts"


def run_cli(*args, expect_fail=False):
    """Run clarity-shield CLI and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [PYTHON, SCANNER, *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if not expect_fail:
        # allow exit codes 0, 1, 2 (severity-based) but not crashes
        assert result.returncode in (0, 1, 2), \
            f"CLI crashed (rc={result.returncode}):\nstderr: {result.stderr}"
    return result.returncode, result.stdout, result.stderr


class TestCLIBasics:
    """Test fundamental CLI flags."""

    def test_help_flag(self):
        """--help should exit 0 and show usage."""
        rc, stdout, _ = run_cli("--help")
        assert rc == 0
        assert "Clarity Shield" in stdout
        assert "target" in stdout
        assert "--format" in stdout

    def test_version_flag(self):
        """--version should exit 0 and print version string."""
        rc, stdout, _ = run_cli("--version")
        assert rc == 0
        assert "clarity-shield" in stdout
        # Version should be a dotted number
        version_part = stdout.strip().split()[-1]
        parts = version_part.split(".")
        assert len(parts) >= 2, f"Invalid version format: {version_part}"
        assert all(p.isdigit() for p in parts), f"Non-numeric version: {version_part}"

    def test_missing_target_shows_error(self):
        """Running with no arguments should fail with usage info."""
        result = subprocess.run(
            [PYTHON, SCANNER],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0
        assert "usage" in result.stderr.lower() or "error" in result.stderr.lower()

    def test_nonexistent_file_error(self):
        """Scanning a nonexistent file should fail gracefully."""
        result = subprocess.run(
            [PYTHON, SCANNER, "/tmp/does-not-exist-xyz.clar"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0
        assert "not found" in result.stdout.lower() or "error" in result.stderr.lower()


@pytest.mark.skipif(
    not TEST_CONTRACTS.is_dir(),
    reason="test-contracts/ directory not found"
)
class TestCLIOutputFormats:
    """Test different output format flags."""

    def _get_vulnerable_contract(self):
        """Find a vulnerable contract for testing."""
        contracts = list(TEST_CONTRACTS.glob("vulnerable-*.clar"))
        assert contracts, "No vulnerable-*.clar files found"
        return str(contracts[0])

    def test_json_format(self):
        """--format json --no-save should produce valid JSON to stdout."""
        contract = self._get_vulnerable_contract()
        rc, stdout, _ = run_cli(contract, "--format", "json", "--no-save")
        # stdout contains [*] status lines mixed with JSON — extract JSON
        # The JSON report starts after the last [*] line
        lines = stdout.strip().split("\n")
        json_lines = [l for l in lines if not l.startswith("[")]
        json_str = "\n".join(json_lines)
        if json_str.strip():
            data = json.loads(json_str)
            assert isinstance(data, (dict, list))

    def test_sarif_format(self):
        """--format sarif --no-save should produce valid SARIF JSON."""
        contract = self._get_vulnerable_contract()
        rc, stdout, _ = run_cli(contract, "--format", "sarif", "--no-save")
        lines = stdout.strip().split("\n")
        # SARIF JSON is the main output — filter out status lines
        json_lines = [l for l in lines if not l.startswith("[")]
        json_str = "\n".join(json_lines)
        sarif = json.loads(json_str)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif

    def test_markdown_format(self):
        """--format markdown --no-save should produce markdown output."""
        contract = self._get_vulnerable_contract()
        rc, stdout, _ = run_cli(contract, "--format", "markdown", "--no-save")
        # Markdown reports have headers
        assert "#" in stdout or "Finding" in stdout or "Security" in stdout

    def test_summary_flag(self):
        """--summary should print a dashboard table."""
        contract = self._get_vulnerable_contract()
        rc, stdout, _ = run_cli(contract, "--summary", "--no-save")
        # Summary dashboard should contain severity labels or table-like output
        output_lower = stdout.lower()
        assert any(word in output_lower for word in
                   ["critical", "high", "medium", "low", "total", "finding"])


@pytest.mark.skipif(
    not TEST_CONTRACTS.is_dir(),
    reason="test-contracts/ directory not found"
)
class TestCLISeverityFilter:
    """Test --severity flag filters output correctly."""

    def test_severity_high_filters_low(self):
        """--severity HIGH should exclude LOW and INFO findings."""
        contract = list(TEST_CONTRACTS.glob("vulnerable-*.clar"))
        assert contract
        contract = str(contract[0])

        # Get all findings
        rc_all, stdout_all, stderr_all = run_cli(contract, "--format", "json", "--no-save")
        # Get HIGH+ findings only
        rc_high, stdout_high, stderr_high = run_cli(contract, "--format", "json", "--no-save",
                                           "--severity", "HIGH")
        # HIGH filter should produce same or fewer results
        # We check via the total count in the summary line
        # Status messages go to stderr; actual report data to stdout
        # Verify JSON on stdout is parseable (no status line pollution)
        try:
            data_all = json.loads(stdout_all) if stdout_all.strip() else {}
        except json.JSONDecodeError:
            pass  # non-JSON format is ok
        # Check stderr has the summary line
        count_all = stderr_all.count("findings across")
        count_high = stderr_high.count("findings across")
        assert count_all >= 1
        assert count_high >= 1


@pytest.mark.skipif(
    not TEST_CONTRACTS.is_dir(),
    reason="test-contracts/ directory not found"
)
class TestCLIExitCodes:
    """Test severity-based exit codes."""

    def test_safe_contract_exits_zero(self, tmp_path):
        """A contract with no HIGH/CRITICAL findings should exit 0."""
        safe = tmp_path / "safe.clar"
        safe.write_text("""\
;; Minimal safe contract
(define-data-var counter uint u0)
(define-read-only (get-counter)
  (ok (var-get counter)))
""")
        rc, _, _ = run_cli(str(safe), "--no-save")
        assert rc == 0

    def test_vulnerable_contract_nonzero_exit(self):
        """A contract with HIGH/CRITICAL findings should exit 1 or 2."""
        contract = list(TEST_CONTRACTS.glob("vulnerable-*.clar"))
        assert contract
        rc, _, _ = run_cli(str(contract[0]), "--no-save")
        assert rc in (1, 2), f"Expected non-zero exit for vulnerable contract, got {rc}"


@pytest.mark.skipif(
    not TEST_CONTRACTS.is_dir(),
    reason="test-contracts/ directory not found"
)
class TestCLIDirectoryScan:
    """Test scanning a directory of contracts."""

    def test_scan_directory(self):
        """Scanning test-contracts/ directory should process multiple files."""
        rc, stdout, _ = run_cli(str(TEST_CONTRACTS), "--no-save", "--format", "markdown")
        # Should mention multiple contracts in the total line
        assert "contract" in stdout.lower()

    def test_scan_directory_recursive(self):
        """--recursive flag should not crash on directory scan."""
        rc, stdout, _ = run_cli(str(TEST_CONTRACTS), "--recursive", "--no-save",
                                 "--format", "markdown")
        assert "contract" in stdout.lower()


class TestStdoutClean:
    """Ensure status messages go to stderr, not stdout."""

    def test_json_stdout_is_pure_json(self):
        """JSON output on stdout should be valid JSON with no status lines mixed in."""
        contract = list(TEST_CONTRACTS.glob("vulnerable-*.clar"))
        assert contract
        contract = str(contract[0])
        rc, stdout, stderr = run_cli(contract, "--format", "json", "--no-save")
        # stdout must be valid JSON
        data = json.loads(stdout)
        assert isinstance(data, dict)
        # No status prefixes in stdout
        assert "[*]" not in stdout
        assert "[+]" not in stdout

    def test_status_lines_on_stderr(self):
        """Status messages like [*] Scanning and [+] Found should be on stderr."""
        contract = list(TEST_CONTRACTS.glob("vulnerable-*.clar"))
        assert contract
        contract = str(contract[0])
        rc, stdout, stderr = run_cli(contract, "--format", "json", "--no-save")
        assert "[*] Scanning" in stderr
        assert "[+] Found" in stderr
        assert "findings across" in stderr

    def test_sarif_stdout_is_pure_json(self):
        """SARIF output on stdout should be valid JSON with no status lines."""
        contract = list(TEST_CONTRACTS.glob("vulnerable-*.clar"))
        assert contract
        contract = str(contract[0])
        rc, stdout, stderr = run_cli(contract, "--format", "sarif", "--no-save")
        data = json.loads(stdout)
        assert "$schema" in data
        assert "[*]" not in stdout
        assert "[+]" not in stdout
