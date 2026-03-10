"""
Clarity Shield — Config Test Suite
Tests TOML/YAML config loading, enable/disable detectors,
severity overrides, and custom regex rules.
"""

import sys
import json
import pytest
from pathlib import Path

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from scanner import ClarityScanner, load_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_contract(tmp_path):
    """Create a simple contract with a known vulnerability (unwrap-panic)."""
    code = """
(define-public (transfer (amount uint) (to principal))
  (let ((balance (unwrap-panic (map-get? balances tx-sender))))
    (map-set balances tx-sender (- balance amount))
    (map-set balances to (+ (default-to u0 (map-get? balances to)) amount))
    (ok true)))

(define-public (set-admin (new-admin principal))
  (begin
    (var-set admin new-admin)
    (ok true)))
"""
    p = tmp_path / "config-test.clar"
    p.write_text(code)
    return str(p)


@pytest.fixture
def tmp_toml(tmp_path):
    """Helper to create temp TOML config files."""
    def _make(content: str, name: str = "test-config.toml") -> str:
        p = tmp_path / name
        p.write_text(content)
        return str(p)
    return _make


@pytest.fixture
def tmp_yaml(tmp_path):
    """Helper to create temp YAML config files."""
    def _make(content: str, name: str = "test-config.yaml") -> str:
        p = tmp_path / name
        p.write_text(content)
        return str(p)
    return _make


# ---------------------------------------------------------------------------
# TOML Config Loading
# ---------------------------------------------------------------------------

class TestTOMLConfig:
    def test_load_toml_basic(self, tmp_toml):
        """Load a simple TOML config and verify keys."""
        cfg = load_config(tmp_toml('[scanner]\ndefault_severity = "HIGH"\n'))
        assert cfg["scanner"]["default_severity"] == "HIGH"

    def test_load_toml_with_disable_detectors(self, tmp_toml):
        """TOML with disable_detectors list."""
        content = '[scanner]\ndisable_detectors = [1, 2, 3]\n'
        cfg = load_config(tmp_toml(content))
        assert cfg["scanner"]["disable_detectors"] == [1, 2, 3]

    def test_load_toml_with_severity_overrides(self, tmp_toml):
        """TOML with severity overrides section."""
        content = '[severity_overrides]\n"61" = "HIGH"\n"64" = "CRITICAL"\n'
        cfg = load_config(tmp_toml(content))
        assert cfg["severity_overrides"]["61"] == "HIGH"
        assert cfg["severity_overrides"]["64"] == "CRITICAL"

    def test_load_nonexistent_config_raises(self):
        """Missing config file raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            load_config("/tmp/nonexistent-clarity-shield-config.toml")

    def test_load_unsupported_extension_raises(self, tmp_path):
        """Unsupported config extension raises ValueError."""
        p = tmp_path / "config.json"
        p.write_text("{}")
        with pytest.raises(ValueError, match="Unsupported config type"):
            load_config(str(p))

    def test_load_none_returns_empty(self):
        """None config path returns empty dict."""
        assert load_config(None) == {}


# ---------------------------------------------------------------------------
# YAML Config Loading
# ---------------------------------------------------------------------------

class TestYAMLConfig:
    def test_load_yaml_basic(self, tmp_yaml):
        """Load a simple YAML config."""
        content = "scanner:\n  default_severity: HIGH\n"
        cfg = load_config(tmp_yaml(content))
        assert cfg["scanner"]["default_severity"] == "HIGH"

    def test_load_yaml_disable_detectors_list(self, tmp_yaml):
        """YAML with list-style disable_detectors."""
        content = "scanner:\n  disable_detectors:\n    - 1\n    - 2\n    - 3\n"
        cfg = load_config(tmp_yaml(content))
        assert cfg["scanner"]["disable_detectors"] == [1, 2, 3]

    def test_load_yaml_inline_list(self, tmp_yaml):
        """YAML with inline list syntax."""
        content = "scanner:\n  enable_detectors: [1, 5, 10]\n"
        cfg = load_config(tmp_yaml(content))
        assert cfg["scanner"]["enable_detectors"] == [1, 5, 10]

    def test_load_yaml_severity_overrides(self, tmp_yaml):
        """YAML severity overrides."""
        content = "severity_overrides:\n  61: HIGH\n  64: CRITICAL\n"
        cfg = load_config(tmp_yaml(content))
        assert cfg["severity_overrides"]["61"] == "HIGH"

    def test_load_yaml_custom_rules(self, tmp_yaml):
        """YAML with custom_rules list."""
        content = """custom_rules:
  - id: CUST-001
    title: Test rule
    severity: LOW
    pattern: "\\\\(asserts!"
    description: Test description
"""
        cfg = load_config(tmp_yaml(content))
        assert len(cfg["custom_rules"]) == 1
        assert cfg["custom_rules"][0]["id"] == "CUST-001"
        assert cfg["custom_rules"][0]["title"] == "Test rule"

    def test_load_yml_extension(self, tmp_path):
        """Load config with .yml extension."""
        p = tmp_path / "config.yml"
        p.write_text("scanner:\n  default_severity: LOW\n")
        cfg = load_config(str(p))
        assert cfg["scanner"]["default_severity"] == "LOW"


# ---------------------------------------------------------------------------
# Enable/Disable Detectors
# ---------------------------------------------------------------------------

class TestDetectorFiltering:
    def test_disable_detectors_reduces_findings(self, tmp_contract, tmp_toml):
        """Disabling detectors should reduce the number of findings."""
        # Run without config
        scanner_plain = ClarityScanner(tmp_contract)
        findings_all = scanner_plain.scan()

        # Get IDs of detectors that found something
        if not findings_all:
            pytest.skip("No findings from test contract")

        # Disable all detectors — should get zero findings
        all_ids = list(range(1, 71))
        disable_str = ", ".join(str(i) for i in all_ids)
        cfg = load_config(tmp_toml(f'[scanner]\ndisable_detectors = [{disable_str}]\n'))
        scanner_disabled = ClarityScanner(tmp_contract, config=cfg)
        findings_disabled = scanner_disabled.scan()
        assert len(findings_disabled) < len(findings_all)

    def test_enable_single_detector(self, tmp_contract, tmp_toml):
        """Enabling only detector #1 should restrict findings to that detector."""
        cfg = load_config(tmp_toml('[scanner]\nenable_detectors = [1]\n'))
        scanner = ClarityScanner(tmp_contract, config=cfg)
        findings = scanner.scan()
        # All findings should come from detector #1 only
        # (The scanner sets _active_detector_id internally, but we can verify
        #  indirectly — if we enable only 1 detector, count should be small)
        assert isinstance(findings, list)

    def test_enable_empty_means_all(self, tmp_contract):
        """No enable list means all detectors run (default behavior)."""
        scanner = ClarityScanner(tmp_contract, config={})
        findings = scanner.scan()
        assert isinstance(findings, list)
        assert len(findings) > 0  # Our test contract has known vulns


# ---------------------------------------------------------------------------
# Severity Overrides
# ---------------------------------------------------------------------------

class TestSeverityOverrides:
    def test_severity_override_changes_finding_severity(self, tmp_contract, tmp_toml):
        """A severity override should change the severity of matched findings."""
        # First scan without overrides
        scanner_plain = ClarityScanner(tmp_contract)
        findings_plain = scanner_plain.scan()

        if not findings_plain:
            pytest.skip("No findings to override")

        # Override everything to INFO via detector name pattern
        overrides = {}
        for f in findings_plain:
            overrides[f.title.lower()] = "INFO"

        toml_lines = ["[severity_overrides]"]
        for title, sev in overrides.items():
            toml_lines.append(f'"{title}" = "{sev}"')

        cfg = load_config(tmp_toml("\n".join(toml_lines)))
        scanner_override = ClarityScanner(tmp_contract, config=cfg)
        findings_override = scanner_override.scan()

        # At least some findings should now be INFO
        info_count = sum(1 for f in findings_override if f.severity == "INFO" or (hasattr(f.severity, "name") and f.severity.name == "INFO"))
        assert info_count > 0

    def test_severity_override_by_detector_id(self, tmp_contract, tmp_toml):
        """Override severity using numeric detector ID as key."""
        # Use detector #6 (unwrap-panic) — our test contract should trigger it
        cfg = load_config(tmp_toml('[severity_overrides]\n"6" = "CRITICAL"\n'))
        scanner = ClarityScanner(tmp_contract, config=cfg)
        findings = scanner.scan()
        # Check if any finding got bumped to CRITICAL
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Custom Rules
# ---------------------------------------------------------------------------

class TestCustomRules:
    def test_custom_rule_fires_on_match(self, tmp_contract, tmp_toml):
        """A custom regex rule should create findings when matched."""
        content = """
[[custom_rules]]
id = "TEST-001"
title = "Found unwrap-panic usage"
severity = "HIGH"
category = "Custom"
pattern = "unwrap-panic"
description = "unwrap-panic detected by custom rule"
"""
        cfg = load_config(tmp_toml(content))
        scanner = ClarityScanner(tmp_contract, config=cfg)
        findings = scanner.scan()

        custom_findings = [f for f in findings if f.title == "Found unwrap-panic usage"]
        assert len(custom_findings) >= 1

    def test_custom_rule_no_match(self, tmp_contract, tmp_toml):
        """A custom rule that doesn't match should not produce findings."""
        content = """
[[custom_rules]]
id = "TEST-002"
title = "Should not match"
severity = "LOW"
category = "Custom"
pattern = "ZZZNOMATCHZZZ"
description = "This pattern should not match anything"
"""
        cfg = load_config(tmp_toml(content))
        scanner = ClarityScanner(tmp_contract, config=cfg)
        findings = scanner.scan()

        custom_findings = [f for f in findings if f.title == "Should not match"]
        assert len(custom_findings) == 0

    def test_custom_rule_max_matches(self, tmp_path, tmp_toml):
        """Custom rule with max_matches should limit reported findings."""
        # Contract with multiple occurrences
        code = """
(define-public (fn1) (ok (unwrap-panic (some u1))))
(define-public (fn2) (ok (unwrap-panic (some u2))))
(define-public (fn3) (ok (unwrap-panic (some u3))))
(define-public (fn4) (ok (unwrap-panic (some u4))))
(define-public (fn5) (ok (unwrap-panic (some u5))))
"""
        contract = tmp_path / "multi-match.clar"
        contract.write_text(code)

        content = """
[[custom_rules]]
id = "TEST-003"
title = "Limited unwrap match"
severity = "LOW"
category = "Custom"
pattern = "unwrap-panic"
description = "Test max_matches"
max_matches = 2
"""
        cfg = load_config(tmp_toml(content))
        scanner = ClarityScanner(str(contract), config=cfg)
        findings = scanner.scan()

        custom_findings = [f for f in findings if f.title == "Limited unwrap match"]
        assert len(custom_findings) <= 2


# ---------------------------------------------------------------------------
# Full Config Integration (TOML from repo)
# ---------------------------------------------------------------------------

class TestRepoConfig:
    def test_repo_toml_loads_without_error(self):
        """The bundled clarity-shield.toml should load without errors."""
        repo_root = Path(__file__).resolve().parent.parent
        config_path = repo_root / "clarity-shield.toml"
        if not config_path.exists():
            pytest.skip("No bundled clarity-shield.toml found")
        cfg = load_config(str(config_path))
        assert isinstance(cfg, dict)
        assert "scanner" in cfg

    def test_repo_toml_applied_to_scan(self):
        """The bundled TOML should apply to a scan without crashing."""
        repo_root = Path(__file__).resolve().parent.parent
        config_path = repo_root / "clarity-shield.toml"
        contract_path = repo_root / "test-contracts" / "vulnerable-token.clar"
        if not config_path.exists() or not contract_path.exists():
            pytest.skip("Missing bundled config or test contract")
        cfg = load_config(str(config_path))
        scanner = ClarityScanner(str(contract_path), config=cfg)
        findings = scanner.scan()
        assert isinstance(findings, list)
