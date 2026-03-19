#!/usr/bin/env python3
"""
Clarity Shield - Smart Contract Security Scanner for Stacks Blockchain
Detects common vulnerabilities in Clarity smart contracts
"""

import re
import json
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Iterator, Tuple, Optional, Set
from pathlib import Path
from enum import Enum
from datetime import datetime

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None  # type: ignore


VERSION = "2.3.0"
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Security finding data structure"""
    severity: str
    title: str
    description: str
    line: int
    code_snippet: str
    recommendation: str
    category: str
    confidence: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    
    def to_dict(self):
        return asdict(self)


def _parse_simple_value(raw: str) -> Any:
    """Parse a scalar-like config value from TOML/YAML-like text."""
    value = raw.strip()
    if not value:
        return ""
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        parts = []
        chunk = []
        in_quote = False
        quote_char = ""
        for char in inner:
            if char in {"'", '"'}:
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif quote_char == char:
                    in_quote = False
            if char == "," and not in_quote:
                part = "".join(chunk).strip()
                if part:
                    parts.append(_parse_simple_value(part))
                chunk = []
                continue
            chunk.append(char)
        tail = "".join(chunk).strip()
        if tail:
            parts.append(_parse_simple_value(tail))
        return parts
    return value


def _load_simple_yaml_config(config_path: Path) -> Dict[str, Any]:
    """
    Minimal YAML parser for Clarity Shield config files (no external dependency).

    Supports maps, inline lists, and simple `- item` lists used by scanner config.
    """
    data: Dict[str, Any] = {}
    current_section: Optional[str] = None
    pending_list_key: Optional[str] = None
    current_rule: Optional[Dict[str, Any]] = None
    custom_rule_indent: Optional[int] = None

    with config_path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.split("#", 1)[0].rstrip("\n")
            if not line.strip():
                continue

            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()

            if indent == 0:
                pending_list_key = None
                current_rule = None
                custom_rule_indent = None
                if ":" in stripped:
                    key, value = stripped.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if not value:
                        if key in {"scanner", "severity_overrides"}:
                            data[key] = {}
                        elif key == "custom_rules":
                            data[key] = []
                        else:
                            data[key] = {}
                        current_section = key
                    else:
                        data[key] = _parse_simple_value(value)
                        current_section = None
                continue

            if current_section is None:
                continue

            if current_section == "custom_rules":
                if stripped.startswith("- "):
                    item = stripped[2:].strip()
                    current_rule = {}
                    custom_rule_indent = indent
                    data.setdefault("custom_rules", []).append(current_rule)
                    if item and ":" in item:
                        key, value = item.split(":", 1)
                        current_rule[key.strip()] = _parse_simple_value(value.strip())
                elif current_rule is not None and custom_rule_indent is not None and indent > custom_rule_indent and ":" in stripped:
                    key, value = stripped.split(":", 1)
                    current_rule[key.strip()] = _parse_simple_value(value.strip())
                continue

            section_obj = data.setdefault(current_section, {})
            if not isinstance(section_obj, dict):
                continue

            if stripped.startswith("- ") and pending_list_key:
                section_obj.setdefault(pending_list_key, []).append(_parse_simple_value(stripped[2:].strip()))
                continue

            if ":" not in stripped:
                continue

            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                section_obj[key] = _parse_simple_value(value)
                pending_list_key = None
            else:
                section_obj[key] = []
                pending_list_key = key

    return data


def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load scanner config from TOML or YAML file."""
    if not config_path:
        return {}

    path = Path(config_path)
    if not path.exists():
        raise ValueError(f"Config file '{config_path}' not found")

    suffix = path.suffix.lower()
    if suffix == ".toml":
        if tomllib is None:
            raise ValueError("TOML config requires Python 3.11+ (tomllib not available)")
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    elif suffix in {".yaml", ".yml"}:
        raw = _load_simple_yaml_config(path)
    else:
        raise ValueError("Unsupported config type. Use .toml, .yaml, or .yml")

    if not isinstance(raw, dict):
        raise ValueError("Invalid config: top-level object must be a table/map")
    return raw


def _normalize_severity(value: str) -> str:
    normalized = value.strip().upper()
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Invalid severity '{value}'. Use one of: {', '.join(SEVERITY_ORDER)}")
    return normalized


class ClarityScanner:
    """Main scanner class for Clarity contracts"""

    DETECTOR_SPECS: List[Tuple[int, str]] = [
        (1, "check_tx_sender_vs_contract_caller"),
        (2, "check_unwrap_usage"),
        (3, "check_arithmetic_safety"),
        (4, "check_public_function_auth"),
        (5, "check_data_map_validation"),
        (6, "check_hardcoded_principals"),
        (7, "check_response_handling"),
        (8, "check_missing_post_conditions"),
        (9, "check_stx_transfer_safety"),
        (10, "check_block_height_dependency"),
        (11, "check_read_only_side_effects"),
        (12, "check_trait_implementation_safety"),
        (13, "check_reentrancy_patterns"),
        (14, "check_magic_numbers"),
        (15, "check_principal_injection"),
        (16, "check_unbounded_loops"),
        (17, "check_flash_loan_patterns"),
        (18, "check_missing_event_logging"),
        (19, "check_unsafe_casting"),
        (20, "check_unprotected_token_uri"),
        (21, "check_sip010_compliance"),
        (22, "check_unguarded_as_contract"),
        (23, "check_excessive_data_var_trust"),
        (24, "check_deprecated_get_block_info"),
        (25, "check_nft_owner_validation"),
        (26, "check_map_delete_without_check"),
        (27, "check_stx_balance_dependency"),
        (28, "check_missing_error_constants"),
        (29, "check_unprotected_mint"),
        (30, "check_price_oracle_manipulation"),
        (31, "check_time_lock_bypass"),
        (32, "check_unchecked_cross_contract_calls"),
        (33, "check_redundant_auth_checks"),
        (34, "check_unprotected_burn"),
        (35, "check_sip009_compliance"),
        (36, "check_unsafe_fold_accumulator"),
        (37, "check_unprotected_contract_init"),
        (38, "check_denial_of_service_patterns"),
        (39, "check_sandwich_attack_vectors"),
        (40, "check_private_key_material"),
        (41, "check_unsafe_to_int_to_uint"),
        (42, "check_unchecked_stx_get_balance"),
        (43, "check_missing_sender_validation_in_callback"),
        (44, "check_unbounded_string_input"),
        (45, "check_governance_centralization"),
        (46, "check_fee_manipulation"),
        (47, "check_deadline_missing_in_swap"),
        (48, "check_integer_truncation_division"),
        (49, "check_map_insert_without_existence_check"),
        (50, "check_stx_transfer_to_variable_recipient"),
        (51, "check_public_data_var_setter"),
        (52, "check_response_type_mismatch"),
        (53, "check_list_append_in_loop"),
        (54, "check_stx_transfer_in_fold"),
        (55, "check_missing_contract_lock"),
        (56, "check_unchecked_contract_call_response"),
        (57, "check_frontrunning_sensitive_operations"),
        (58, "check_double_spend_map_pattern"),
        (59, "check_missing_principal_check_in_callback"),
        (60, "check_unsafe_stx_liquid_supply"),
        (61, "check_unbounded_map_set_public"),
        (62, "check_missing_sip010_metadata_functions"),
        (63, "check_unsafe_string_concat_without_length_check"),
        (64, "check_governance_execution_without_timelock"),
        (65, "check_unvalidated_trait_parameter"),
        (66, "check_post_condition_missing"),
        (67, "check_reentrancy_via_dynamic_dispatch"),
        (68, "check_sip009_royalty_bypass"),
        (69, "check_flash_loan_callback_unguarded"),
        (70, "check_time_based_unlock_manipulation"),
        (71, "check_sip013_compliance"),
        (72, "check_missing_token_supply_cap"),
        (73, "check_uncapped_nft_minting"),
        (74, "check_unbounded_reward_emission"),
        (75, "check_missing_zero_amount_validation"),
        (76, "check_insecure_randomness"),
        (77, "check_single_step_privilege_transfer"),
        (78, "check_unvalidated_fee_parameter"),
        (79, "check_missing_slippage_protection"),
        (80, "check_stale_oracle_price_dependency"),
        (81, "check_unprotected_liquidity_withdrawal"),
        (82, "check_missing_emergency_pause"),
        (83, "check_mutable_token_metadata"),
        (84, "check_missing_pending_operation_timeout"),
        (85, "check_missing_minimum_deposit_amount"),
        (86, "check_unsafe_proportional_calculation"),
        (87, "check_missing_withdrawal_cooldown"),
        (88, "check_unprotected_liquidation"),
        (89, "check_missing_quorum_validation"),
        (90, "check_unchecked_transfer_return"),
        (91, "check_signature_replay"),
        (92, "check_unvalidated_oracle_update"),
        (93, "check_unsafe_at_block_usage"),
        (94, "check_division_by_zero_risk"),
    ]

    def __init__(self, contract_path: str, config: Optional[Dict[str, Any]] = None):
        self.contract_path = Path(contract_path)
        self.contract_name = self.contract_path.stem
        self.findings: List[Finding] = []
        self.lines: List[str] = []
        self.config = config or {}
        self._active_detector_id: Optional[int] = None
        self._active_detector_name: str = ""
        self.enabled_detector_ids: Set[int] = set()
        self.disabled_detector_ids: Set[int] = set()
        self.severity_overrides: Dict[str, str] = {}
        self.custom_rules: List[Dict[str, Any]] = []
        
        with open(contract_path, 'r', encoding="utf-8") as f:
            self.content = f.read()
            self.lines = self.content.split('\n')

        self._load_scanner_config()

    def _resolve_detector_ids(self, selectors: Any) -> Set[int]:
        if not isinstance(selectors, list):
            return set()

        known_by_id = {detector_id for detector_id, _ in self.DETECTOR_SPECS}
        known_by_name = {
            method_name.lower(): detector_id
            for detector_id, method_name in self.DETECTOR_SPECS
        }
        known_by_short_name = {
            method_name.replace("check_", "").lower(): detector_id
            for detector_id, method_name in self.DETECTOR_SPECS
        }

        resolved: Set[int] = set()
        for selector in selectors:
            if isinstance(selector, int) and selector in known_by_id:
                resolved.add(selector)
                continue

            selector_str = str(selector).strip().lower()
            if not selector_str:
                continue
            if selector_str.isdigit() and int(selector_str) in known_by_id:
                resolved.add(int(selector_str))
                continue
            if selector_str in known_by_name:
                resolved.add(known_by_name[selector_str])
                continue
            if selector_str in known_by_short_name:
                resolved.add(known_by_short_name[selector_str])

        return resolved

    def _load_scanner_config(self) -> None:
        scanner_cfg = self.config.get("scanner", {})
        if not isinstance(scanner_cfg, dict):
            scanner_cfg = {}

        # Keep compatibility with flat configs.
        if not scanner_cfg and any(key in self.config for key in ["enable_detectors", "disable_detectors"]):
            scanner_cfg = self.config

        self.enabled_detector_ids = self._resolve_detector_ids(scanner_cfg.get("enable_detectors", []))
        self.disabled_detector_ids = self._resolve_detector_ids(scanner_cfg.get("disable_detectors", []))

        overrides_raw = self.config.get("severity_overrides", {})
        if isinstance(overrides_raw, dict):
            for key, value in overrides_raw.items():
                try:
                    self.severity_overrides[str(key).strip().lower()] = _normalize_severity(str(value))
                except ValueError:
                    continue

        custom_rules_raw = self.config.get("custom_rules", [])
        if isinstance(custom_rules_raw, list):
            self.custom_rules = [rule for rule in custom_rules_raw if isinstance(rule, dict)]

    def _override_severity(self, base_severity: Severity, title: str) -> Severity:
        keys_to_try = []
        if self._active_detector_id is not None:
            keys_to_try.append(str(self._active_detector_id))
        if self._active_detector_name:
            keys_to_try.append(self._active_detector_name.lower())
            keys_to_try.append(self._active_detector_name.replace("check_", "").lower())
        keys_to_try.append(title.lower())

        for key in keys_to_try:
            override = self.severity_overrides.get(key)
            if override:
                return Severity[override]
        return base_severity
    
    def scan(self) -> List[Finding]:
        """Run all vulnerability checks"""
        enabled_specs: List[Tuple[int, str]] = []
        for detector_id, method_name in self.DETECTOR_SPECS:
            if self.enabled_detector_ids and detector_id not in self.enabled_detector_ids:
                continue
            if detector_id in self.disabled_detector_ids:
                continue
            enabled_specs.append((detector_id, method_name))

        detector_text = f"{len(enabled_specs)} detectors"
        if self.custom_rules:
            detector_text += f" + {len(self.custom_rules)} custom rules"
        print(f"[*] Scanning {self.contract_name} with {detector_text}...", file=sys.stderr)

        for detector_id, method_name in enabled_specs:
            detector = getattr(self, method_name, None)
            if detector is None:
                continue
            self._active_detector_id = detector_id
            self._active_detector_name = method_name
            detector()

        self._active_detector_id = None
        self._active_detector_name = ""
        self.check_custom_rules()
        
        print(f"[+] Found {len(self.findings)} potential issues", file=sys.stderr)
        return self.findings
    
    def add_finding(self, severity: Severity, title: str, description: str,
                   line: int, code_snippet: str, recommendation: str, category: str):
        """Add a security finding"""
        final_severity = self._override_severity(severity, title)
        finding = Finding(
            severity=final_severity.value,
            title=title,
            description=description,
            line=line,
            code_snippet=code_snippet.strip(),
            recommendation=recommendation,
            category=category
        )
        self.findings.append(finding)

    def check_custom_rules(self):
        """Run user-defined regex rules loaded from config."""
        if not self.custom_rules:
            return

        for idx, rule in enumerate(self.custom_rules, 1):
            pattern = str(rule.get("pattern", "")).strip()
            if not pattern:
                continue

            rule_id = str(rule.get("id", f"custom-{idx}"))
            title = str(rule.get("title", f"Custom Rule {rule_id}"))
            severity_name = str(rule.get("severity", "MEDIUM"))
            try:
                severity = Severity[_normalize_severity(severity_name)]
            except ValueError:
                severity = Severity.MEDIUM

            description = str(
                rule.get(
                    "description",
                    f"Custom rule '{rule_id}' matched configured pattern: {pattern}",
                )
            )
            recommendation = str(
                rule.get("recommendation", "Review this pattern and apply project-specific hardening.")
            )
            category = str(rule.get("category", "Custom Rule"))
            confidence = str(rule.get("confidence", "MEDIUM"))

            flags = re.IGNORECASE if bool(rule.get("ignore_case", True)) else 0
            try:
                regex = re.compile(pattern, flags)
            except re.error:
                continue

            max_matches = rule.get("max_matches", 0)
            if isinstance(max_matches, str) and max_matches.isdigit():
                max_matches = int(max_matches)
            if not isinstance(max_matches, int) or max_matches < 0:
                max_matches = 0

            match_count = 0
            previous_detector_name = self._active_detector_name
            self._active_detector_name = f"custom-rule:{rule_id}".lower()
            for i, line in enumerate(self.lines, 1):
                code = self._strip_comments(line)
                if regex.search(code):
                    self.add_finding(
                        severity,
                        title,
                        description,
                        i,
                        line,
                        recommendation,
                        category,
                    )
                    if self.findings:
                        self.findings[-1].confidence = confidence
                    match_count += 1
                    if max_matches > 0 and match_count >= max_matches:
                        break
            self._active_detector_name = previous_detector_name

    def _strip_comments(self, line: str) -> str:
        """Remove Clarity line comments from a source line."""
        return line.split(";;", 1)[0]

    def _paren_delta(self, line: str) -> int:
        """Track parenthesis balance while ignoring comments and string literals."""
        code = self._strip_comments(line)
        code = re.sub(r'"[^"]*"', '', code)
        return code.count('(') - code.count(')')

    def _iter_function_blocks(self, kind: str) -> Iterator[Tuple[str, int, int, List[str]]]:
        """
        Yield function blocks with balanced-paren boundaries.

        Returns tuples of: (function_name, start_line, end_line, block_lines).
        """
        pattern = re.compile(rf'\(define-{re.escape(kind)}\s+\(([^\s)]+)')
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            match = pattern.search(self._strip_comments(line))
            if not match:
                i += 1
                continue

            func_name = match.group(1)
            start_line = i + 1
            block_lines = [line]
            depth = self._paren_delta(line)
            j = i + 1

            while j < len(self.lines) and depth > 0:
                block_lines.append(self.lines[j])
                depth += self._paren_delta(self.lines[j])
                j += 1

            end_line = j if j > i else i + 1
            yield func_name, start_line, end_line, block_lines
            i = max(j, i + 1)

    def _extract_function_params(self, header_line: str) -> List[str]:
        """Extract parameter names from a function declaration header line."""
        code = self._strip_comments(header_line)
        return [
            match.group(1)
            for match in re.finditer(r'\(([a-zA-Z0-9_-]+)\s+[^()]+\)', code)
        ]
    
    def check_tx_sender_vs_contract_caller(self):
        """Detect authorization bypass via contract-caller misuse"""
        comparison_patterns = [
            r'\(is-eq\s+contract-caller\s+([^)]+)\)',
            r'\(is-eq\s+([^)]+)\s+contract-caller\)'
        ]

        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'contract-caller' not in code or 'is-eq' not in code:
                continue

            flagged = False
            for pattern in comparison_patterns:
                match = re.search(pattern, code, re.IGNORECASE)
                if not match:
                    continue
                compared_expr = match.group(1).strip().lower()
                if re.match(r"^'s[0-9a-z]+\.[a-z0-9-]+$", compared_expr) or re.match(r"^\.[a-z0-9-]+$", compared_expr):
                    # Explicit allowlist of a contract principal is a common and often valid pattern.
                    continue
                if re.search(r'(admin|owner|govern|operator|authority|auth)', compared_expr):
                    flagged = True
                    break

            if flagged:
                self.add_finding(
                    Severity.CRITICAL,
                    "Authorization Bypass Risk: contract-caller in Access Control",
                    "Using 'contract-caller' for authorization allows any intermediate "
                    "contract to impersonate the caller. An attacker can deploy a malicious "
                    "contract that calls this function, bypassing access controls.",
                    i,
                    line,
                    "Use 'tx-sender' for authorization checks instead of 'contract-caller'. "
                    "Only use 'contract-caller' when you explicitly need to authorize "
                    "the immediate calling contract.",
                    "Authorization"
                )
    
    def check_unwrap_usage(self):
        """Detect unsafe unwrap operations that can cause DoS"""
        patterns = [
            (r'unwrap-panic', "unwrap-panic causes transaction to abort, potential DoS vector"),
            (r'unwrap!\s*\([^)]+\)\s*\)', "unwrap! without error handling can cause unexpected failures")
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    severity = Severity.HIGH if 'panic' in pattern else Severity.MEDIUM
                    self.add_finding(
                        severity,
                        "Unsafe Unwrap Operation",
                        f"{desc}. If the optional/response value is none/err, the entire "
                        "transaction will fail. Attacker can exploit this for DoS.",
                        i,
                        line,
                        "Use 'match' or 'default-to' for safer error handling. For response types, "
                        "propagate errors with 'try!' or explicitly handle with pattern matching.",
                        "Error Handling"
                    )
    
    def check_arithmetic_safety(self):
        """Detect unchecked arithmetic operations"""
        arithmetic_ops = [r'\+\s+\w+\s+\w+', r'-\s+\w+\s+\w+', r'\*\s+\w+\s+\w+']
        
        for i, line in enumerate(self.lines, 1):
            for op_pattern in arithmetic_ops:
                if re.search(op_pattern, line):
                    # Check if there's overflow/underflow protection nearby
                    context_start = max(0, i-3)
                    context_end = min(len(self.lines), i+3)
                    context = '\n'.join(self.lines[context_start:context_end])
                    
                    has_check = any(keyword in context for keyword in [
                        'asserts!', '>=', '<=', 'u128', 'overflow', 'underflow'
                    ])
                    
                    if not has_check and 'uint' in line:
                        self.add_finding(
                            Severity.MEDIUM,
                            "Potential Integer Overflow/Underflow",
                            "Arithmetic operation on uint without bounds checking. Clarity uint "
                            "types wrap on overflow/underflow, which can lead to logic errors.",
                            i,
                            line,
                            "Add explicit bounds checks before arithmetic operations: "
                            "(asserts! (<= (+ a b) u340282366920938463463374607431768211455) ERR_OVERFLOW)",
                            "Arithmetic Safety"
                        )
    
    def check_public_function_auth(self):
        """Check if public functions have authorization checks"""
        sensitive_name_keywords = [
            'admin', 'owner', 'govern', 'protocol', 'set-', 'update',
            'upgrade', 'pause', 'configure', 'mint', 'burn'
        ]
        state_change_keywords = [
            'map-set', 'map-insert', 'map-delete', 'var-set',
            'ft-mint?', 'ft-burn?', 'nft-mint?', 'nft-burn?', 'stx-transfer?',
            'as-contract'
        ]
        auth_indicators = [
            'tx-sender', 'contract-caller', 'is-admin', 'is-owner',
            'is-protocol-caller', 'is-lending-pool', 'only-owner',
            'var-get admin', 'var-get owner', 'var-get contract-owner'
        ]

        for func_name, func_start_line, _, func_lines in self._iter_function_blocks('public'):
            func_name_lower = func_name.lower()
            func_body = '\n'.join(func_lines)
            func_body_lower = func_body.lower()

            if not any(keyword in func_name_lower for keyword in sensitive_name_keywords):
                continue

            has_state_change = any(keyword in func_body_lower for keyword in state_change_keywords)
            if not has_state_change:
                continue

            has_auth = any(indicator in func_body_lower for indicator in auth_indicators)
            if not has_auth and re.search(r'asserts!\s*\(\s*is-[a-z0-9-]+', func_body_lower):
                has_auth = True
            if not has_auth:
                self.add_finding(
                    Severity.HIGH,
                    f"Missing Authorization Check in Public Function '{func_name}'",
                    f"The public function '{func_name}' appears to perform privileged state "
                    "changes but lacks obvious caller authorization checks.",
                    func_start_line,
                    func_lines[0],
                    "Add authorization checks using 'tx-sender' or a vetted role guard, for "
                    "example: (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)",
                    "Access Control"
                )
    
    def check_data_map_validation(self):
        """Check for unsafe data map access"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)

            # Check map-set without validation
            if 'map-set' in code:
                context_start = max(0, i-12)
                context = '\n'.join(self.lines[context_start:i])
                context_lower = context.lower()
                
                has_validation = any(keyword in context_lower for keyword in [
                    'asserts!', 'is-eq', 'map-get?', 'default-to',
                    'match', 'if ', 'try!', 'unwrap!', 'is-none', 'is-some'
                ])
                
                if not has_validation:
                    self.add_finding(
                        Severity.MEDIUM,
                        "Data Map Set Without Prior Validation",
                        "Setting map values without checking existing state can lead to "
                        "data inconsistencies or unauthorized state changes.",
                        i,
                        line,
                        "Validate map state before setting: use 'map-get?' to check existing "
                        "values and add assertions to ensure state transitions are valid.",
                        "Data Validation"
                    )
            
            # Check map-get? without default-to
            if re.search(r'map-get\?\s+\w+', code):
                context_end = min(len(self.lines), i+4)
                context = '\n'.join(self.lines[i-1:context_end])
                context_lower = context.lower()
                
                has_default = any(keyword in context_lower for keyword in [
                    'default-to', 'match', 'unwrap!', 'unwrap-panic',
                    'try!', 'asserts!', 'is-none', 'is-some'
                ])
                
                if not has_default:
                    self.add_finding(
                        Severity.LOW,
                        "Map Access Without Default Value",
                        "Accessing map without default-to can result in optional unwrapping issues.",
                        i,
                        line,
                        "Wrap map-get? with 'default-to' to handle missing keys: "
                        "(default-to u0 (map-get? balances {user: tx-sender}))",
                        "Data Validation"
                    )
    
    def check_hardcoded_principals(self):
        """Detect hardcoded principal addresses (centralization risk)"""
        principal_pattern = r"'[STSPN][0-9A-Z]{28,}"
        
        for i, line in enumerate(self.lines, 1):
            if re.search(principal_pattern, line):
                self.add_finding(
                    Severity.INFO,
                    "Hardcoded Principal Address Detected",
                    "Hardcoded principal addresses create centralization risks and "
                    "make contract upgrades difficult.",
                    i,
                    line,
                    "Consider using data variables for administrative addresses that can "
                    "be updated: (define-data-var contract-owner principal 'SP...)",
                    "Centralization"
                )
    
    def check_response_handling(self):
        """Check for proper response type handling in function calls"""
        function_blocks = list(self._iter_function_blocks('public')) + list(self._iter_function_blocks('private'))

        for _, func_start, _, func_lines in function_blocks:
            for offset, line in enumerate(func_lines):
                line_num = func_start + offset
                code = self._strip_comments(line)
                if 'contract-call?' not in code:
                    continue
                if 'define-constant' in code:
                    continue

                stripped = code.strip()

                # Returning a contract call directly is common and not inherently unsafe.
                if stripped.startswith('(contract-call?'):
                    continue

                local_window_end = min(len(func_lines), offset + 5)
                local_context = '\n'.join(func_lines[offset:local_window_end]).lower()

                has_response_handling = any(keyword in local_context for keyword in [
                    'try!', 'match', 'unwrap!', 'unwrap-panic', 'is-ok', 'is-err', 'default-to'
                ])

                if not has_response_handling:
                    self.add_finding(
                        Severity.MEDIUM,
                        "Unhandled Response from Contract Call",
                        "Contract calls return response types that must be handled. "
                        "Ignoring response can lead to silent failures.",
                        line_num,
                        line,
                        "Handle the response using 'try!' to propagate errors or 'match' "
                        "to handle success/failure explicitly.",
                        "Error Handling"
                    )


    def check_missing_post_conditions(self):
        """Detect STX/token transfers without post-condition annotations"""
        transfer_fns = ['stx-transfer?', 'ft-transfer?', 'nft-transfer?']
        for i, line in enumerate(self.lines, 1):
            for fn in transfer_fns:
                if fn in line:
                    # Check if any post-condition comment/annotation nearby
                    context_start = max(0, i - 10)
                    context = '\n'.join(self.lines[context_start:i])
                    if 'post-condition' not in context.lower():
                        self.add_finding(
                            Severity.MEDIUM,
                            f"Transfer Without Post-Condition Documentation ({fn})",
                            f"The function uses '{fn}' but has no documented post-conditions. "
                            "Stacks transactions can include post-conditions to limit token "
                            "movement. Without clear documentation, wallets may reject the "
                            "transaction or users may not set protective post-conditions.",
                            i,
                            line,
                            "Document expected post-conditions in comments. Consider adding "
                            "a ;; @post-condition annotation so wallets/frontends can enforce limits.",
                            "Post-Conditions"
                        )

    def check_stx_transfer_safety(self):
        """Check for STX transfers that could drain contract balance"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'stx-transfer?' in code and 'as-contract' in code:
                # Heuristic: focus on generic amount-driven transfers; skip derived payout variables.
                if not re.search(r'\b(amount|amt|value)\b', code, re.IGNORECASE):
                    continue
                # Contract is sending its own STX — high risk
                func_context_start = max(0, i - 20)
                context = '\n'.join(self.lines[func_context_start:i])
                has_limit = any(k in context for k in ['asserts!', '<=', '<', 'min'])
                if not has_limit:
                    self.add_finding(
                        Severity.HIGH,
                        "Unbounded STX Transfer from Contract",
                        "The contract transfers STX using 'as-contract' without apparent "
                        "amount validation. An attacker who can control the amount parameter "
                        "could drain the contract's entire STX balance.",
                        i,
                        line,
                        "Add maximum transfer limits and validate amounts: "
                        "(asserts! (<= amount (var-get max-withdrawal)) ERR_AMOUNT_TOO_HIGH)",
                        "Fund Safety"
                    )

    def check_block_height_dependency(self):
        """Detect unsafe reliance on block-height for time-critical logic"""
        for i, line in enumerate(self.lines, 1):
            if 'block-height' in line:
                context_end = min(len(self.lines), i + 3)
                context = '\n'.join(self.lines[i-1:context_end])
                if any(k in context for k in ['unlock', 'deadline', 'expir', 'lock', 'vest']):
                    self.add_finding(
                        Severity.LOW,
                        "Block-Height Used for Time-Sensitive Logic",
                        "Block-height is used near time-sensitive logic (locking/unlocking). "
                        "Stacks block times are variable (especially post-Nakamoto), so "
                        "block-height is an unreliable time proxy.",
                        i,
                        line,
                        "Consider using tenure-height or documenting the expected block time "
                        "assumptions. Alert users that timing may vary.",
                        "Timing"
                    )

    def check_read_only_side_effects(self):
        """Check that read-only functions don't attempt state changes"""
        state_changers = ['map-set', 'map-delete', 'map-insert',
                          'var-set', 'stx-transfer?', 'ft-transfer?',
                          'nft-transfer?', 'ft-mint?', 'nft-mint?',
                          'ft-burn?', 'nft-burn?']

        for _, func_start, _, func_lines in self._iter_function_blocks('read-only'):
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                for sc in state_changers:
                    if sc in code:
                        self.add_finding(
                            Severity.HIGH,
                            "State-Changing Call in Read-Only Function",
                            f"A read-only function contains '{sc}' which attempts state "
                            "mutation. While Clarity will reject this at deployment, it "
                            "indicates a logic error in the contract design.",
                            func_start + offset,
                            line,
                            "Move state-changing logic to a public function, or remove "
                            "the mutation from the read-only function.",
                            "Logic Error"
                        )

    def check_reentrancy_patterns(self):
        """Detect state changes after external contract calls (reentrancy-like patterns)"""
        state_changers = {'map-set', 'map-delete', 'map-insert', 'var-set'}

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            saw_external_call = False
            external_call_line = 0
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if 'contract-call?' in code:
                    saw_external_call = True
                    external_call_line = func_start + offset
                if saw_external_call:
                    for sc in state_changers:
                        if sc in code:
                            self.add_finding(
                                Severity.HIGH,
                                f"State Change After External Call in '{func_name}' (Reentrancy Pattern)",
                                f"'{sc}' occurs after 'contract-call?' (line {external_call_line}). "
                                "While Clarity prevents traditional reentrancy, state changes after "
                                "external calls can lead to inconsistent state if the call fails "
                                "or if future Clarity versions relax call restrictions.",
                                func_start + offset,
                                line,
                                "Follow checks-effects-interactions: perform state changes BEFORE "
                                "external calls, not after.",
                                "Reentrancy"
                            )
                            break

    def check_magic_numbers(self):
        """Detect raw numeric literals that should be named constants"""
        # Only flag large/unusual numbers, not common ones like u0, u1, u100
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'define-constant' in code or code.strip().startswith(';;'):
                continue
            matches = re.findall(r'\bu(\d+)\b', code)
            for m in matches:
                val = int(m)
                if val > 1000 and val != 1000000:  # skip trivially common values
                    self.add_finding(
                        Severity.INFO,
                        f"Magic Number u{m} — Consider Named Constant",
                        f"The literal u{m} appears inline. Magic numbers reduce readability "
                        "and make audits harder.",
                        i,
                        line,
                        f"Define a named constant: (define-constant MEANINGFUL_NAME u{m})",
                        "Code Quality"
                    )

    def check_principal_injection(self):
        """Detect functions that accept principal params and use them in privileged ops"""
        privileged_ops = ['stx-transfer?', 'ft-mint?', 'nft-mint?', 'ft-transfer?', 'nft-transfer?']

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            header = func_lines[0] if func_lines else ''
            if 'principal' not in header:
                continue
            func_body = '\n'.join(func_lines)
            for op in privileged_ops:
                if op in func_body:
                    # Check if there's validation of the principal param
                    if not any(k in func_body for k in ['is-eq', 'asserts!', 'contract-caller', 'tx-sender']):
                        self.add_finding(
                            Severity.HIGH,
                            f"Unvalidated Principal in Privileged Operation '{func_name}'",
                            f"Function accepts a principal parameter and uses it in '{op}' "
                            "without validating the principal. An attacker could pass an "
                            "arbitrary address to redirect funds or mint tokens.",
                            func_start,
                            header,
                            "Validate principal parameters against tx-sender or an allowlist "
                            "before using them in privileged operations.",
                            "Input Validation"
                        )
                    break

    def check_trait_implementation_safety(self):
        """Detect trait usage without proper validation"""
        for i, line in enumerate(self.lines, 1):
            # Detect dynamic dispatch via trait references in function params
            if re.search(r'<[A-Za-z-]+>', line) and 'define-public' in line:
                self.add_finding(
                    Severity.MEDIUM,
                    "Dynamic Dispatch via Trait Parameter",
                    "Function accepts a trait reference as parameter, enabling dynamic "
                    "dispatch. A caller can pass any contract implementing the trait, "
                    "potentially one with malicious side effects.",
                    i,
                    line,
                    "Validate the trait implementor against an allowlist of known-good "
                    "contracts, or use 'contract-call?' with static contract references.",
                    "Trait Safety"
                )

    def check_unbounded_loops(self):
        """Detect potential unbounded iteration patterns (DoS risk)"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            # fold and map over user-controlled lists
            for op in ['fold', 'map', 'filter']:
                if f'({op} ' in func_body:
                    # Check if iterating over a variable-length input
                    if any(k in func_body for k in ['(list ', 'get-list', 'contract-call?']):
                        self.add_finding(
                            Severity.MEDIUM,
                            f"Potential Unbounded Iteration in '{func_name}'",
                            f"Function uses '{op}' which may iterate over data of "
                            "unbounded or user-controlled length. In Clarity, iterations "
                            "consume compute units per element and can hit runtime limits.",
                            func_start,
                            func_lines[0] if func_lines else '',
                            f"Ensure the list passed to '{op}' has a bounded, known maximum "
                            "length. Use fixed-size lists and validate input length upfront.",
                            "Denial of Service"
                        )
                    break

    def check_flash_loan_patterns(self):
        """Detect patterns vulnerable to flash loan manipulation"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            # Price reads followed by transfers in same function
            has_price_read = any(k in func_body for k in [
                'get-price', 'get-balance', 'get-reserve', 'get-rate',
                'stx-get-balance', 'ft-get-balance', 'get-stx-balance'
            ])
            has_transfer = any(k in func_body for k in [
                'stx-transfer?', 'ft-transfer?', 'ft-mint?'
            ])
            if has_price_read and has_transfer:
                self.add_finding(
                    Severity.HIGH,
                    f"Flash Loan Vulnerability Pattern in '{func_name}'",
                    "Function reads a balance or price and then performs a token "
                    "operation in the same transaction. An attacker could manipulate "
                    "the price/balance via a flash loan before this function executes.",
                    func_start,
                    func_lines[0] if func_lines else '',
                    "Use time-weighted average prices (TWAP) or oracles instead of "
                    "spot balances. Add minimum delay between price reads and actions.",
                    "Flash Loan"
                )

    def check_missing_event_logging(self):
        """Detect state-changing functions without print events"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            # State changes: map-set, map-delete, var-set, stx-transfer, ft/nft ops
            state_ops = ['map-set', 'map-delete', 'var-set', 'stx-transfer?',
                        'ft-transfer?', 'ft-mint?', 'ft-burn?', 'nft-mint?', 'nft-burn?']
            has_state_change = any(op in func_body for op in state_ops)
            has_event = 'print' in func_body
            if has_state_change and not has_event:
                self.add_finding(
                    Severity.LOW,
                    f"Missing Event Logging in '{func_name}'",
                    "Function modifies contract state but does not emit a print event. "
                    "Events are critical for off-chain indexers, explorers, and audit trails.",
                    func_start,
                    func_lines[0] if func_lines else '',
                    "Add (print { event: \"action-name\", ... }) to emit structured events "
                    "for all state-changing operations.",
                    "Best Practice"
                )



    def check_unsafe_casting(self):
        """Detect unsafe int/uint conversions that can cause runtime errors"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'to-int' in code or 'to-uint' in code:
                context_start = max(0, i - 5)
                context = '\n'.join(self.lines[context_start:i])
                has_guard = any(k in context for k in ['asserts!', '<=', '>=', '<', '>', 'if ', 'match'])
                if not has_guard:
                    cast_fn = 'to-int' if 'to-int' in code else 'to-uint'
                    self.add_finding(
                        Severity.MEDIUM,
                        f"Unsafe {cast_fn} Cast Without Range Check",
                        f"'{cast_fn}' can fail at runtime if the value is out of range. "
                        "to-int fails for uint values > MAX_INT, to-uint fails for negative ints. "
                        "This causes a runtime abort, exploitable for DoS.",
                        i,
                        line,
                        f"Add a range check before casting: "
                        f"(asserts! (<= value u170141183460469231731687303715884105727) ERR_OVERFLOW) "
                        f"before (to-int value).",
                        "Type Safety"
                    )

    def check_unprotected_token_uri(self):
        """Detect NFT/FT URI setter functions without access control"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_name_lower = func_name.lower()
            if 'uri' not in func_name_lower and 'metadata' not in func_name_lower:
                continue
            func_body = '\n'.join(func_lines)
            if 'var-set' in func_body:
                auth_indicators = ['tx-sender', 'contract-caller', 'is-eq', 'asserts!']
                if not any(k in func_body for k in auth_indicators):
                    self.add_finding(
                        Severity.HIGH,
                        f"Unprotected Token URI Setter '{func_name}'",
                        "Token URI/metadata setter has no access control. An attacker could "
                        "change NFT metadata to point to malicious content, enabling phishing "
                        "or rug-pull scenarios where NFT images/data are swapped.",
                        func_start,
                        func_lines[0] if func_lines else '',
                        "Add owner-only access control: "
                        "(asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)",
                        "Access Control"
                    )

    def check_sip010_compliance(self):
        """Check if FT contracts implement required SIP-010 functions"""
        if 'ft-mint?' not in self.content and 'define-fungible-token' not in self.content:
            return
        required_fns = ['transfer', 'get-name', 'get-symbol', 'get-decimals',
                       'get-balance', 'get-total-supply', 'get-token-uri']
        defined_fns = set()
        for func_name, _, _, _ in self._iter_function_blocks('public'):
            defined_fns.add(func_name.lower())
        for func_name, _, _, _ in self._iter_function_blocks('read-only'):
            defined_fns.add(func_name.lower())

        missing = [fn for fn in required_fns if fn not in defined_fns]
        if missing:
            self.add_finding(
                Severity.MEDIUM,
                "Incomplete SIP-010 Fungible Token Interface",
                f"This contract defines a fungible token but is missing SIP-010 required "
                f"functions: {', '.join(missing)}. Non-compliant tokens may not work with "
                "wallets, DEXes, and block explorers.",
                1,
                self.lines[0] if self.lines else '',
                f"Implement the missing functions: {', '.join(missing)}. "
                "See https://github.com/stacksgov/sips/blob/main/sips/sip-010.md",
                "Standards Compliance"
            )

    def check_unguarded_as_contract(self):
        """Detect as-contract usage without proper authorization context"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            if 'as-contract' not in func_body:
                continue
            # as-contract elevates to contract principal — needs auth
            auth_before = False
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if any(k in code for k in ['asserts!', 'is-eq', 'tx-sender', 'contract-caller']):
                    auth_before = True
                if 'as-contract' in code and not auth_before:
                    self.add_finding(
                        Severity.HIGH,
                        f"Unguarded as-contract Privilege Escalation in '{func_name}'",
                        "'as-contract' grants the function contract-level privileges "
                        "(can move the contract's own funds/assets). Without prior "
                        "authorization checks, any caller can trigger privileged operations.",
                        func_start + offset,
                        line,
                        "Add authorization checks BEFORE the as-contract block: "
                        "(asserts! (is-eq tx-sender (var-get admin)) ERR_UNAUTHORIZED)",
                        "Privilege Escalation"
                    )
                    break

    def check_excessive_data_var_trust(self):
        """Detect data-var values used directly in transfer amounts without validation"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            if 'stx-transfer?' not in func_body and 'ft-transfer?' not in func_body:
                continue
            # Check if transfer amount comes from var-get without bounds check
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if ('stx-transfer?' in code or 'ft-transfer?' in code) and 'var-get' in code:
                    local_start = max(0, offset - 8)
                    local_context = '\n'.join(func_lines[local_start:offset + 1])
                    if not any(k in local_context for k in ['asserts!', '<=', '<', 'min']):
                        self.add_finding(
                            Severity.MEDIUM,
                            f"Transfer Amount from Data Variable Without Bounds in '{func_name}'",
                            "Transfer amount is read directly from a data variable. If an admin "
                            "function can set this variable without bounds checking, it could be "
                            "used to drain funds (either by a compromised admin or governance attack).",
                            func_start + offset,
                            line,
                            "Add maximum bounds on data variable values when they're set, and "
                            "validate again before using them in transfers.",
                            "Fund Safety"
                        )
                    break


    def check_deprecated_get_block_info(self):
        """Detect usage of deprecated get-block-info? function"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'get-block-info?' in code and 'at-block' not in code:
                self.add_finding(
                    Severity.LOW,
                    f"Deprecated get-block-info? Usage (line {i})",
                    "get-block-info? is deprecated in Clarity 2+ in favor of "
                    "at-block and block-height builtins. Using deprecated functions "
                    "may cause issues with future Stacks upgrades (Nakamoto).",
                    i,
                    line,
                    "Migrate to Clarity 2 block info accessors. "
                    "See SIP-015 for Clarity 2 migration guide.",
                    "Deprecation"
                )

    def check_nft_owner_validation(self):
        """Detect NFT transfers without ownership validation"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            if 'nft-transfer?' not in func_body:
                continue
            has_owner_check = any(
                'nft-get-owner?' in self._strip_comments(l) for l in func_lines
            )
            if not has_owner_check:
                for offset, line in enumerate(func_lines):
                    if 'nft-transfer?' in self._strip_comments(line):
                        self.add_finding(
                            Severity.HIGH,
                            f"NFT Transfer Without Ownership Validation in '{func_name}'",
                            "nft-transfer? is called without first verifying ownership via "
                            "nft-get-owner?. This could allow unauthorized users to transfer "
                            "NFTs they don't own if tx-sender/contract-caller checks are insufficient.",
                            func_start + offset,
                            line,
                            "Verify NFT ownership with (nft-get-owner? <asset> <id>) before "
                            "calling nft-transfer?, and assert the caller is the owner.",
                            "Access Control"
                        )
                        break

    def check_map_delete_without_check(self):
        """Detect map-delete calls without existence checks"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            if 'map-delete' not in func_body:
                continue
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if 'map-delete' not in code:
                    continue
                local_start = max(0, offset - 5)
                local_context = '\n'.join(func_lines[local_start:offset + 1])
                if 'map-get?' not in local_context:
                    self.add_finding(
                        Severity.MEDIUM,
                        f"Map Delete Without Existence Check in '{func_name}'",
                        "map-delete is called without first checking if the entry exists "
                        "via map-get?. While map-delete on a non-existent key returns false, "
                        "the lack of validation may mask logic errors or allow replay attacks "
                        "where the same delete is called multiple times.",
                        func_start + offset,
                        line,
                        "Check existence with (map-get? ...) before deleting, and handle "
                        "the case where the entry doesn't exist.",
                        "Data Integrity"
                    )

    def check_stx_balance_dependency(self):
        """Detect contract logic depending on stx-get-balance for authorization"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            if 'stx-get-balance' not in func_body:
                continue
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if 'stx-get-balance' in code:
                    local_start = max(0, offset - 3)
                    local_end = min(len(func_lines), offset + 4)
                    local_context = '\n'.join(func_lines[local_start:local_end])
                    if any(k in local_context for k in ['asserts!', 'if', 'when']):
                        self.add_finding(
                            Severity.MEDIUM,
                            f"Balance-Dependent Logic in '{func_name}'",
                            "Contract logic branches on stx-get-balance. An attacker can "
                            "manipulate their STX balance within a single transaction (e.g., "
                            "borrow via flash-loan patterns) to bypass balance-based gates.",
                            func_start + offset,
                            line,
                            "Avoid using balance checks for authorization or access control. "
                            "Use explicit role-based access or token holdings tracked in data maps.",
                            "Economic Manipulation"
                        )
                        break

    def check_missing_error_constants(self):
        """Detect raw integer error codes instead of named constants"""
        raw_err_pattern = re.compile(r'\(err\s+u\d+\)')
        has_err_constant = any(
            re.search(r'\(define-constant\s+ERR[-_]', self._strip_comments(l))
            for l in self.lines
        )
        raw_count = 0
        first_line = None
        first_code = None
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if raw_err_pattern.search(code):
                raw_count += 1
                if first_line is None:
                    first_line = i
                    first_code = line
        if raw_count >= 3 and not has_err_constant:
            self.add_finding(
                Severity.INFO,
                f"Raw Integer Error Codes ({raw_count} occurrences)",
                f"Contract uses {raw_count} raw (err uN) values without named error "
                "constants. This reduces readability, makes debugging harder, and "
                "increases the risk of duplicate or conflicting error codes.",
                first_line,
                first_code,
                "Define named error constants: (define-constant ERR_UNAUTHORIZED (err u401)) "
                "and use them throughout the contract.",
                "Code Quality"
            )

    def check_unprotected_mint(self):
        """Detect mint functions without authorization checks"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            header = self._strip_comments(func_lines[0])
            if not re.search(r'\(define-public\s+\((mint|ft-mint|nft-mint)', header):
                continue
            # Search only within this function's body (no cross-function bleed)
            context = ' '.join(self._strip_comments(l) for l in func_lines)
            if not re.search(r'(is-eq\s+(contract-caller|tx-sender)|asserts!.*contract-caller|asserts!.*tx-sender|asserts!\s*\(\s*is-(owner|admin|authorized|protocol|minter))', context):
                self.add_finding(
                    Severity.CRITICAL,
                    'Unprotected Mint Function',
                    'A public mint function lacks authorization checks. Anyone can call '
                    'this function to mint tokens, potentially causing unlimited inflation.',
                    func_start, func_lines[0],
                    'Add authorization: (asserts! (is-eq contract-caller CONTRACT-OWNER) ERR_UNAUTHORIZED)',
                    'Access Control'
                )

    def check_price_oracle_manipulation(self):
        """Detect reliance on single price sources without validation"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if re.search(r'(get-price|oracle-price|price-feed|get-stx-price)', code):
                context_start = max(0, i - 3)
                context_end = min(len(self.lines), i + 3)
                context = ' '.join(self._strip_comments(l) for l in self.lines[context_start:context_end])
                if not re.search(r'(asserts?!|>|<|>=|<=).*price', context, re.IGNORECASE):
                    self.add_finding(
                        Severity.HIGH,
                        'Unvalidated Price Oracle Usage',
                        'Price data from an oracle is used without bounds checking or staleness '
                        'validation. An attacker who controls or manipulates the oracle can exploit '
                        'price-dependent logic.',
                        i, line,
                        'Add price bounds validation and check oracle freshness timestamps.',
                        'Oracle Security'
                    )

    def check_time_lock_bypass(self):
        """Detect time-lock mechanisms that can be bypassed"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if re.search(r'\(define-public\s+\((set-.*(?:unlock|lock|time|cooldown))', code):
                self.add_finding(
                    Severity.HIGH,
                    'Potentially Bypassable Time-Lock Setter',
                    'A public function exists that can modify time-lock parameters. If this '
                    'function lacks proper authorization, attackers can bypass withdrawal delays.',
                    i, line,
                    'Ensure time-lock setter functions have strict authorization and consider '
                    'making time-lock values immutable or governable by multisig.',
                    'Temporal Security'
                )

    def check_unchecked_cross_contract_calls(self):
        """Detect contract-call? without proper error handling"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if 'contract-call?' not in code:
                    continue
                
                # Check if wrapped in try!, unwrap!, unwrap-panic, match, or if
                context_start = max(0, offset - 2)
                context_end = min(len(func_lines), offset + 3)
                context = ' '.join(self._strip_comments(l) for l in func_lines[context_start:context_end])
                
                if not re.search(r'\b(try!|unwrap!|unwrap-panic|match|\(if\s)', context):
                    self.add_finding(
                        Severity.HIGH,
                        f"Unchecked Cross-Contract Call in '{func_name}'",
                        "contract-call? is used without wrapping the result in try!, unwrap!, "
                        "unwrap-panic, match, or if. If the external contract call fails or returns "
                        "an error, this could lead to unexpected behavior or silent failures.",
                        func_start + offset,
                        line,
                        "Wrap contract-call? in (try! ...) to propagate errors, or use (match ...) "
                        "to handle both success and error cases explicitly.",
                        "Error Handling"
                    )

    def check_redundant_auth_checks(self):
        """Detect functions checking both tx-sender and contract-caller against same variable"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            
            # Look for patterns where both tx-sender and contract-caller are checked against the same variable
            tx_sender_checks = re.findall(r'is-eq\s+tx-sender\s+(\S+)', func_body)
            contract_caller_checks = re.findall(r'is-eq\s+contract-caller\s+(\S+)', func_body)
            
            # Also check reverse order
            tx_sender_checks += re.findall(r'is-eq\s+(\S+)\s+tx-sender', func_body)
            contract_caller_checks += re.findall(r'is-eq\s+(\S+)\s+contract-caller', func_body)
            
            common_vars = set(tx_sender_checks) & set(contract_caller_checks)
            if common_vars:
                for offset, line in enumerate(func_lines):
                    if any(var in line for var in common_vars):
                        self.add_finding(
                            Severity.INFO,
                            f"Redundant Authorization Check in '{func_name}'",
                            f"Function checks both tx-sender and contract-caller against the same "
                            f"variable(s): {', '.join(common_vars)}. This is redundant - typically only "
                            f"one check is needed. tx-sender is the original transaction signer, while "
                            f"contract-caller is the immediate caller (which could be another contract).",
                            func_start + offset,
                            line,
                            "Choose the appropriate authorization principal: use tx-sender for end-user "
                            "authorization, or contract-caller for contract-to-contract interactions. "
                            "Remove the redundant check.",
                            "Code Quality"
                        )
                        break

    def check_unprotected_burn(self):
        """Detect burn functions without authorization checks"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            header = self._strip_comments(func_lines[0])
            if not re.search(r'\(define-public\s+\((burn|ft-burn|nft-burn)', header):
                continue
            # Search only within this function's body (no cross-function bleed)
            context = ' '.join(self._strip_comments(l) for l in func_lines)
            if not re.search(r'(is-eq\s+(contract-caller|tx-sender)|asserts!.*contract-caller|asserts!.*tx-sender|asserts!\s*\(\s*is-(owner|admin|authorized|protocol|minter))', context):
                self.add_finding(
                    Severity.HIGH,
                    'Unprotected Burn Function',
                    'A public burn function lacks authorization checks. Anyone can call '
                    'this function to burn tokens, potentially destroying user assets without permission.',
                    func_start, func_lines[0],
                    'Add authorization to verify that only the token owner or an authorized '
                    'party can burn tokens: (asserts! (is-eq tx-sender token-owner) ERR_UNAUTHORIZED)',
                    'Access Control'
                )


    def check_unsafe_fold_accumulator(self):
        """Detect fold operations where accumulator could overflow or be manipulated"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if '(fold' in code:
                context = ' '.join(self._strip_comments(l) for l in self.lines[i:min(i+5, len(self.lines))])
                if any(op in context for op in ['(+ ', '(* ', '(- ']):
                    self.add_finding(
                        Severity.MEDIUM,
                        'Unsafe Fold Accumulator Arithmetic',
                        'fold operation uses arithmetic on the accumulator without overflow '
                        'protection. The accumulator could overflow with large lists.',
                        i + 1, code.strip(),
                        'Wrap arithmetic in fold callbacks with checked math or add bounds validation.',
                        'Arithmetic Safety'
                    )

    def check_unprotected_contract_init(self):
        """Detect initialization patterns that can be called multiple times"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'\(define-public\s+\(init', code, re.IGNORECASE):
                block = ' '.join(self._strip_comments(l) for l in self.lines[i:min(i+10, len(self.lines))])
                if 'initialized' not in block.lower() and 'is-initialized' not in block.lower():
                    self.add_finding(
                        Severity.HIGH,
                        'Unprotected Contract Initialization',
                        'Public init function can be called multiple times. An attacker could re-initialize the contract.',
                        i + 1, code.strip(),
                        'Add a data-var initialized flag checked at the start of init.',
                        'Access Control'
                    )

    def check_denial_of_service_patterns(self):
        """Detect patterns that could enable DoS attacks"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if '(map ' in code or '(fold ' in code:
                context = ' '.join(self._strip_comments(l) for l in self.lines[i:min(i+8, len(self.lines))])
                if any(c in context for c in ['contract-call?', 'stx-transfer?', 'nft-transfer?', 'ft-transfer?']):
                    self.add_finding(
                        Severity.HIGH,
                        'Denial of Service via External Call in Loop',
                        'External call inside map/fold. If any call fails, the entire tx reverts.',
                        i + 1, code.strip(),
                        'Use pull-over-push: record amounts owed and let recipients withdraw.',
                        'Denial of Service'
                    )

    def check_sandwich_attack_vectors(self):
        """Detect swap/trade functions vulnerable to sandwich attacks"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'\(define-public\s+\((swap|trade|exchange|buy|sell)', code, re.IGNORECASE):
                block = ' '.join(self._strip_comments(l) for l in self.lines[i:min(i+15, len(self.lines))])
                if not any(t in block.lower() for t in ['min-amount', 'slippage', 'min-out', 'minimum', 'max-in', 'deadline']):
                    self.add_finding(
                        Severity.HIGH,
                        'Missing Slippage Protection (Sandwich Attack Vector)',
                        'Public swap/trade function lacks slippage protection. Vulnerable to sandwich attacks.',
                        i + 1, code.strip(),
                        'Add min-amount-out parameter and deadline/block-height check.',
                        'DeFi Safety'
                    )

    def check_private_key_material(self):
        """Detect accidental inclusion of key-like material in contracts"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'0x[0-9a-fA-F]{64}', code):
                self.add_finding(
                    Severity.CRITICAL,
                    'Potential Private Key Material in Contract',
                    'A 64-char hex string found. If this is a secret, it is permanently visible on-chain.',
                    i + 1, code.strip()[:80] + '...',
                    'Never embed secrets in contracts. Use commit-reveal schemes.',
                    'Secret Exposure'
                )

    def check_sip009_compliance(self):
        """Detect NFT contracts missing required SIP-009 functions"""
        has_nft = any('nft-mint?' in line or 'define-non-fungible-token' in line 
                     for line in self.lines)
        
        if not has_nft:
            return
        
        required_functions = {
            'get-last-token-id': False,
            'get-token-uri': False,
            'get-owner': False,
            'transfer': False
        }
        
        # Check which required functions are present
        for line in self.lines:
            code = self._strip_comments(line)
            for func_name in required_functions.keys():
                if re.search(rf'\(define-(public|read-only)\s+\({func_name}', code):
                    required_functions[func_name] = True
        
        missing = [f for f, present in required_functions.items() if not present]
        
        if missing:
            self.add_finding(
                Severity.MEDIUM,
                'Missing SIP-009 NFT Standard Compliance',
                f"Contract appears to be an NFT contract but is missing required SIP-009 "
                f"functions: {', '.join(missing)}. SIP-009 compliance is essential for "
                f"interoperability with NFT marketplaces, wallets, and other ecosystem tools.",
                1,
                '(NFT contract)',
                f"Implement the missing SIP-009 functions: {', '.join(missing)}. "
                "See https://github.com/stacksgov/sips/blob/main/sips/sip-009/sip-009-nft-standard.md",
                "Standards Compliance"
            )


    def check_unsafe_to_int_to_uint(self):
        """Detect unchecked to-int/to-uint conversions that may overflow"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'\(to-uint\s', code):
                context = '\n'.join(self.lines[max(0,i-2):i+3])
                if 'if' not in context and 'asserts!' not in context:
                    self.add_finding(
                        Severity.MEDIUM,
                        'Unchecked to-uint Conversion',
                        'to-uint on a negative int causes unexpected large values. Validate input is non-negative first.',
                        i + 1, code.strip()[:80],
                        'Add (asserts! (>= value 0) err-negative) before to-uint conversion.',
                        'Type Safety'
                    )
            if re.search(r'\(to-int\s', code):
                context = '\n'.join(self.lines[max(0,i-2):i+3])
                if 'if' not in context and 'asserts!' not in context:
                    self.add_finding(
                        Severity.MEDIUM,
                        'Unchecked to-int Conversion',
                        'to-int on a uint > MAX_INT causes unexpected negative values.',
                        i + 1, code.strip()[:80],
                        'Add bounds check before to-int conversion to prevent overflow.',
                        'Type Safety'
                    )

    def check_unchecked_stx_get_balance(self):
        """Detect reliance on stx-get-balance near transfers"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if 'stx-get-balance' in code:
                context = '\n'.join(self.lines[max(0,i-1):i+3])
                if re.search(r'(stx-transfer\?|/|%|\*)', context):
                    self.add_finding(
                        Severity.MEDIUM,
                        'Balance-Dependent Logic with STX Transfer',
                        'Using stx-get-balance in calculations near stx-transfer can lead to race conditions.',
                        i + 1, code.strip()[:80],
                        'Use explicit amount tracking via data-vars instead of live balance queries.',
                        'Race Condition'
                    )

    def check_missing_sender_validation_in_callback(self):
        """Detect public callback functions that don\'t validate the caller"""
        in_public_fn = False
        fn_name = ""
        fn_start = 0
        fn_lines = []
        depth = 0
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            match = re.search(r'\(define-public\s+\(([\w-]+)', code)
            if match:
                fn_name = match.group(1)
                if re.search(r'(callback|hook|on-|handle-|notify)', fn_name):
                    in_public_fn = True
                    fn_start = i + 1
                    fn_lines = []
                    depth = 0
            if in_public_fn:
                fn_lines.append(code)
                depth += code.count('(') - code.count(')')
                if depth <= 0 and len(fn_lines) > 1:
                    fn_body = '\n'.join(fn_lines)
                    if 'contract-caller' not in fn_body and 'tx-sender' not in fn_body:
                        self.add_finding(
                            Severity.HIGH,
                            f'Unvalidated Callback Function: {fn_name}',
                            'Public callback/hook function does not check the caller identity.',
                            fn_start, fn_lines[0].strip()[:80],
                            'Add (asserts! (is-eq contract-caller expected-caller) err-unauthorized).',
                            'Access Control'
                        )
                    in_public_fn = False

    def check_unbounded_string_input(self):
        """Detect public functions accepting very large string parameters"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            match = re.search(r'\(define-public\s+\([\w-]+.*?(string-(utf8|ascii)\s+(\d+))', code)
            if match:
                max_len = int(match.group(3))
                if max_len > 256:
                    self.add_finding(
                        Severity.LOW,
                        'Large String Parameter in Public Function',
                        f'Public function accepts string input up to {max_len} chars. Large inputs increase tx cost.',
                        i + 1, code.strip()[:80],
                        'Consider limiting string parameters to reasonable bounds (e.g., 256 chars).',
                        'Gas Optimization'
                    )

    def check_governance_centralization(self):
        """Detect single-owner governance patterns without multisig"""
        has_owner_var = False
        has_set_owner = False
        has_multisig = False
        owner_line = 0
        owner_snippet = ""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'define-data-var\s+(contract-owner|owner|admin|governance)', code):
                has_owner_var = True
                owner_line = i + 1
                owner_snippet = code.strip()[:80]
            if re.search(r'var-set\s+(contract-owner|owner|admin)', code):
                has_set_owner = True
            if re.search(r'(multisig|multi-sig|threshold|quorum|n-of-m)', code, re.IGNORECASE):
                has_multisig = True
        if has_owner_var and has_set_owner and not has_multisig:
            self.add_finding(
                Severity.MEDIUM,
                'Centralized Governance — Single Owner Pattern',
                'Contract uses a single mutable owner with no multisig or timelock.',
                owner_line, owner_snippet,
                'Implement multisig governance or a timelock on ownership transfers.',
                'Governance'
            )



    def check_public_data_var_setter(self):
        """Detect public functions that set critical data vars without access control"""
        critical_vars = ['owner', 'admin', 'treasury', 'fee-rate', 'price', 'oracle', 'paused']
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            if 'var-set' not in func_body:
                continue
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if 'var-set' in code:
                    for cv in critical_vars:
                        if cv in code:
                            local_ctx = '\n'.join(func_lines[:offset+1])
                            if 'contract-caller' not in local_ctx and 'tx-sender' not in local_ctx:
                                self.add_finding(
                                    Severity.CRITICAL,
                                    f"Unprotected Critical Variable Setter '{func_name}' (sets {cv})",
                                    f"Public function sets the critical variable '{cv}' without any "
                                    "caller validation. Anyone can change ownership, fees, or pause state.",
                                    func_start + offset,
                                    line.strip()[:120],
                                    "Add strict access control: (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)",
                                    "Access Control"
                                )
                            break

    def check_response_type_mismatch(self):
        """Detect functions with conditional logic but missing error branches"""
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            ok_count = 0
            err_count = 0
            has_if = False
            for line in func_lines:
                code = self._strip_comments(line)
                if '(if ' in code or '(match ' in code:
                    has_if = True
                if '(ok ' in code:
                    ok_count += 1
                if '(err ' in code:
                    err_count += 1
            if has_if and ok_count > 0 and err_count == 0:
                self.add_finding(
                    Severity.MEDIUM,
                    f"Missing Error Branch in '{func_name}'",
                    "Function has conditional logic but always returns (ok ...) without "
                    "any (err ...) branch. Failed conditions may silently succeed.",
                    func_start,
                    func_lines[0] if func_lines else '',
                    "Add explicit (err ...) returns for failure conditions.",
                    "Error Handling"
                )

    def check_list_append_in_loop(self):
        """Detect unbounded list growth via append inside map/fold"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'append' in code:
                context_start = max(0, i - 10)
                context = '\n'.join(self.lines[context_start:i])
                if any(k in context for k in ['fold', 'map', 'filter']):
                    self.add_finding(
                        Severity.HIGH,
                        "Unbounded List Growth in Loop",
                        "Using append inside fold/map/filter can exceed Clarity list limits, "
                        "causing runtime aborts — a denial of service vector.",
                        i,
                        line.strip()[:120],
                        "Pre-allocate with known max size or add explicit length checks.",
                        "Resource Safety"
                    )

    def check_stx_transfer_in_fold(self):
        """Detect token transfers inside fold/map — batch transfer DoS risk"""
        for i, line in enumerate(self.lines, 1):
            code = self._strip_comments(line)
            if 'stx-transfer?' in code or 'ft-transfer?' in code:
                context_start = max(0, i - 15)
                context = '\n'.join(self.lines[context_start:i])
                if 'fold' in context or 'map' in context:
                    self.add_finding(
                        Severity.HIGH,
                        "Token Transfer Inside Loop (Batch DoS Risk)",
                        "A single failed transfer in fold/map aborts the entire batch. "
                        "An attacker can block all payouts by adding a rejecting address.",
                        i,
                        line.strip()[:120],
                        "Use pull-over-push: record amounts owed, let recipients claim separately.",
                        "Denial of Service"
                    )

    def check_missing_contract_lock(self):
        """Detect contracts with admin + transfers but no emergency pause"""
        has_admin_fn = False
        has_pause = False
        has_transfer = False
        for func_name, _, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(func_lines)
            name_lower = func_name.lower()
            if any(k in name_lower for k in ['set-admin', 'set-owner', 'upgrade', 'migrate']):
                has_admin_fn = True
            if any(k in name_lower for k in ['pause', 'lock', 'freeze', 'emergency']):
                has_pause = True
            if 'stx-transfer?' in func_body or 'ft-transfer?' in func_body:
                has_transfer = True
        if has_admin_fn and has_transfer and not has_pause:
            self.add_finding(
                Severity.MEDIUM,
                "No Emergency Pause Mechanism",
                "Contract has admin functions and transfers but no pause mechanism. "
                "No way to halt operations during an active exploit.",
                1,
                self.lines[0] if self.lines else '',
                "Add (define-data-var paused bool false) with admin-only toggle and check in critical fns.",
                "Emergency Response"
            )


    def check_unchecked_contract_call_response(self):
        """Detect contract-call? results that are not unwrapped or matched"""
        for func_name, start, end, func_lines in self._iter_function_blocks('public'):
            for i, line in enumerate(func_lines):
                stripped = self._strip_comments(line)
                if 'contract-call?' in stripped:
                    context = chr(10).join(func_lines[max(0,i-1):i+3])
                    if not re.search(r'(unwrap[!-]|match|try!|asserts!)', context):
                        self.add_finding(
                            Severity.HIGH,
                            'Unchecked Cross-Contract Call Response',
                            f"contract-call? in '{func_name}' — result may be silently ignored. "
                            'A failed external call will not revert the transaction.',
                            start + i + 1,
                            stripped.strip(),
                            'Always unwrap! or match the response from contract-call? to handle errors.',
                            'Error Handling'
                        )

    def check_frontrunning_sensitive_operations(self):
        """Detect swap/trade/bid functions without slippage or deadline params"""
        sensitive_keywords = ['swap', 'trade', 'bid', 'buy', 'sell', 'exchange', 'liquidat']
        for func_name, start, _, func_lines in self._iter_function_blocks('public'):
            name_lower = func_name.lower()
            if any(k in name_lower for k in sensitive_keywords):
                func_body = chr(10).join(func_lines)
                has_slippage = re.search(r'(min-amount|max-amount|slippage|min-out|max-in|deadline|min-received)', func_body, re.IGNORECASE)
                if not has_slippage:
                    self.add_finding(
                        Severity.HIGH,
                        'Frontrunning-Sensitive Operation Without Slippage Protection',
                        f"Function '{func_name}' performs trading/swapping but has no slippage or deadline parameter. "
                        'Miners or observers can frontrun and extract value.',
                        start + 1,
                        self.lines[start].strip(),
                        'Add min-amount-out or deadline parameters to protect users from sandwich attacks.',
                        'MEV Protection'
                    )

    def check_double_spend_map_pattern(self):
        """Detect map-get? followed by map-set without map-delete in claim/redeem flows"""
        claim_keywords = ['claim', 'redeem', 'withdraw', 'collect', 'harvest']
        for func_name, start, _, func_lines in self._iter_function_blocks('public'):
            name_lower = func_name.lower()
            if any(k in name_lower for k in claim_keywords):
                func_body = chr(10).join(func_lines)
                has_get = 'map-get?' in func_body
                has_delete = 'map-delete' in func_body
                has_set = 'map-set' in func_body
                if has_get and not has_delete and not has_set:
                    self.add_finding(
                        Severity.CRITICAL,
                        'Potential Double-Claim Vulnerability',
                        f"Function '{func_name}' reads a map but never deletes/updates the entry. "
                        'Users may be able to claim the same reward multiple times.',
                        start + 1,
                        self.lines[start].strip(),
                        'Use map-delete or map-set to mark claims as consumed after successful claim.',
                        'Replay Attack'
                    )

    def check_missing_principal_check_in_callback(self):
        """Detect public callback-style functions without sender/caller validation"""
        callback_keywords = ['callback', 'hook', 'on-', 'handle-', 'receive', 'notify']
        for func_name, start, _, func_lines in self._iter_function_blocks('public'):
            name_lower = func_name.lower()
            if any(k in name_lower for k in callback_keywords):
                func_body = chr(10).join(func_lines)
                has_auth = re.search(r'(tx-sender|contract-caller|is-eq\s+\S+\s+\S*sender)', func_body)
                if not has_auth:
                    self.add_finding(
                        Severity.HIGH,
                        'Unprotected Public Callback Function',
                        f"Public function '{func_name}' appears to be a callback/hook with no sender validation. "
                        'Anyone can invoke it to trigger unintended state changes.',
                        start + 1,
                        self.lines[start].strip(),
                        'Validate that the caller is the expected contract or principal.',
                        'Access Control'
                    )

    def check_unsafe_stx_liquid_supply(self):
        """Detect reliance on stx-liquid-supply for pricing or share calculations"""
        for i, line in enumerate(self.lines):
            stripped = self._strip_comments(line)
            if 'stx-liquid-supply' in stripped:
                self.add_finding(
                    Severity.MEDIUM,
                    'Reliance on stx-liquid-supply for Calculations',
                    'stx-liquid-supply changes with unlocking schedules and may be manipulable '
                    'in edge cases. Using it for share/price calculations can lead to inaccurate valuations.',
                    i + 1,
                    stripped.strip(),
                    'Use a fixed total supply constant or a trusted oracle for pricing calculations.',
                    'Data Integrity'
                )

    def check_unbounded_map_set_public(self):
        """#61 Detect unbounded map-set usage in public functions (state bloat DoS)."""
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            header = func_lines[0] if func_lines else ""
            params = self._extract_function_params(header)
            if not params:
                continue

            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if "map-set" not in code:
                    continue

                uses_user_input_key = any(re.search(rf"\b{re.escape(param)}\b", code) for param in params)
                if not uses_user_input_key:
                    continue

                local_start = max(0, offset - 8)
                local_context = "\n".join(func_lines[local_start:offset + 1]).lower()
                has_bounds_or_existence_check = any(
                    marker in local_context
                    for marker in [
                        "map-get?",
                        "map-insert",
                        "as-max-len?",
                        "(len ",
                        "max-",
                        "limit",
                        "quota",
                        "asserts!",
                    ]
                )
                if not has_bounds_or_existence_check:
                    self.add_finding(
                        Severity.HIGH,
                        f"Unbounded map-set in Public Function '{func_name}'",
                        "Public function writes user-controlled keys with map-set without clear "
                        "existence/size bounds checks. Attackers can spam unique keys and bloat "
                        "contract state, degrading performance and increasing long-term maintenance cost.",
                        func_start + offset,
                        line.strip()[:120],
                        "Enforce key/value bounds and per-user quotas. Prefer map-insert with result "
                        "checks, and gate writes with asserts! on size/usage limits.",
                        "Denial of Service",
                    )
                    break

    def check_missing_sip010_metadata_functions(self):
        """#62 Detect FT contracts missing SIP-010 metadata functions."""
        if "define-fungible-token" not in self.content and "ft-mint?" not in self.content:
            return

        defined_fns = set()
        for func_name, _, _, _ in self._iter_function_blocks("public"):
            defined_fns.add(func_name.lower())
        for func_name, _, _, _ in self._iter_function_blocks("read-only"):
            defined_fns.add(func_name.lower())

        metadata_fns = ["get-symbol", "get-decimals"]
        missing = [fn for fn in metadata_fns if fn not in defined_fns]
        if missing:
            self.add_finding(
                Severity.MEDIUM,
                "Missing SIP-010 Metadata Function(s)",
                f"Fungible token contract is missing required metadata function(s): {', '.join(missing)}. "
                "Wallets and indexers rely on these methods for token presentation and UX.",
                1,
                self.lines[0] if self.lines else "",
                "Implement required SIP-010 metadata read-only functions for symbol and decimals.",
                "Standards Compliance",
            )

    def check_unsafe_string_concat_without_length_check(self):
        """#63 Detect concat usage without length guard."""
        function_blocks = list(self._iter_function_blocks("public")) + list(self._iter_function_blocks("private"))
        for func_name, func_start, _, func_lines in function_blocks:
            for offset, line in enumerate(func_lines):
                code = self._strip_comments(line)
                if "(concat " not in code:
                    continue

                local_start = max(0, offset - 4)
                local_end = min(len(func_lines), offset + 5)
                local_context = "\n".join(func_lines[local_start:local_end]).lower()
                has_length_check = any(
                    marker in local_context
                    for marker in ["as-max-len?", "(len ", "asserts! (<= ", "asserts! (< "]
                )
                if not has_length_check:
                    self.add_finding(
                        Severity.MEDIUM,
                        f"Unsafe String Concatenation in '{func_name}'",
                        "String concatenation occurs without a preceding length guard. "
                        "Unbounded concatenation can exceed size limits and cause runtime aborts.",
                        func_start + offset,
                        line.strip()[:120],
                        "Validate combined length before concat, or wrap with as-max-len? and "
                        "handle the none case explicitly.",
                        "Input Validation",
                    )

    def check_governance_execution_without_timelock(self):
        """#64 Detect governance execution paths with no timelock."""
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            name_lower = func_name.lower()
            if not any(token in name_lower for token in ["execute", "enact", "apply"]):
                continue

            func_body = "\n".join(func_lines)
            func_body_lower = func_body.lower()
            has_governance_context = any(
                token in func_body_lower
                for token in ["proposal", "govern", "vote", "quorum", "dao"]
            ) or "proposal" in name_lower
            if not has_governance_context:
                continue

            has_state_change = any(
                op in func_body_lower
                for op in ["var-set", "map-set", "map-insert", "map-delete", "stx-transfer?", "ft-transfer?"]
            )
            if not has_state_change:
                continue

            has_timelock_keyword = any(
                token in func_body_lower
                for token in [
                    "timelock",
                    "time-lock",
                    "delay",
                    "eta",
                    "execute-after",
                    "unlock-height",
                    "ready-at",
                ]
            )
            has_height_delay_check = (
                any(token in func_body_lower for token in ["block-height", "burn-block-height", "tenure-height"])
                and any(op in func_body_lower for op in [">=", "<=", ">", "<"])
            )

            if not has_timelock_keyword and not has_height_delay_check:
                self.add_finding(
                    Severity.CRITICAL,
                    f"Governance Proposal Execution Without Timelock in '{func_name}'",
                    "Governance action execution appears callable without a timelock delay. "
                    "A compromised governance flow can execute malicious proposals immediately, "
                    "leaving no defensive response window.",
                    func_start,
                    func_lines[0].strip()[:120] if func_lines else "",
                    "Add explicit queue + timelock enforcement (eta/delay) before execution. "
                    "Require block-height checks and immutable minimum delay constants.",
                    "Governance",
                )

    def check_unvalidated_trait_parameter(self):
        """#65 Detect public trait parameters used without validation."""
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            header = func_lines[0] if func_lines else ""
            trait_params = re.findall(r"\(([a-zA-Z0-9_-]+)\s+<[^>]+>\)", self._strip_comments(header))
            if not trait_params:
                continue

            body = "\n".join(func_lines)
            body_lower = body.lower()
            for trait_param in trait_params:
                trait_param_l = trait_param.lower()
                is_used = re.search(rf"\b{re.escape(trait_param_l)}\b", body_lower)
                if not is_used:
                    continue

                has_validation = any(
                    re.search(pattern, body_lower)
                    for pattern in [
                        rf"is-eq\s+{re.escape(trait_param_l)}\b",
                        rf"is-eq\s+\S+\s+{re.escape(trait_param_l)}\b",
                        rf"asserts!\s*\([^)]*{re.escape(trait_param_l)}",
                        rf"map-get\?\s+[^)\n]*{re.escape(trait_param_l)}",
                        rf"allow[a-z0-9_-]*\s+[^)\n]*{re.escape(trait_param_l)}",
                    ]
                )
                if not has_validation:
                    self.add_finding(
                        Severity.HIGH,
                        f"Unvalidated Trait Parameter in Public Function '{func_name}'",
                        "Public function accepts a trait-typed contract reference without allowlist "
                        "or identity validation. Attackers can pass malicious trait implementors.",
                        func_start,
                        header.strip()[:120],
                        "Validate trait parameters against approved principals before contract-call? "
                        "or use static contract references for privileged flows.",
                        "Trait Safety",
                    )
                    break



    def check_fee_manipulation(self):
        """Detect mutable fee parameters without caps or timelocks"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'define-data-var\s+(fee|fee-rate|fee-bps|swap-fee|protocol-fee)', code):
                has_cap = any(
                    re.search(r'(max-fee|fee-cap|fee-limit|<=.*fee|asserts!.*fee)', self._strip_comments(l))
                    for l in self.lines
                )
                if not has_cap:
                    self.add_finding(
                        Severity.HIGH,
                        'Uncapped Fee Parameter — Rug Vector',
                        'Mutable fee variable with no upper bound. Admin can set fee to 100% and drain user funds.',
                        i + 1, code.strip()[:80],
                        'Add a maximum fee cap (e.g., asserts! (<= new-fee u1000)) and consider a timelock.',
                        'Economic'
                    )
                break

    def check_deadline_missing_in_swap(self):
        """Detect swap/trade functions without deadline/expiry parameters"""
        in_swap_fn = False
        swap_line = 0
        swap_snippet = ""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'define-public\s+\((swap|trade|exchange|execute-swap)', code):
                in_swap_fn = True
                swap_line = i + 1
                swap_snippet = code.strip()[:80]
            if in_swap_fn and re.search(r'(deadline|expiry|expires-at|valid-until|block-height)', code):
                in_swap_fn = False
            if in_swap_fn and re.search(r'^\s*\)\s*$', code):
                self.add_finding(
                    Severity.MEDIUM,
                    'Missing Deadline in Swap Function',
                    'Swap function has no deadline/expiry parameter — transactions can be held and executed at unfavorable prices.',
                    swap_line, swap_snippet,
                    'Add a deadline parameter and check (asserts! (<= block-height deadline)).',
                    'MEV'
                )
                in_swap_fn = False

    def check_integer_truncation_division(self):
        """Detect division before multiplication (precision loss)"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'\(\*\s+\(/\s+', code):
                self.add_finding(
                    Severity.MEDIUM,
                    'Division Before Multiplication — Precision Loss',
                    'Division performed before multiplication can silently truncate to zero in integer arithmetic.',
                    i + 1, code.strip()[:80],
                    'Reorder to multiply first, then divide: (* a c) / b.',
                    'Arithmetic'
                )

    def check_map_insert_without_existence_check(self):
        """Detect map-insert that could silently fail if key exists"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            if re.search(r'\(map-insert\s+', code):
                context_start = max(0, i - 3)
                context = ' '.join(self._strip_comments(l) for l in self.lines[context_start:i+2])
                if not re.search(r'(unwrap!|try!|asserts!|match|if\s+\(map-insert)', context):
                    self.add_finding(
                        Severity.MEDIUM,
                        'Unchecked map-insert — Silent Failure',
                        'map-insert returns false if key already exists, but result is not checked. Data may silently not be written.',
                        i + 1, code.strip()[:80],
                        'Use (asserts! (map-insert ...) (err ...)) or check the boolean return value.',
                        'Data Integrity'
                    )

    def check_stx_transfer_to_variable_recipient(self):
        """Detect STX transfers where recipient comes from a data-var (admin-controlled drain)"""
        for i, line in enumerate(self.lines):
            code = self._strip_comments(line)
            m = re.search(r'\(stx-transfer\?\s+\S+\s+\S+\s+\(var-get\s+(\S+)\)', code)
            if m:
                var_name = m.group(1)
                is_settable = any(
                    re.search(rf'var-set\s+{re.escape(var_name)}', self._strip_comments(l))
                    for l in self.lines
                )
                if is_settable:
                    self.add_finding(
                        Severity.HIGH,
                        'STX Transfer to Admin-Controlled Recipient',
                        f'STX transferred to variable "{var_name}" which can be changed by admin. Potential drain vector.',
                        i + 1, code.strip()[:80],
                        'Use a hardcoded treasury address or require multisig approval for recipient changes.',
                        'Rug Pull'
                    )
    def check_post_condition_missing(self):
        """#66 Detect public functions with asset transfers but no post-conditions."""
        transfer_patterns = [r"stx-transfer\?", r"nft-transfer\?", r"ft-transfer\?"]
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            body = "\n".join(func_lines)
            body_stripped = self._strip_comments(body)
            has_transfer = any(re.search(p, body_stripped) for p in transfer_patterns)
            if not has_transfer:
                continue
            # Check for post-condition annotations in comments
            has_post_condition = any(
                re.search(pattern, body, re.IGNORECASE)
                for pattern in [
                    r";;\s*post-condition",
                    r";;\s*@post",
                    r"post-conditions",
                ]
            )
            if not has_post_condition:
                self.add_finding(
                    Severity.MEDIUM,
                    f"Missing Post-Condition Annotation in '{func_name}'",
                    "Public function performs asset transfers (STX/NFT/FT) without "
                    "documented post-conditions. Stacks post-conditions are a critical "
                    "safety mechanism that should be explicitly specified.",
                    func_start,
                    body_stripped.split("\n")[0].strip()[:120],
                    "Add post-condition annotations (;; @post-condition) and ensure "
                    "callers attach appropriate post-conditions to transactions.",
                    "Post-Conditions",
                )

    def check_reentrancy_via_dynamic_dispatch(self):
        """#67 Detect contract-call? with variable/parameter contract references."""
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            body = "\n".join(func_lines)
            body_stripped = self._strip_comments(body)
            # contract-call? with a variable ref (not a literal .contract-name)
            matches = re.finditer(
                r"contract-call\?\s+([a-zA-Z0-9_-]+)\s+",
                body_stripped,
            )
            for m in matches:
                target = m.group(1)
                # Literal contract refs start with . or ' — variables don't
                if not target.startswith(".") and not target.startswith("'"):
                    line_offset = body_stripped[: m.start()].count("\n")
                    self.add_finding(
                        Severity.HIGH,
                        f"Dynamic Dispatch in contract-call? in '{func_name}'",
                        f"contract-call? uses variable '{target}' as contract reference "
                        "instead of a literal. This enables reentrancy-like attacks where "
                        "an attacker passes a malicious contract implementing the expected trait.",
                        func_start + line_offset,
                        m.group(0).strip()[:120],
                        "Use static contract references (e.g., .my-contract) or validate "
                        "the contract parameter against an allowlist of approved addresses.",
                        "Reentrancy",
                    )

    def check_sip009_royalty_bypass(self):
        """#68 Detect NFT marketplace patterns where royalty payment can be skipped."""
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            body = "\n".join(func_lines)
            body_stripped = self._strip_comments(body).lower()
            # Look for marketplace-like functions
            is_marketplace = any(
                kw in func_name.lower()
                for kw in ["list", "buy", "sell", "purchase", "trade", "marketplace"]
            )
            if not is_marketplace:
                continue
            has_nft_transfer = "nft-transfer?" in body_stripped
            has_royalty = any(
                kw in body_stripped
                for kw in ["royalt", "creator-fee", "artist-fee", "commission"]
            )
            if has_nft_transfer and not has_royalty:
                self.add_finding(
                    Severity.HIGH,
                    f"Potential Royalty Bypass in NFT Function '{func_name}'",
                    "NFT marketplace function transfers NFTs without apparent royalty/commission "
                    "payment logic. This allows sellers to bypass creator royalties, violating "
                    "SIP-009 marketplace best practices.",
                    func_start,
                    func_lines[0].strip()[:120] if func_lines else "",
                    "Implement mandatory royalty payment (e.g., percentage of sale price sent "
                    "to the original creator) before completing the NFT transfer.",
                    "NFT Safety",
                )

    def check_flash_loan_callback_unguarded(self):
        """#69 Detect flash loan callback functions without sender verification."""
        flash_patterns = [
            r"on-flash-loan", r"flash-callback", r"execute-flash",
            r"flash-loan-callback", r"on-loan-received",
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            is_flash_callback = any(
                re.search(p, func_name, re.IGNORECASE) for p in flash_patterns
            )
            if not is_flash_callback:
                continue
            body = "\n".join(func_lines)
            body_stripped = self._strip_comments(body).lower()
            has_sender_check = any(
                pattern in body_stripped
                for pattern in [
                    "is-eq contract-caller",
                    "is-eq tx-sender",
                    "asserts!",
                    "lending-pool",
                    "flash-lender",
                ]
            )
            if not has_sender_check:
                self.add_finding(
                    Severity.CRITICAL,
                    f"Unguarded Flash Loan Callback '{func_name}'",
                    "Flash loan callback function lacks sender verification. Anyone can "
                    "call this function directly, potentially manipulating contract state "
                    "outside the intended flash loan flow.",
                    func_start,
                    func_lines[0].strip()[:120] if func_lines else "",
                    "Verify that contract-caller is the expected lending pool contract. "
                    "Use (asserts! (is-eq contract-caller .lending-pool) (err ...)).",
                    "Flash Loan Safety",
                )

    def check_time_based_unlock_manipulation(self):
        """#70 Detect time-sensitive operations using block-height without delta checks."""
        time_keywords = [
            "unlock", "vest", "release", "expire", "deadline", "mature", "lock-until",
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks("public"):
            body = "\n".join(func_lines)
            body_stripped = self._strip_comments(body).lower()
            is_time_sensitive = any(kw in func_name.lower() or kw in body_stripped for kw in time_keywords)
            if not is_time_sensitive:
                continue
            uses_block_height = "block-height" in body_stripped
            if not uses_block_height:
                continue
            # Check for proper comparison (>= or > with a stored/calculated value)
            has_safe_comparison = re.search(
                r"(?:>=|>|is-eq)\s+block-height\s+\S+|(?:>=|>|is-eq)\s+\S+\s+block-height",
                body_stripped,
            )
            if not has_safe_comparison:
                self.add_finding(
                    Severity.MEDIUM,
                    f"Unsafe Block-Height Time Check in '{func_name}'",
                    "Time-sensitive function references block-height without a clear "
                    "comparison against a stored unlock/deadline value. Block-height can "
                    "be manipulated by miners within small windows.",
                    func_start,
                    func_lines[0].strip()[:120] if func_lines else "",
                    "Store the target block-height in a data-var and use explicit "
                    "(>= block-height target-height) comparisons. Consider adding "
                    "a minimum block delta for safety.",
                    "Time Safety",
                )


    def check_sip013_compliance(self):
        """#71 Detect SFT contracts missing required SIP-013 semi-fungible token functions"""
        # SIP-013 semi-fungible tokens use maps keyed by (token-id, owner)
        # Indicators: trait reference, or map with token-id + balance patterns
        sft_indicators = [
            'sip013-semi-fungible-token',
            'semi-fungible',
            'sft-mint',
        ]
        # Also detect via common SFT map patterns: balance maps keyed by token-id + principal
        has_sft_trait = any(
            ind in self.content.lower() for ind in sft_indicators
        )
        # Check for balance-map pattern: a map with token-id and principal as keys
        has_sft_map = bool(re.search(
            r'\(define-map\s+\S*balance\S*\s+\{[^}]*token-id[^}]*\}',
            self.content, re.IGNORECASE
        ))
        # Also detect multi-token patterns using ft-mint? with token-id references
        has_multi_token = (
            'define-fungible-token' in self.content
            and re.search(r'token-id', self.content, re.IGNORECASE) is not None
            and ('ft-mint?' in self.content or 'ft-burn?' in self.content)
        )

        if not (has_sft_trait or has_sft_map or has_multi_token):
            return

        # SIP-013 required functions
        required_functions = {
            'transfer': False,
            'transfer-memo': False,
            'get-balance': False,
            'get-overall-balance': False,
            'get-total-supply': False,
            'get-overall-supply': False,
            'get-token-uri': False,
            'get-decimals': False,
        }

        for line in self.lines:
            code = self._strip_comments(line)
            for func_name in required_functions:
                if re.search(
                    rf'\(define-(public|read-only)\s+\({re.escape(func_name)}\b',
                    code,
                ):
                    required_functions[func_name] = True

        missing = [f for f, present in required_functions.items() if not present]

        if missing:
            self.add_finding(
                Severity.MEDIUM,
                'Incomplete SIP-013 Semi-Fungible Token Interface',
                f"Contract appears to implement a semi-fungible token but is missing "
                f"required SIP-013 functions: {', '.join(missing)}. SIP-013 compliance "
                f"is needed for interoperability with SFT marketplaces, wallets, and "
                f"DeFi protocols on Stacks.",
                1,
                self.lines[0] if self.lines else '',
                f"Implement the missing functions: {', '.join(missing)}. "
                "See https://github.com/stacksgov/sips/blob/main/sips/sip-013.md",
                'Standards Compliance',
            )

    def check_missing_token_supply_cap(self):
        """#72 Detect ft-mint? calls in public functions without supply cap validation.

        Minting without a max-supply check allows unbounded token inflation,
        devaluing all existing holders.  This complements #29 (which checks
        authorization) by verifying economic safety bounds.
        """
        # Patterns that indicate a supply-cap check is present.
        # Use regex word-boundaries to avoid 'cap' matching inside 'uncapped'.
        supply_patterns = [
            r'max-supply', r'total-supply', r'supply-cap', r'max-tokens',
            r'max-mint', r'get-total-supply', r'ft-get-supply',
            r'(?<![a-z-])cap(?![a-z-])',   # standalone 'cap'
            r'(?<![a-z-])limit(?![a-z-])', # standalone 'limit'
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            # Use regex to match ft-mint? but NOT nft-mint?
            if not re.search(r'(?<!n)ft-mint\?', body):
                continue
            body_lower = body.lower()
            has_supply_check = any(re.search(p, body_lower) for p in supply_patterns)
            # Also accept a numeric comparison near ft-mint? (e.g. asserts! (< count u1000000))
            if not has_supply_check:
                has_supply_check = bool(re.search(
                    r'asserts?!\s*\([<>]=?\s', body_lower
                ))
            if not has_supply_check:
                mint_line_offset = 0
                for i, fl in enumerate(func_lines):
                    if 'ft-mint?' in self._strip_comments(fl):
                        mint_line_offset = i
                        break
                self.add_finding(
                    Severity.HIGH,
                    f"Uncapped Token Minting in '{func_name}'",
                    'ft-mint? is called without any supply cap or max-supply validation. '
                    'Without a hard cap, authorized minters can inflate the token supply '
                    'indefinitely, destroying holder value.',
                    func_start + mint_line_offset + 1,
                    func_lines[mint_line_offset].strip() if mint_line_offset < len(func_lines) else '',
                    'Add a max-supply constant and validate before minting: '
                    '(asserts! (<= (+ (ft-get-supply token) amount) MAX-SUPPLY) ERR_CAP_EXCEEDED)',
                    'Economic Safety',
                )

    def check_uncapped_nft_minting(self):
        """#73 Detect nft-mint? calls in public functions without mint count limits.

        Unlimited NFT minting (no per-address cap, no total supply cap, no
        allowlist) enables a single caller to mint unbounded NFTs, flooding
        the collection and destroying rarity/value for existing holders.
        """
        # Patterns that indicate a mint-count/supply guard is present
        limit_patterns = [
            r'max-supply', r'total-supply', r'max-mint', r'mint-limit',
            r'mint-count', r'minted-count', r'total-minted', r'max-nft',
            r'mint-cap', r'allowlist', r'whitelist', r'allow-list',
            r'nft-get-supply', r'get-last-token-id',
            r'(?<![a-z-])cap(?![a-z-])',
            r'(?<![a-z-])limit(?![a-z-])',
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            if 'nft-mint?' not in body:
                continue
            body_lower = body.lower()
            has_limit = any(re.search(p, body_lower) for p in limit_patterns)
            # Accept numeric comparison as a guard (e.g. asserts! (< count u10000))
            if not has_limit:
                has_limit = bool(re.search(
                    r'asserts?!\s*\([<>]=?\s', body_lower
                ))
            # Accept map-get? near nft-mint? as a per-address tracking check
            if not has_limit:
                has_limit = bool(re.search(
                    r'map-get\?\s+\S*mint', body_lower
                ))
            if not has_limit:
                mint_line_offset = 0
                for i, fl in enumerate(func_lines):
                    if 'nft-mint?' in self._strip_comments(fl):
                        mint_line_offset = i
                        break
                self.add_finding(
                    Severity.HIGH,
                    f"Uncapped NFT Minting in '{func_name}'",
                    'nft-mint? is called without any supply cap, per-address mint limit, '
                    'or allowlist check. An attacker or authorized caller could mint an '
                    'unlimited number of NFTs, flooding the collection and destroying '
                    'value for existing holders.',
                    func_start + mint_line_offset + 1,
                    func_lines[mint_line_offset].strip() if mint_line_offset < len(func_lines) else '',
                    'Add a total supply cap (asserts! (<= next-id MAX-SUPPLY) ERR_SOLD_OUT) '
                    'or per-address mint limit via a tracking map.',
                    'Economic Safety',
                )




    def check_unbounded_reward_emission(self):
        """#74 Detect reward/claim functions that transfer tokens without rate-limiting.

        Public functions that distribute rewards (stx-transfer?, ft-transfer?,
        contract-call? ... transfer) without cooldown checks, epoch/block-height
        guards, or per-user claim tracking allow unbounded reward draining.
        An attacker can call the function repeatedly in the same block to
        extract the entire reward pool.
        """
        # Function names that suggest reward distribution
        reward_name_patterns = [
            r'claim', r'harvest', r'reward', r'airdrop', r'distribute',
            r'yield', r'payout', r'redeem', r'collect',
        ]
        # Transfer patterns that move value
        transfer_patterns = [
            r'stx-transfer\?', r'ft-transfer\?',
            r'contract-call\?\s+\S+\s+transfer\b',
        ]
        # Rate-limiting / cooldown patterns that make it safe
        guard_patterns = [
            r'block-height', r'burn-block-height', r'stacks-block-height',
            r'last-claim', r'last-harvest', r'last-redeem', r'last-collect',
            r'claimed', r'claim-epoch', r'claim-block', r'claim-height',
            r'cooldown', r'interval', r'epoch', r'period',
            r'already-claimed', r'has-claimed', r'is-claimed',
            r'map-get\?\s+\S*claim', r'map-get\?\s+\S*reward',
            r'map-set\s+\S*claim', r'map-set\s+\S*reward',
            r'nonce', r'reward-cycle', r'cycle-id',
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            # Check if function name matches a reward pattern
            name_lower = func_name.lower()
            is_reward_func = any(re.search(p, name_lower) for p in reward_name_patterns)
            if not is_reward_func:
                continue
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()
            # Must contain a transfer
            has_transfer = any(re.search(p, body_lower) for p in transfer_patterns)
            if not has_transfer:
                continue
            # Check for rate-limiting guards
            has_guard = any(re.search(p, body_lower) for p in guard_patterns)
            if has_guard:
                continue
            # Also accept asserts! with comparison as a guard
            if re.search(r'asserts?!\s*\(', body_lower):
                continue
            # Find the transfer line for reporting
            transfer_line_offset = 0
            for i, fl in enumerate(func_lines):
                stripped = self._strip_comments(fl).lower()
                if any(re.search(p, stripped) for p in transfer_patterns):
                    transfer_line_offset = i
                    break
            self.add_finding(
                Severity.HIGH,
                f"Unbounded Reward Emission in '{func_name}'",
                'This reward/claim function transfers tokens without any cooldown, '
                'block-height check, epoch guard, or per-user claim tracking. '
                'An attacker can call it repeatedly in the same block to drain '
                'the entire reward pool before others can claim.',
                func_start + transfer_line_offset + 1,
                func_lines[transfer_line_offset].strip() if transfer_line_offset < len(func_lines) else '',
                'Add a per-user claim map (map-set last-claimed {user: tx-sender} '
                '{block: block-height}) and check it at the start with asserts! '
                'to enforce a cooldown period between claims.',
                'Economic Safety',
            )


    def check_missing_zero_amount_validation(self):
        """#75 Detect public functions accepting amount params without zero-check.

        Public functions that take an amount parameter and use it in
        stx-transfer?, ft-transfer?, or ft-mint? without first asserting
        that the amount is greater than zero allow zero-amount transactions.
        Zero-amount transfers can be used for:
        - Event/log spam without economic cost
        - Manipulating claim counters or reward maps
        - Bypassing rate limits that check "has transferred" without amounts
        - Inflating transaction counts for airdrop eligibility
        """
        # Transfer operations that take an amount argument
        transfer_patterns = [
            r'stx-transfer\?',
            r'ft-transfer\?',
            r'ft-mint\?',
        ]
        # Patterns that validate amount > 0
        zero_check_patterns = [
            r'asserts?!\s*\(>\s+amount\s+u0\)',       # (asserts! (> amount u0) ...)
            r'asserts?!\s*\(>\s+amount\s+\(var-get',   # (asserts! (> amount (var-get min-amount)) ...)
            r'asserts?!\s*\(is-eq\s+\(>\s+amount',     # wrapped comparison
            r'asserts?!\s*\(not\s+\(is-eq\s+amount\s+u0', # (asserts! (not (is-eq amount u0)) ...)
            r'asserts?!\s*\(>=\s+amount\s+u1\)',       # (asserts! (>= amount u1) ...)
            r'asserts?!\s*\(>\s+amount\s+u0',          # relaxed: (asserts! (> amount u0 ...
            r'asserts?!\s*\(>=\s+amount\s+u1',         # relaxed: (asserts! (>= amount u1 ...
            r'\(if\s+\(is-eq\s+amount\s+u0\)',         # (if (is-eq amount u0) (err ...))
            r'\(if\s+\(<\s+amount\s+u1\)',             # (if (< amount u1) (err ...))
            r'\(if\s+\(<=\s+amount\s+u0\)',            # (if (<= amount u0) (err ...))
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()
            # Must have an 'amount' parameter
            # Look for (amount uint) in the function signature area (first few lines)
            header = '\n'.join(self._strip_comments(l) for l in func_lines[:5]).lower()
            if 'amount' not in header:
                continue
            # Check if any of the amount param patterns exist
            if not re.search(r'\(\s*amount\s+(uint|int)\s*\)', header):
                continue
            # Must contain a transfer using the amount
            has_transfer = any(re.search(p, body_lower) for p in transfer_patterns)
            if not has_transfer:
                continue
            # Check for zero-amount validation
            has_zero_check = any(re.search(p, body_lower) for p in zero_check_patterns)
            if has_zero_check:
                continue
            # Find the transfer line for reporting
            transfer_line_offset = 0
            for i, fl in enumerate(func_lines):
                stripped = self._strip_comments(fl).lower()
                if any(re.search(p, stripped) for p in transfer_patterns):
                    transfer_line_offset = i
                    break
            self.add_finding(
                Severity.MEDIUM,
                f"Missing Zero-Amount Validation in '{func_name}'",
                'This function accepts an amount parameter and uses it in a token '
                'transfer or mint operation without first checking that amount > 0. '
                'Zero-amount transfers succeed silently and can be abused for event '
                'spam, reward map manipulation, or inflating on-chain metrics.',
                func_start + transfer_line_offset + 1,
                func_lines[transfer_line_offset].strip() if transfer_line_offset < len(func_lines) else '',
                'Add (asserts! (> amount u0) ERR-INVALID-AMOUNT) at the start of '
                'the function before any transfer operations.',
                'Input Validation',
            )


    def check_insecure_randomness(self):
        """#76 Detect use of on-chain values as randomness sources.

        Contracts using block-height, burn-block-height, stx-liquid-supply,
        or get-block-info? as input to modulo (mod) or hashing (hash160,
        sha256, sha512, keccak256) for selection/lottery logic create
        miner-exploitable pseudo-randomness.  Miners can manipulate block
        data to influence outcomes in their favor.
        """
        on_chain_sources = [
            'burn-block-height',
            'block-height',
            'stx-liquid-supply',
            r'get-block-info\?',
        ]
        randomness_ops = [
            r'\bmod\b',
            'hash160',
            'sha256',
            'sha512',
            'keccak256',
        ]
        safe_markers = [
            'vrf', 'oracle', 'commit-reveal', 'chainlink',
            'randomness-seed', 'off-chain', 'external-random',
        ]
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()
            if any(marker in body_lower for marker in safe_markers):
                continue
            matched_source = None
            for src in on_chain_sources:
                if re.search(src, body_lower):
                    matched_source = src.replace(r'\?', '?')
                    break
            if not matched_source:
                continue
            has_rng_op = any(re.search(op, body_lower) for op in randomness_ops)
            if not has_rng_op:
                continue
            report_line_offset = 0
            for i, fl in enumerate(func_lines):
                stripped = self._strip_comments(fl).lower()
                if re.search(matched_source.replace('?', r'\?'), stripped):
                    report_line_offset = i
                    break
            self.add_finding(
                Severity.HIGH,
                f"Insecure Randomness Source in '{func_name}'",
                f"This function uses '{matched_source}' combined with hashing or "
                "modulo arithmetic to generate pseudo-random values. On-chain data "
                "is deterministic and miner-influenceable — miners can reorder, "
                "withhold, or selectively include transactions to manipulate outcomes "
                "in lotteries, NFT mints, or reward distributions.",
                func_start + report_line_offset + 1,
                func_lines[report_line_offset].strip() if report_line_offset < len(func_lines) else '',
                "Use a commit-reveal scheme, VRF (Verifiable Random Function), or "
                "an off-chain oracle for randomness. Never derive randomness solely "
                "from on-chain block data.",
                'Randomness',
            )

    def check_single_step_privilege_transfer(self):
        """#77 Detect single-step privilege/ownership transfer without confirmation.

        Contracts that allow transferring admin/owner roles in a single
        transaction risk permanent lockout if the new address is wrong.
        A two-step pattern (propose + accept) ensures the new owner can
        actually sign transactions before the transfer completes.
        """
        privilege_var_patterns = [
            'owner', 'admin', 'authority', 'governor', 'operator',
            'controller', 'manager',
        ]
        # Find all data-var names that look like privilege vars
        privilege_vars = set()
        for line in self.lines:
            stripped = self._strip_comments(line).lower()
            m = re.search(r'\(define-data-var\s+(\S+)\s+principal', stripped)
            if m:
                var_name = m.group(1)
                if any(p in var_name for p in privilege_var_patterns):
                    privilege_vars.add(var_name)

        if not privilege_vars:
            return

        # Build per-var two-step coverage: a var is safe if it has pending/propose/accept pattern
        content_lower = self.content.lower()
        vars_with_two_step = set()
        for priv_var in privilege_vars:
            # Extract the role keyword (e.g. 'owner' from 'contract-owner')
            role_parts = [p for p in priv_var.split('-') if p in privilege_var_patterns]
            role = role_parts[0] if role_parts else priv_var
            two_step_markers = [
                f'pending-{role}', f'proposed-{role}', f'pending-{priv_var}',
                f'accept-{role}', f'claim-{role}', f'confirm-{role}',
                f'accept-{role}ship', f'claim-{role}ship', f'confirm-{role}ship',
            ]
            if any(marker in content_lower for marker in two_step_markers):
                vars_with_two_step.add(priv_var)

        # Scan public functions for var-set on privilege vars with a parameter (not tx-sender)
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()

            for priv_var in privilege_vars:
                if priv_var in vars_with_two_step:
                    continue
                pattern = r'\(var-set\s+' + re.escape(priv_var) + r'\s+(\S+)'
                match = re.search(pattern, body_lower)
                if not match:
                    continue

                new_value = match.group(1)
                # If setting to tx-sender, it is not a transfer to an arbitrary principal
                if new_value.rstrip(')') == 'tx-sender':
                    continue

                # Find the line with var-set for reporting
                report_line_offset = 0
                for i, fl in enumerate(func_lines):
                    stripped = self._strip_comments(fl).lower()
                    if f'var-set {priv_var}' in stripped:
                        report_line_offset = i
                        break

                self.add_finding(
                    Severity.HIGH,
                    f"Single-Step Privilege Transfer in \'{func_name}\'",
                    f"This function transfers the privileged role \'{priv_var}\' to a new "
                    "principal in a single transaction. If the new address is incorrect "
                    "(typo, wrong network, non-existent), admin access is permanently "
                    "lost with no recovery mechanism.",
                    func_start + report_line_offset + 1,
                    func_lines[report_line_offset].strip() if report_line_offset < len(func_lines) else '',
                    "Use a two-step ownership transfer pattern: (1) current owner calls "
                    "propose-owner to set a pending-owner, (2) new owner calls accept-ownership "
                    "to confirm. This ensures the new address is valid and accessible.",
                    'Access Control',
                )


    def check_unvalidated_fee_parameter(self):
        """#78 Detect fee/percentage/rate parameters without bounds validation.

        Public functions that accept fee, percentage, rate, commission, royalty,
        or basis-point parameters and use them in arithmetic without upper-bound
        checks allow callers (or admins) to set values that drain funds.
        A fee-percent of 100 (or 10000 bps) means the entire amount is taken.
        """
        fee_param_patterns = [
            'fee', 'percent', 'percentage', 'rate', 'commission',
            'royalty', 'bps', 'basis', 'slippage', 'spread',
        ]
        bounds_patterns = [
            r'asserts!\s+\(<=?\s+{param}',
            r'asserts!\s+\(>=?\s+\w+\s+{param}',
            r'asserts!\s+\(<\s+{param}',
            r'asserts!\s+\(>\s+\w+\s+{param}',
            r'if\s+\(<=?\s+{param}',
            r'if\s+\(<\s+{param}',
            r'match.*\(<=?\s+{param}',
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()

            # Extract parameter names from the function header lines
            header = ' '.join(self._strip_comments(l) for l in func_lines[:3]).lower()
            param_matches = re.findall(r'\(([a-z0-9_-]+)\s+uint\)', header)
            if not param_matches:
                continue

            for param_name in param_matches:
                # Check if param name matches fee/rate patterns
                if not any(fp in param_name for fp in fee_param_patterns):
                    continue

                # Check if the parameter is actually used in the function body
                if param_name not in body_lower:
                    continue

                # Check for bounds validation
                has_bounds = False
                for bp in bounds_patterns:
                    pattern = bp.format(param=re.escape(param_name))
                    if re.search(pattern, body_lower):
                        has_bounds = True
                        break

                if has_bounds:
                    continue

                # Find the line where the param is first used for reporting
                report_line_offset = 0
                for i, fl in enumerate(func_lines):
                    stripped = self._strip_comments(fl).lower()
                    if param_name in stripped and 'define-public' not in stripped:
                        report_line_offset = i
                        break

                self.add_finding(
                    Severity.HIGH,
                    f"Unvalidated Fee/Rate Parameter '{param_name}' in '{func_name}'",
                    f"The function '{func_name}' accepts a fee/rate parameter "
                    f"'{param_name}' of type uint without validating its upper bound. "
                    "An uncapped fee percentage can be set to 100% (or 10000 bps), "
                    "allowing the entire transfer amount to be taken as fees. "
                    "Malicious callers or compromised admins can drain user funds.",
                    func_start + report_line_offset + 1,
                    func_lines[report_line_offset].strip() if report_line_offset < len(func_lines) else '',
                    "Add explicit bounds validation: (asserts! (<= fee-param MAX_FEE) "
                    "(err ERR_FEE_TOO_HIGH)). Use basis points (bps) with a max of "
                    "1000 (10%) or a project-appropriate cap. Define the cap as a "
                    "constant for clarity.",
                    'Input Validation',
                )


    def check_missing_slippage_protection(self):
        """#79 Detect swap/exchange functions without minimum output validation.

        DEX and swap functions that transfer tokens without enforcing a minimum
        output amount leave users vulnerable to sandwich attacks and front-running.
        Attackers can manipulate the pool price before and after the transaction,
        extracting value from the user's trade.
        """
        swap_name_patterns = [
            'swap', 'exchange', 'trade', 'convert', 'sell', 'buy',
            'liquidate', 'fill-order', 'execute-order',
        ]
        transfer_patterns = [
            r'stx-transfer\?',
            r'(?<!n)ft-transfer\?',
            r'contract-call\?\s+\S+\s+transfer',
        ]
        # Patterns that indicate slippage protection exists
        slippage_safe_patterns = [
            r'min-out', r'min-amount', r'min-receive', r'min-return',
            r'minimum-out', r'minimum-amount', r'minimum-receive',
            r'slippage', r'min-tokens', r'min-dx', r'min-dy',
            r'expected-out', r'expected-amount', r'min-expected',
            r'amount-out-min', r'min-output',
        ]
        # Bound check patterns: asserts!/if comparing output >= min
        bound_check_patterns = [
            r'asserts!\s+\(>=?\s+\w+[\w-]*\s+\w+[\w-]*min',
            r'asserts!\s+\(>=?\s+\w+[\w-]*\s+min',
            r'asserts!\s+\(<=?\s+min[\w-]*\s+\w+',
            r'if\s+\(>=?\s+\w+[\w-]*\s+min',
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()
            func_name_lower = func_name.lower()

            # Check if function name matches swap/exchange patterns
            is_swap_func = any(sp in func_name_lower for sp in swap_name_patterns)
            if not is_swap_func:
                continue

            # Check if function actually does a token transfer
            has_transfer = False
            transfer_line_offset = 0
            for tp in transfer_patterns:
                match = re.search(tp, body_lower)
                if match:
                    has_transfer = True
                    matched_pos = match.start()
                    line_count = body_lower[:matched_pos].count('\n')
                    transfer_line_offset = line_count
                    break

            if not has_transfer:
                continue

            # Check if function has slippage protection
            has_slippage = False

            for sp in slippage_safe_patterns:
                if re.search(sp, body_lower):
                    has_slippage = True
                    break

            if has_slippage:
                continue

            for bp in bound_check_patterns:
                if re.search(bp, body_lower):
                    has_slippage = True
                    break

            if has_slippage:
                continue

            self.add_finding(
                Severity.HIGH,
                f"Missing Slippage Protection in '{func_name}'",
                f"The swap/exchange function '{func_name}' performs token transfers "
                "without enforcing a minimum output amount. Without slippage protection, "
                "users are vulnerable to sandwich attacks where an attacker front-runs "
                "the transaction to move the price, executes their own trade, then "
                "back-runs to profit \u2014 extracting value from the user's trade. "
                "This is especially dangerous in AMM/DEX pools with low liquidity.",
                func_start + transfer_line_offset + 1,
                func_lines[transfer_line_offset].strip() if transfer_line_offset < len(func_lines) else '',
                "Add a min-amount-out parameter and validate: "
                "(asserts! (>= actual-output min-amount-out) (err ERR_SLIPPAGE)). "
                "Consider also adding a deadline parameter to prevent stale "
                "transactions from executing at unfavorable prices.",
                'DEX Safety',
            )
    def check_stale_oracle_price_dependency(self):
        """#80 Detect oracle/price reads without freshness or staleness validation.

        DeFi protocols that consume external price feeds (oracles) must validate
        that the data is recent. Stale prices can be exploited for arbitrage,
        unfair liquidations, or mispriced swaps. Attackers can wait for oracle
        downtime and use outdated prices to drain protocol funds.
        """
        # Patterns indicating oracle price reading
        oracle_call_patterns = [
            r'contract-call\?\s+\S+\s+get-price',
            r'contract-call\?\s+\S+\s+get-latest-price',
            r'contract-call\?\s+\S+\s+read-price',
            r'contract-call\?\s+\S+\s+fetch-price',
            r'contract-call\?\s+\S+\s+get-oracle',
            r'contract-call\?\s+\S+\s+get-feed',
            r'contract-call\?\s+\S+\s+get-rate',
            r'contract-call\?\s+\S+\s+get-exchange-rate',
            r'contract-call\?\s+\S+\s+get-spot',
            r'contract-call\?\s+\S+\s+price-feed',
            r'contract-call\?\s+\S+\s+get-twap',
            r'contract-call\?\s+\S+\s+get-value',
        ]
        # Variable reads that suggest price data usage
        price_var_patterns = [
            r'\(var-get\s+[\w-]*price[\w-]*\)',
            r'\(var-get\s+[\w-]*oracle[\w-]*\)',
            r'\(var-get\s+[\w-]*rate[\w-]*\)',
            r'\(var-get\s+[\w-]*feed[\w-]*\)',
        ]
        # Freshness validation patterns (safe)
        freshness_patterns = [
            r'last-updated', r'last-update', r'updated-at', r'update-time',
            r'timestamp', r'staleness', r'stale', r'freshness',
            r'max-age', r'max-delay', r'price-age', r'oracle-age',
            r'block-height.*price', r'price.*block-height',
            r'update-block', r'last-block', r'price-block',
            r'heartbeat', r'valid-until', r'expires', r'expiry',
            r'asserts!\s+\(<=?\s+\(-\s+block-height',
            r'asserts!\s+\(<\s+\(-\s+block-height',
            r'asserts!\s+\(>=?\s+\w+[\w-]*\s+\(-\s+block-height',
        ]
        # Operations that use prices for critical financial decisions
        price_usage_patterns = [
            r'stx-transfer\?',
            r'(?<!n)ft-transfer\?',
            r'ft-mint\?',
            r'ft-burn\?',
            r'liquidat',
            r'collateral',
            r'borrow',
            r'lend',
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()

            # Check if function reads oracle/price data
            has_oracle_read = False
            oracle_line_offset = 0
            matched_pattern_desc = ""

            for op in oracle_call_patterns:
                match = re.search(op, body_lower)
                if match:
                    has_oracle_read = True
                    matched_pos = match.start()
                    oracle_line_offset = body_lower[:matched_pos].count('\n')
                    matched_pattern_desc = "external oracle call"
                    break

            if not has_oracle_read:
                for vp in price_var_patterns:
                    match = re.search(vp, body_lower)
                    if match:
                        # Only flag var-get price reads if function also does financial ops
                        has_financial_op = any(
                            re.search(pp, body_lower) for pp in price_usage_patterns
                        )
                        if has_financial_op:
                            has_oracle_read = True
                            matched_pos = match.start()
                            oracle_line_offset = body_lower[:matched_pos].count('\n')
                            matched_pattern_desc = "price variable read"
                            break

            if not has_oracle_read:
                continue

            # Check for freshness validation
            has_freshness = any(
                re.search(fp, body_lower) for fp in freshness_patterns
            )
            if has_freshness:
                continue

            self.add_finding(
                Severity.HIGH,
                f"Stale Oracle Price Dependency in '{func_name}'",
                f"The function '{func_name}' reads {matched_pattern_desc} data "
                "without validating its freshness or staleness. If the oracle "
                "stops updating (downtime, congestion, or manipulation), the "
                "contract will continue using outdated prices. This can be "
                "exploited for unfair liquidations, mispriced swaps, arbitrage, "
                "or draining protocol reserves using stale favorable prices.",
                func_start + oracle_line_offset + 1,
                func_lines[oracle_line_offset].strip() if oracle_line_offset < len(func_lines) else '',
                "Add staleness validation: store the last-update block height "
                "alongside price data and check "
                "(asserts! (<= (- block-height last-update-block) MAX_STALENESS) "
                "(err ERR_STALE_PRICE)). Consider using multiple oracle sources "
                "and implementing a heartbeat check for critical price feeds.",
                'Oracle Safety',
            )


    def check_unprotected_liquidity_withdrawal(self):
        """#81 Detect liquidity pool functions allowing unrestricted fund withdrawal.

        LP/pool contracts that allow withdrawal or removal of liquidity without
        time locks, proportional share enforcement, or multi-sig authorization
        are vulnerable to rug pulls. An admin or privileged user can drain the
        entire pool in a single transaction.
        """
        # Function names suggesting liquidity withdrawal
        withdraw_name_patterns = [
            'remove-liquidity', 'withdraw-liquidity', 'withdraw',
            'drain', 'remove-lp', 'burn-lp', 'exit-pool',
            'redeem', 'withdraw-pool', 'pull-liquidity',
            'emergency-withdraw', 'admin-withdraw', 'owner-withdraw',
            'withdraw-all', 'remove-all-liquidity', 'rug',
        ]
        # Transfer patterns indicating fund movement
        transfer_patterns = [
            r'stx-transfer\?',
            r'(?<!n)ft-transfer\?',
            r'contract-call\?\s+\S+\s+transfer',
        ]
        # Patterns indicating proportional/share-based withdrawal (safe)
        proportional_patterns = [
            r'lp-balance', r'lp-share', r'share-of', r'pool-share',
            r'user-share', r'proportional', r'pro-rata',
            r'lp-token', r'lp-amount', r'burn.*lp', r'lp.*burn',
            r'ft-burn\?.*lp', r'ft-burn\?.*pool', r'ft-burn\?.*share',
            r'\(var-get\s+[\w-]*total-supply[\w-]*\)',
            r'user-balance.*total', r'balance.*total-supply',
            r'share-amount', r'user-lp',
        ]
        # Time lock patterns (safe)
        timelock_patterns = [
            r'lock-until', r'lock-block', r'unlock-height', r'unlock-block',
            r'time-lock', r'timelock', r'cooldown', r'lock-period',
            r'withdrawal-delay', r'min-lock', r'lock-duration',
            r'asserts!\s+\(>=?\s+block-height\s+',
            r'asserts!\s+\(<=?\s+\w+[\w-]*lock',
        ]
        # Multi-sig or governance patterns (safe)
        multisig_patterns = [
            r'multi-sig', r'multisig', r'threshold', r'required-approvals',
            r'approval-count', r'signers', r'n-of-m',
            r'governance.*approve', r'proposal.*execute',
            r'vote-count', r'quorum',
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()
            func_name_lower = func_name.lower()

            # Check if function name matches withdrawal patterns
            is_withdraw_func = any(wp in func_name_lower for wp in withdraw_name_patterns)
            if not is_withdraw_func:
                continue

            # Check if function does a token transfer
            has_transfer = False
            transfer_line_offset = 0
            for tp in transfer_patterns:
                match = re.search(tp, body_lower)
                if match:
                    has_transfer = True
                    matched_pos = match.start()
                    transfer_line_offset = body_lower[:matched_pos].count('\n')
                    break

            if not has_transfer:
                continue

            # Check for proportional/share-based withdrawal
            has_proportional = any(
                re.search(pp, body_lower) for pp in proportional_patterns
            )
            if has_proportional:
                continue

            # Check for time lock
            has_timelock = any(
                re.search(tp, body_lower) for tp in timelock_patterns
            )
            if has_timelock:
                continue

            # Check for multi-sig / governance
            has_multisig = any(
                re.search(mp, body_lower) for mp in multisig_patterns
            )
            if has_multisig:
                continue

            self.add_finding(
                Severity.HIGH,
                f"Unprotected Liquidity Withdrawal in '{func_name}'",
                f"The function '{func_name}' transfers funds without proportional "
                "share enforcement, time lock, or multi-sig authorization. An admin "
                "or privileged caller could drain the entire liquidity pool in one "
                "transaction (rug pull). Even with tx-sender auth checks, a single "
                "compromised key enables total fund extraction.",
                func_start + transfer_line_offset + 1,
                func_lines[transfer_line_offset].strip() if transfer_line_offset < len(func_lines) else '',
                "Implement proportional withdrawal: require burning LP tokens to "
                "receive a proportional share of pool assets. Add time locks for "
                "large withdrawals (asserts! (>= block-height withdrawal-unlock-block)). "
                "For admin emergency functions, require multi-sig approval or "
                "governance vote before executing.",
                'DeFi Safety',
            )

    def check_missing_emergency_pause(self):
        """#82 Detect contracts with financial operations but no emergency pause mechanism.

        DeFi contracts that transfer, mint, or burn tokens should include a
        pause/circuit-breaker mechanism so operations can be halted during an
        active exploit. Without a pause, the only response to a hack is to
        race the attacker — which usually fails.
        """
        # Financial operation patterns that indicate a DeFi contract
        financial_ops = [
            r'stx-transfer\?',
            r'(?<!n)ft-transfer\?',
            r'nft-transfer\?',
            r'(?<!n)ft-mint\?',
            r'(?<!n)ft-burn\?',
        ]
        # Pause-related variable/function patterns (safe)
        pause_patterns = [
            r'is-paused', r'paused', r'contract-paused',
            r'emergency-stop', r'emergency-shutdown', r'circuit-breaker',
            r'halted', r'is-halted', r'frozen', r'is-frozen',
            r'stopped', r'is-stopped', r'is-active', r'is-enabled',
            r'pause-guard', r'when-not-paused', r'require-not-paused',
            r'toggle-pause', r'set-paused',
        ]

        # Count public functions with financial operations
        financial_funcs = []
        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            body = '\n'.join(self._strip_comments(l) for l in func_lines)
            body_lower = body.lower()
            for fop in financial_ops:
                if re.search(fop, body_lower):
                    financial_funcs.append((func_name, func_start, func_lines))
                    break

        # Only flag if contract has 3+ financial public functions (real DeFi contract)
        if len(financial_funcs) < 3:
            return

        # Check the entire contract for pause mechanisms
        full_content_lower = self.content.lower()
        has_pause = any(
            re.search(pp, full_content_lower) for pp in pause_patterns
        )
        if has_pause:
            return

        # No pause mechanism found — report on the first financial function
        first_name, first_start, first_lines = financial_funcs[0]
        func_list = ", ".join(f"\'{fn}\'" for fn, _, _ in financial_funcs[:5])
        if len(financial_funcs) > 5:
            func_list += f" (and {len(financial_funcs) - 5} more)"

        self.add_finding(
            Severity.MEDIUM,
            "Missing Emergency Pause Mechanism",
            f"This contract has {len(financial_funcs)} public functions with financial "
            f"operations ({func_list}) but no pause/circuit-breaker mechanism. "
            f"During an active exploit, there is no way to halt operations — the "
            f"only option is to race the attacker, which usually fails. Every DeFi "
            f"contract should include a pause mechanism for incident response.",
            first_start + 1,
            first_lines[0].strip() if first_lines else "",
            "Add an \'is-paused\' data variable and check it at the start of every "
            "financial function: (asserts! (not (var-get is-paused)) ERR-PAUSED). "
            "Include admin-only pause/unpause functions with proper access control. "
            "Consider adding a time-limited auto-unpause to prevent permanent lockout.",
            "Governance",
        )


    def check_mutable_token_metadata(self):
        """#83 Detect SIP-010/SIP-009 metadata functions returning mutable var-get values.

        Token metadata functions (get-name, get-symbol, get-decimals, get-token-uri)
        that return values from data-vars instead of constants allow admins to change
        token identity post-deployment. An admin could rename a token to impersonate
        a high-value asset, change decimals to cause display/calculation errors, or
        modify the token URI to serve malicious metadata.
        """
        # Metadata function names per SIP-010 / SIP-009
        metadata_func_names = [
            'get-name', 'get-symbol', 'get-decimals', 'get-token-uri',
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('read-only'):
            # Only check known metadata functions
            if func_name not in metadata_func_names:
                continue

            body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Check if the function uses var-get (mutable state)
            var_get_match = re.search(r'\(var-get\s+([a-zA-Z][a-zA-Z0-9_-]*)\)', body)
            if not var_get_match:
                continue

            var_name = var_get_match.group(1)

            # Check if there's a setter for this var anywhere in the contract
            has_setter = bool(re.search(
                rf'\(var-set\s+{re.escape(var_name)}\b', self.content
            ))

            # Find the line number for the var-get usage
            finding_line = func_start + 1
            for i, line in enumerate(func_lines):
                if 'var-get' in line:
                    finding_line = func_start + i + 1
                    break

            if has_setter:
                severity_note = (
                    f" A var-set for \'{var_name}\' exists in this contract, "
                    f"confirming the metadata can be changed after deployment."
                )
            else:
                severity_note = (
                    f" The variable \'{var_name}\' is defined as mutable (data-var) "
                    f"even though no setter was found in this contract — consider "
                    f"using define-constant instead."
                )

            self.add_finding(
                Severity.MEDIUM,
                f"Mutable Token Metadata in \'{func_name}\'",
                f"The \'{func_name}\' metadata function returns a value from the "
                f"mutable variable \'{var_name}\' instead of a constant. This allows "
                f"token metadata to be changed after deployment, which can be used "
                f"to impersonate other tokens (name/symbol spoofing), cause display "
                f"errors (decimal manipulation), or serve malicious metadata via "
                f"token URI changes.{severity_note}",
                finding_line,
                func_lines[0].strip() if func_lines else "",
                f"Use \'define-constant\' instead of \'define-data-var\' for token "
                f"metadata that should not change after deployment. If mutability "
                f"is intentional (e.g., upgradeable token URI), add governance "
                f"controls and emit events on changes so wallets and indexers "
                f"can detect metadata modifications.",
                "Token Safety",
            )


    def check_missing_pending_operation_timeout(self):
        """#84 Detect pending/escrow map operations without block-height timeout.

        Contracts that create pending operations (escrow, queued transfers,
        proposals, orders) by inserting into maps without recording a
        block-height deadline risk locking funds indefinitely. If the
        counterparty never confirms or the operation is never finalized,
        locked assets become permanently inaccessible.
        """
        # Patterns that indicate a pending/queued/escrow map
        pending_map_patterns = re.compile(
            r'(pending|queued|escrow|locked|order|proposal|request|offer|bid|auction)',
            re.IGNORECASE
        )

        # Patterns that indicate a timeout/deadline is present
        timeout_patterns = re.compile(
            r'(block-height|burn-block-height|deadline|expires?[-_]?at|timeout|'
            r'expir[yation]+|unlock[-_]?height|end[-_]?block|valid[-_]?until|'
            r'ttl|time[-_]?limit|cancel[-_]?after)',
            re.IGNORECASE
        )

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Look for map-set or map-insert with pending-style map names
            map_ops = re.finditer(
                r'\((map-set|map-insert)\s+([a-zA-Z][a-zA-Z0-9_-]*)',
                func_body
            )

            for match in map_ops:
                op_name = match.group(1)
                map_name = match.group(2)

                # Only flag maps with pending/escrow-like names
                if not pending_map_patterns.search(map_name):
                    continue

                # Check if the function body contains any timeout-related value
                if timeout_patterns.search(func_body):
                    continue

                # Also check if the map value tuple contains timeout fields
                # by looking at the broader context around the map operation
                op_start = match.start()
                # Grab up to 500 chars after the map-set/map-insert to see the value
                value_context = func_body[op_start:op_start + 500]
                if timeout_patterns.search(value_context):
                    continue

                # Find the line number
                finding_line = func_start + 1
                for i, line in enumerate(func_lines):
                    stripped = self._strip_comments(line)
                    if map_name in stripped and (op_name in stripped or
                            (i > 0 and op_name in self._strip_comments(func_lines[i-1]))):
                        finding_line = func_start + i + 1
                        break

                self.add_finding(
                    Severity.HIGH,
                    f"Missing Timeout for Pending Operation in '{func_name}'",
                    f"The '{func_name}' function writes to the '{map_name}' map "
                    f"using {op_name} without recording a block-height deadline or "
                    f"expiry timestamp. If the counterparty never completes the "
                    f"operation (confirm, accept, finalize), any locked funds or "
                    f"assets become permanently inaccessible. This is especially "
                    f"dangerous in escrow, auction, and order-book contracts where "
                    f"users deposit tokens expecting a future settlement.",
                    finding_line,
                    func_lines[0].strip() if func_lines else "",
                    f"Include a block-height deadline in the '{map_name}' map value "
                    f"(e.g., {{... deadline: (+ block-height u1440)}}), and add a "
                    f"public cancel/refund function that allows the depositor to "
                    f"reclaim funds after the deadline has passed.",
                    "Fund Safety",
                )

    def check_missing_minimum_deposit_amount(self):
        """#85 Detect deposit/stake functions without minimum amount enforcement.

        Public functions that accept deposits, stakes, or liquidity without
        enforcing a minimum threshold are vulnerable to dust attacks:
        - Thousands of micro-positions bloat storage maps at negligible cost
        - Rounding errors on tiny amounts can be exploited to extract value
        - Reward calculations on dust positions may round to zero, wasting gas
        - Protocol accounting overhead becomes disproportionate to TVL
        """
        # Function names that indicate deposit/stake operations
        deposit_fn_patterns = re.compile(
            r'(deposit|stake|provide|add-liquidity|add-collateral|supply|lock-tokens|fund)',
            re.IGNORECASE
        )

        # Amount parameter patterns
        amount_param_pattern = re.compile(
            r'\(([a-zA-Z][-a-zA-Z0-9_]*amount[-a-zA-Z0-9_]*|'
            r'[a-zA-Z][-a-zA-Z0-9_]*qty[-a-zA-Z0-9_]*|'
            r'value|tokens|shares)\s+uint\)',
            re.IGNORECASE
        )

        # Patterns that indicate a minimum check is present
        min_check_patterns = re.compile(
            r'(min[-_]?deposit|min[-_]?amount|min[-_]?stake|min[-_]?value|'
            r'minimum[-_]?deposit|minimum[-_]?amount|minimum[-_]?stake|'
            r'dust[-_]?threshold|min[-_]?liquidity|min[-_]?collateral|'
            r'MIN[-_]?DEPOSIT|MIN[-_]?AMOUNT|MIN[-_]?STAKE)',
        )

        # Assert patterns checking amount >= some minimum
        assert_min_patterns = re.compile(
            r'asserts!\s*\(>=?\s+\S+\s+u[1-9]',
        )

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            # Only check deposit/stake-like functions
            if not deposit_fn_patterns.search(func_name):
                continue

            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Must have an amount-like parameter
            func_header = '\n'.join(self._strip_comments(l) for l in func_lines[:5])
            if not amount_param_pattern.search(func_header):
                # Also check if there is a generic uint param used with transfer
                if 'uint' not in func_header:
                    continue

            # Check if function has transfer operations (stx-transfer?, ft-transfer?, ft-mint?)
            if not re.search(r'(stx-transfer\?|ft-transfer\?|ft-mint\?|map-set|map-insert)', func_body):
                continue

            # Skip if minimum check patterns are present
            if min_check_patterns.search(func_body):
                continue

            # Skip if there's an assert checking amount >= some minimum
            if assert_min_patterns.search(func_body):
                continue

            # Skip if there's a comparison of the amount against a constant
            if re.search(r'asserts!\s*\(>\s+\S+\s+u0\)', func_body):
                # > u0 is a zero check, not a minimum — still flag it
                # unless there is a stronger check
                if re.search(r'asserts!\s*\(>=?\s+\S+\s+u[1-9][0-9]*\)', func_body):
                    continue

            self.add_finding(
                Severity.MEDIUM,
                f"Missing Minimum Deposit Amount in '{func_name}'",
                f"The '{func_name}' function accepts deposits or stakes without "
                f"enforcing a minimum amount threshold. This allows dust attacks "
                f"where attackers create thousands of micro-positions at negligible "
                f"cost, bloating storage maps and potentially exploiting rounding "
                f"errors in reward calculations. Tiny deposits also create "
                f"disproportionate accounting overhead relative to their economic value.",
                func_start + 1,
                func_lines[0].strip() if func_lines else "",
                f"Add a minimum deposit check: (asserts! (>= amount MIN-DEPOSIT) "
                f"ERR-BELOW-MINIMUM) where MIN-DEPOSIT is a constant set to a "
                f"meaningful economic threshold (e.g., u1000000 for 1 STX). "
                f"Consider also enforcing minimum-position checks on stake/unstake "
                f"to prevent position fragmentation.",
                "DeFi Safety",
            )


    def check_unsafe_proportional_calculation(self):
        """#86 Detect division by mutable variables without zero-check guards.

        DeFi functions that compute proportional shares, rewards, or exchange rates
        often divide by a mutable total (total-supply, total-assets, pool-balance,
        total-staked). If that total is zero (empty pool, first deposit, post-drain),
        the division causes a runtime abort — a permanent denial of service.

        Common exploitable scenarios:
        - First depositor: pool starts with total-supply = u0, share calc aborts
        - Post-emergency-drain: all funds withdrawn, reward calc divides by u0
        - Race condition: last withdrawer takes everything, next TX aborts
        """
        # Mutable variables that are commonly used as divisors in proportional calcs
        divisor_var_patterns = re.compile(
            r'(total[-_]?supply|total[-_]?assets|total[-_]?deposits|total[-_]?staked|'
            r'total[-_]?shares|total[-_]?balance|total[-_]?liquidity|total[-_]?pool|'
            r'pool[-_]?balance|pool[-_]?size|reserve[-_]?balance|total[-_]?weight)',
            re.IGNORECASE
        )

        # Division patterns using var-get as divisor (handles nested parens in numerator)
        div_by_var_pattern = re.compile(
            r'\(/\s+.+?\(var-get\s+([a-zA-Z][-a-zA-Z0-9_]*)\)',
            re.DOTALL
        )
        # Division by ft-get-supply (token supply as divisor)
        div_by_ft_supply = re.compile(
            r'\(/\s+.+?\(ft-get-supply\s+',
            re.DOTALL
        )

        # Zero-check guard patterns — broad enough to handle (var-get ...) expressions
        zero_check_patterns = re.compile(
            r'(asserts!\s*\(>\s+.+?\s+u0\)|'
            r'asserts!\s*\(>=\s+.+?\s+u1\)|'
            r'asserts!\s*\(not\s+\(is-eq\s+.+?\s+u0\)\)|'
            r'if\s+\(is-eq\s+.+?\s+u0\)|'
            r'if\s+\(>\s+.+?\s+u0\))',
        )

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Check for division by var-get with a total-like variable
            vulnerable_var = None
            has_division = False

            for m in div_by_var_pattern.finditer(func_body):
                var_name = m.group(1)
                if divisor_var_patterns.search(var_name):
                    vulnerable_var = var_name
                    has_division = True
                    break

            # Also check division by ft-get-supply (token supply as divisor)
            if not has_division and div_by_ft_supply.search(func_body):
                vulnerable_var = 'ft-get-supply'
                has_division = True

            if not has_division:
                continue

            # Check if there's a zero-check guard anywhere in the function
            if zero_check_patterns.search(func_body):
                continue

            display_divisor = f"var-get {vulnerable_var}" if vulnerable_var != 'ft-get-supply' else 'ft-get-supply'
            self.add_finding(
                Severity.HIGH,
                f"Unsafe Proportional Calculation in \'{func_name}\' — Division by Zero Risk",
                f"The \'{func_name}\' function divides by ({display_divisor}) without "
                f"checking that the divisor is non-zero. When the pool is empty "
                f"(total is u0), this causes a runtime abort, permanently bricking "
                f"the function until someone manually seeds the pool. This creates a "
                f"denial-of-service vulnerability exploitable after emergency drains, "
                f"on first deposit, or when the last user withdraws everything.",
                func_start + 1,
                func_lines[0].strip() if func_lines else "",
                f"Add a zero-check before division: (asserts! (> ({display_divisor}) u0) "
                f"ERR-EMPTY-POOL). For first-deposit scenarios, use a conditional branch: "
                f"(if (is-eq ({display_divisor}) u0) <initial-deposit-logic> "
                f"<proportional-calc>). Consider also setting a minimum initial deposit "
                f"to prevent share inflation attacks.",
                "DeFi Safety",
            )

    def check_missing_withdrawal_cooldown(self):
        """#87 Detect withdraw/unstake functions without time-delay enforcement.

        DeFi staking/pool contracts that allow instant withdrawal after deposit
        are vulnerable to flash-deposit attacks: an attacker deposits, manipulates
        pool state (e.g. inflates rewards, shifts vote weight, skews price), and
        immediately withdraws — all within the same block or consecutive blocks.

        Legitimate staking contracts enforce cooldown/lock periods via block-height
        checks to ensure depositors have skin in the game for a minimum duration.
        """
        full_code = '\n'.join(self._strip_comments(l) for l in self.lines)

        # Only flag contracts that ALSO have deposit-like functions (confirms staking pattern)
        deposit_fn_pattern = re.compile(
            r'\(define-public\s+\((deposit|stake|provide|add-liquidity|lock-tokens|enter-pool)',
            re.IGNORECASE
        )
        if not deposit_fn_pattern.search(full_code):
            return

        # Withdraw-like function names
        withdraw_fn_names = re.compile(
            r'^(withdraw|unstake|redeem|remove-liquidity|exit-pool|unlock-tokens|claim-and-withdraw)$',
            re.IGNORECASE
        )

        # Transfer patterns — function must actually move funds
        transfer_pattern = re.compile(
            r'(stx-transfer\?|ft-transfer\?|contract-call\?.*transfer)',
            re.IGNORECASE
        )

        # Safe patterns — any time-delay / cooldown enforcement
        cooldown_patterns = re.compile(
            r'(cooldown|lock[-_]?period|min[-_]?blocks|withdrawal[-_]?delay|'
            r'unlock[-_]?at|locked[-_]?until|earliest[-_]?withdraw|'
            r'min[-_]?stake[-_]?blocks|min[-_]?lock|vesting|maturity|'
            r'lock[-_]?duration|time[-_]?lock|lockup|unbonding)',
            re.IGNORECASE
        )

        # Block-height arithmetic — comparing stored deposit height to current
        height_check_pattern = re.compile(
            r'(block-height\s.*deposit|block-height\s.*stake|block-height\s.*lock|'
            r'block-height\s.*entry|block-height\s.*start|'
            r'\(-\s+block-height\s|'
            r'>=?\s+block-height\s|'
            r'asserts!.*block-height)',
            re.IGNORECASE
        )

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            if not withdraw_fn_names.match(func_name):
                continue

            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Must actually transfer funds
            if not transfer_pattern.search(func_body):
                continue

            # Check for cooldown references
            if cooldown_patterns.search(func_body):
                continue

            # Check for block-height arithmetic (comparing deposit time)
            if height_check_pattern.search(func_body):
                continue

            self.add_finding(
                Severity.HIGH,
                f"Missing Withdrawal Cooldown in '{func_name}' — Flash Deposit Attack Risk",
                f"The '{func_name}' function transfers funds without enforcing any "
                f"time-delay or cooldown period since deposit. This enables flash-deposit "
                f"attacks where an attacker deposits and withdraws in the same block to "
                f"manipulate pool state (inflate rewards, shift governance votes, skew "
                f"price calculations) without genuine economic commitment. Staking pools "
                f"without lockup periods offer no protection against this attack vector.",
                func_start + 1,
                func_lines[0].strip() if func_lines else "",
                f"Enforce a minimum lock period before withdrawal by storing the deposit "
                f"block-height and requiring a cooldown: (asserts! (>= (- block-height "
                f"(get deposit-block position)) MIN-LOCK-PERIOD) ERR-COOLDOWN-ACTIVE). "
                f"Common lock periods range from 100-2100 blocks (~16 hours to ~2 weeks). "
                f"Consider implementing a graduated unlock schedule for larger positions.",
                "DeFi Safety",
            )

    def check_unprotected_liquidation(self):
        """#88 Detect liquidation functions without price manipulation safeguards.

        DeFi lending/margin contracts with liquidation functions that rely on a single
        price source without deviation caps, grace periods, or multi-oracle validation
        are vulnerable to oracle manipulation attacks. An attacker can temporarily skew
        the price (via flash loans, DEX manipulation, or oracle front-running) to trigger
        unfair liquidations of healthy positions, seizing collateral at a discount.

        Safe liquidation implementations include: price deviation bounds, TWAP/time-weighted
        prices, multi-oracle median, grace periods before liquidation, and maximum
        liquidation discounts.
        """
        full_code = '\n'.join(self._strip_comments(l) for l in self.lines)

        # Only flag contracts with price/oracle references (lending/margin pattern)
        price_usage = re.compile(
            r'(get-price|oracle|price-feed|get-rate|get-exchange-rate|'
            r'collateral[-_]?ratio|loan[-_]?to[-_]?value|ltv)',
            re.IGNORECASE
        )
        if not price_usage.search(full_code):
            return

        # Liquidation function names
        liquidation_fn_names = re.compile(
            r'^(liquidate|liquidation|force-close|margin-call|'
            r'seize[-_]?collateral|close[-_]?position|force[-_]?repay|'
            r'liquidate[-_]?position|liquidate[-_]?loan|execute[-_]?liquidation)$',
            re.IGNORECASE
        )

        # Transfer patterns — function must actually move funds/collateral
        transfer_pattern = re.compile(
            r'(stx-transfer\?|ft-transfer\?|nft-transfer\?|contract-call\?.*transfer)',
            re.IGNORECASE
        )

        # Safe patterns — price manipulation protections
        safe_patterns = re.compile(
            r'(price[-_]?deviation|max[-_]?deviation|deviation[-_]?threshold|'
            r'twap|time[-_]?weighted|price[-_]?average|moving[-_]?average|'
            r'multi[-_]?oracle|oracle[-_]?count|median[-_]?price|'
            r'grace[-_]?period|liquidation[-_]?delay|cooldown|'
            r'max[-_]?discount|liquidation[-_]?bonus|max[-_]?penalty|'
            r'price[-_]?staleness|price[-_]?freshness|last[-_]?updated|'
            r'circuit[-_]?breaker|price[-_]?band|price[-_]?cap|'
            r'min[-_]?collateral[-_]?ratio|health[-_]?factor)',
            re.IGNORECASE
        )

        # Health/ratio check — verifies position is actually undercollateralized
        health_check = re.compile(
            r'(asserts!.*collateral.*ratio|asserts!.*health|asserts!.*ltv|'
            r'asserts!.*under[-_]?collateral|'
            r'if.*collateral.*ratio|if.*health[-_]?factor)',
            re.IGNORECASE
        )

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            if not liquidation_fn_names.match(func_name):
                continue

            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Must actually transfer funds/collateral
            if not transfer_pattern.search(func_body):
                continue

            # Check for price manipulation safeguards
            if safe_patterns.search(func_body):
                continue

            # Determine severity based on whether health check exists
            has_health_check = bool(health_check.search(func_body))
            severity = Severity.HIGH if not has_health_check else Severity.MEDIUM

            health_note = ""
            if not has_health_check:
                health_note = (
                    " Additionally, no collateral ratio or health factor validation "
                    "was detected — the function may liquidate positions without verifying "
                    "they are actually undercollateralized."
                )

            self.add_finding(
                severity,
                f"Unprotected Liquidation in \'{func_name}\' — Oracle Manipulation Risk",
                f"The \'{func_name}\' function performs liquidation (transfers collateral) "
                f"without price manipulation safeguards such as deviation caps, TWAP/time-weighted "
                f"pricing, multi-oracle validation, or liquidation grace periods. An attacker can "
                f"temporarily manipulate the price oracle (via flash loans, DEX pool manipulation, "
                f"or oracle front-running) to trigger unfair liquidations of healthy positions, "
                f"seizing collateral at a steep discount.{health_note}",
                func_start + 1,
                func_lines[0].strip() if func_lines else "",
                f"Implement multiple layers of liquidation protection: (1) Use TWAP or multi-oracle "
                f"median pricing instead of spot price. (2) Add a price deviation cap — reject "
                f"liquidations when price moved >X% in a short period. (3) Enforce a grace period "
                f"allowing borrowers to add collateral before seizure. (4) Cap the liquidation "
                f"discount/bonus to prevent excessive profit extraction. (5) Verify the position "
                f"is genuinely undercollateralized: (asserts! (< collateral-ratio MIN-RATIO) "
                f"ERR-POSITION-HEALTHY).",
                "DeFi Safety",
            )


    def check_missing_quorum_validation(self):
        """#89 Detect governance execution without quorum validation.

        DAO/governance contracts that execute proposals (transferring funds, changing
        parameters, upgrading contracts) without verifying that a minimum quorum of
        voters participated are vulnerable to low-turnout attacks. An attacker can
        wait for low participation periods (holidays, off-hours) and pass malicious
        proposals with minimal votes.

        Safe governance implementations enforce minimum quorum thresholds: a minimum
        number or percentage of total voting power must participate before a proposal
        can be executed.
        """
        full_code = '\n'.join(self._strip_comments(l) for l in self.lines)

        # Only flag contracts with governance/proposal patterns
        governance_pattern = re.compile(
            r'(proposal|governance|voting|ballot|referendum|dao)',
            re.IGNORECASE
        )
        if not governance_pattern.search(full_code):
            return

        # Must have vote tracking (map with vote/ballot/tally references)
        vote_tracking = re.compile(
            r'(define-map\s+\S*(vote|ballot|tally|poll))',
            re.IGNORECASE
        )
        if not vote_tracking.search(full_code):
            return

        # Execution function names
        execute_fn_names = re.compile(
            r'^(execute[-_]?proposal|finalize[-_]?proposal|conclude[-_]?vote|'
            r'execute[-_]?vote|settle[-_]?proposal|enact[-_]?proposal|'
            r'process[-_]?proposal|close[-_]?vote|resolve[-_]?proposal|'
            r'execute|finalize|conclude|enact)$',
            re.IGNORECASE
        )

        # Transfer/state-change patterns — must do something consequential
        consequential_action = re.compile(
            r'(stx-transfer\?|ft-transfer\?|nft-transfer\?|contract-call\?|'
            r'var-set|map-set|map-delete)',
            re.IGNORECASE
        )

        # Safe patterns — quorum validation
        quorum_patterns = re.compile(
            r'(quorum|min[-_]?votes|minimum[-_]?votes|min[-_]?participation|'
            r'vote[-_]?threshold|min[-_]?turnout|required[-_]?votes|'
            r'min[-_]?voters|participation[-_]?threshold|vote[-_]?count.*>=|'
            r'total[-_]?votes.*>=|enough[-_]?votes)',
            re.IGNORECASE
        )

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            if not execute_fn_names.match(func_name):
                continue

            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Must perform consequential action
            if not consequential_action.search(func_body):
                continue

            # Check for quorum validation
            if quorum_patterns.search(func_body):
                continue

            self.add_finding(
                Severity.HIGH,
                f"Missing Quorum Validation in '{func_name}' — Low-Turnout Attack Risk",
                f"The '{func_name}' function executes a governance proposal (performs "
                f"state changes or transfers) without verifying that a minimum quorum "
                f"of voters participated. Without quorum enforcement, an attacker can "
                f"wait for low participation periods and pass malicious proposals with "
                f"a tiny fraction of total voting power. This enables unauthorized fund "
                f"transfers, parameter changes, or contract upgrades with minimal opposition.",
                func_start + 1,
                func_lines[0].strip() if func_lines else "",
                f"Add quorum validation before executing any proposal: "
                f"(1) Track total votes cast per proposal. "
                f"(2) Define a minimum quorum constant (e.g., 10-30%% of total supply): "
                f"(define-constant QUORUM-THRESHOLD u1000000). "
                f"(3) Assert quorum is met before execution: "
                f"(asserts! (>= (var-get total-votes-cast) QUORUM-THRESHOLD) ERR-QUORUM-NOT-MET). "
                f"(4) Consider both vote count AND voting power thresholds for robust governance.",
                "Governance",
            )


    def check_unchecked_transfer_return(self):
        """#90 Detect unchecked return values from transfer functions.

        In Clarity, transfer functions (stx-transfer?, ft-transfer?, nft-transfer?)
        return (response bool uint) to indicate success or failure. If a function
        calls these transfers but doesn't check the return value with try!, unwrap!,
        asserts!, or match, the transfer could silently fail and the contract logic
        will continue as if the transfer succeeded. This can lead to:
        - Double-spend vulnerabilities (withdrawal succeeds even though transfer failed)
        - Accounting inconsistencies (balance updated despite failed transfer)
        - Loss of funds (escrow released even though payment failed)

        Safe implementations must explicitly check transfer results before proceeding
        with state changes or returning success.
        """
        # Transfer function patterns
        transfer_pattern = re.compile(
            r'\((stx-transfer\?|ft-transfer\?|nft-transfer\?)\s',
            re.IGNORECASE
        )

        # Safe patterns that indicate return value is checked
        # 1. Wrapped in try! or unwrap! or unwrap-panic
        # 2. Assigned to a var and then checked with asserts! or match
        # 3. Used directly in asserts! or match
        checked_patterns = [
            re.compile(r'\(try!\s*\((?:stx|ft|nft)-transfer\?', re.IGNORECASE),
            re.compile(r'\(unwrap!\s*\((?:stx|ft|nft)-transfer\?', re.IGNORECASE),
            re.compile(r'\(unwrap-panic\s*\((?:stx|ft|nft)-transfer\?', re.IGNORECASE),
            re.compile(r'\(asserts!\s*\((?:stx|ft|nft)-transfer\?', re.IGNORECASE),
            re.compile(r'\(match\s+\((?:stx|ft|nft)-transfer\?', re.IGNORECASE),
            re.compile(r'\(let\s*\(\s*\([^)]*\s+\((?:stx|ft|nft)-transfer\?[^)]*\)\s*\)[^)]*\((?:asserts!|match|try!|unwrap)', re.IGNORECASE),
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            # Find all transfer calls
            transfer_matches = list(transfer_pattern.finditer(func_body))
            
            if not transfer_matches:
                continue

            # For each transfer, check if it's wrapped in a checking construct
            for match in transfer_matches:
                transfer_pos = match.start()
                # Get surrounding context (100 chars before and after)
                context_start = max(0, transfer_pos - 100)
                context_end = min(len(func_body), transfer_pos + 200)
                context = func_body[context_start:context_end]

                # Check if any safe pattern matches this context
                # Additional check: let-binding with later asserts! on is-ok
                if re.search(r'\(let\s*\(', context, re.IGNORECASE) and \
                   re.search(r'\(asserts!.*is-ok', context, re.IGNORECASE | re.DOTALL):
                    is_checked = True
                else:
                    is_checked = any(pattern.search(context) for pattern in checked_patterns)

                if not is_checked:
                    # Find the actual line within the function for better reporting
                    lines_before_match = func_body[:transfer_pos].count('\n')
                    actual_line = func_start + lines_before_match + 1
                    
                    transfer_type = match.group(1)
                    
                    self.add_finding(
                        Severity.HIGH,
                        f"Unchecked Transfer Return Value in '{func_name}' — Silent Failure Risk",
                        f"The function '{func_name}' calls '{transfer_type}' without checking "
                        f"the return value. In Clarity, transfer functions return (response bool uint) "
                        f"to indicate success or failure. If the transfer fails (e.g., insufficient "
                        f"balance, frozen account, invalid recipient), the contract will continue "
                        f"executing as if the transfer succeeded. This can lead to double-spending "
                        f"(withdrawals succeed even when transfer fails), accounting inconsistencies "
                        f"(balances updated despite failed transfers), or loss of funds (escrow "
                        f"released even when payment fails). Attackers can exploit this by forcing "
                        f"transfers to fail while still receiving state updates in their favor.",
                        actual_line,
                        func_lines[lines_before_match].strip() if lines_before_match < len(func_lines) else "",
                        f"Wrap all transfer calls in error-checking constructs: "
                        f"(1) Use try!: (try! (stx-transfer? amt sender recipient) ERR-TRANSFER-FAILED) — "
                        f"automatically propagates errors up the call stack. "
                        f"(2) Use unwrap!: (unwrap! (ft-transfer? token amt sender recipient) ERR-TRANSFER) — "
                        f"aborts with custom error on failure. "
                        f"(3) Use match for custom error handling: "
                        f"(match (nft-transfer? token-id sender recipient) success-branch error-branch). "
                        f"(4) Never ignore transfer return values — treat them as critical security checks.",
                        "Fund Safety",
                    )
    def check_signature_replay(self):
        """#91 Detect signature verification without replay protection.

        In Clarity, secp256k1-recover? and secp256k1-verify allow contracts to
        verify off-chain signatures. However, if the contract doesn't track which
        signatures have been used (via nonces, used-signature maps, or sequence
        numbers), the same valid signature can be submitted multiple times to
        replay the action. This enables:
        - Double-spending (same withdrawal signature replayed)
        - Duplicate vote counting (governance signatures replayed)
        - Repeated reward claims (claim signature replayed after each epoch)

        Safe implementations must include nonce tracking, used-signature maps,
        or sequence number validation to prevent replay attacks.
        """
        # Signature verification patterns
        sig_pattern = re.compile(
            r'\((secp256k1-recover\?|secp256k1-verify)\s',
            re.IGNORECASE
        )

        # Safe patterns indicating replay protection
        replay_guard_patterns = [
            re.compile(r'nonce', re.IGNORECASE),
            re.compile(r'used-signature', re.IGNORECASE),
            re.compile(r'processed-signature', re.IGNORECASE),
            re.compile(r'consumed-signature', re.IGNORECASE),
            re.compile(r'seen-hash', re.IGNORECASE),
            re.compile(r'replay', re.IGNORECASE),
            re.compile(r'sequence', re.IGNORECASE),
            re.compile(r'msg-id', re.IGNORECASE),
            re.compile(r'action-id', re.IGNORECASE),
        ]

        for func_name, func_start, _, func_lines in self._iter_function_blocks('public'):
            func_body = '\n'.join(self._strip_comments(l) for l in func_lines)

            sig_matches = list(sig_pattern.finditer(func_body))
            if not sig_matches:
                continue

            # Check if function body references any replay guard pattern
            func_has_guard = any(p.search(func_body) for p in replay_guard_patterns)

            if func_has_guard:
                continue

            # Found signature verification without replay protection
            first_match = sig_matches[0]
            lines_before = func_body[:first_match.start()].count('\n')
            actual_line = func_start + lines_before + 1
            sig_func = first_match.group(1)

            self.add_finding(
                Severity.HIGH,
                f"Signature Replay Vulnerability in \'{func_name}\' — Missing Nonce/Replay Guard",
                f"The function \'{func_name}\' uses \'{sig_func}\' to verify off-chain "
                f"signatures but has no replay protection mechanism. Without nonce tracking, "
                f"used-signature maps, or sequence number validation, the same valid signature "
                f"can be submitted multiple times to repeat the action. Attackers can replay "
                f"withdrawal authorizations to drain funds, replay governance votes to skew "
                f"outcomes, or replay reward claims to extract more than their share. "
                f"The contract has no map or variable tracking used signatures or nonces.",
                actual_line,
                func_lines[lines_before].strip() if lines_before < len(func_lines) else "",
                f"Implement replay protection: "
                f"(1) Nonce tracking: maintain a per-user nonce map, include the nonce in the "
                f"signed message, and increment after each use. "
                f"(2) Used-signature map: store each signature hash after first use and reject "
                f"duplicates with (asserts! (is-none (map-get? used-signatures sig)) ERR-REPLAY). "
                f"(3) Sequence numbers: require monotonically increasing sequence numbers in "
                f"signed messages and track the last-used sequence per user. "
                f"(4) Include contract address and chain-id in signed data to prevent cross-contract "
                f"and cross-chain replay.",
                "Cryptographic Safety",
            )

    def check_unvalidated_oracle_update(self):
        """#92 Detect price oracle updates without safety controls.

        Oracle price manipulation is a critical attack vector in DeFi. When
        set-price/update-price/set-rate functions allow arbitrary price updates
        without proper controls, a compromised oracle admin or exploited update
        mechanism can instantly manipulate prices to:
        - Drain lending protocols via unfair liquidations
        - Enable arbitrage attacks by setting fake exchange rates
        - Steal collateral by manipulating collateralization ratios

        Safe implementations must include at least one of:
        - Deviation bounds (max % change from current price)
        - Timelock delays (proposal + execution with waiting period)
        - Multi-signature requirements (2+ confirmations)
        - Quorum voting for oracle updates
        """
        # Oracle update function name patterns
        oracle_update_pattern = re.compile(
            r'^('
            r'set-price|update-price|set-rate|update-rate|'
            r'set-oracle|update-oracle|set-feed|update-feed|'
            r'set-btc-price|set-eth-price|set-stx-price|'
            r'update-btc-price|update-eth-price|update-stx-price'
            r')$',
            re.IGNORECASE
        )
        # Safe control patterns
        deviation_patterns = [
            re.compile(r'deviation', re.IGNORECASE),
            re.compile(r'max-change', re.IGNORECASE),
            re.compile(r'price-band', re.IGNORECASE),
            re.compile(r'max-diff', re.IGNORECASE),
            re.compile(r'bounds', re.IGNORECASE),
        ]

        timelock_patterns = [
            re.compile(r'timelock', re.IGNORECASE),
            re.compile(r'delay', re.IGNORECASE),
            re.compile(r'proposal-time', re.IGNORECASE),
            re.compile(r'propose-price', re.IGNORECASE),
            re.compile(r'execute-price', re.IGNORECASE),
            re.compile(r'pending-price', re.IGNORECASE),
        ]

        multisig_patterns = [
            re.compile(r'confirmations?', re.IGNORECASE),
            re.compile(r'multi-?sig', re.IGNORECASE),
            re.compile(r'signers?', re.IGNORECASE),
            re.compile(r'approvals?', re.IGNORECASE),
            re.compile(r'threshold', re.IGNORECASE),
        ]

        # Scan for vulnerable oracle update functions
        for fn_name, fn_start, _, fn_lines in self._iter_function_blocks('public'):
            fn_body = "\n".join(fn_lines)

            # Only check functions with oracle update naming
            if not oracle_update_pattern.match(fn_name):
                continue

            # Check for safety controls
            has_deviation = any(p.search(fn_body) for p in deviation_patterns)
            has_timelock = any(p.search(fn_body) for p in timelock_patterns)
            has_multisig = any(p.search(fn_body) for p in multisig_patterns)

            if not (has_deviation or has_timelock or has_multisig):
                self.add_finding(
                    severity=Severity.HIGH,
                    title="Unvalidated Oracle Price Update",
                    description=(
                        f"Function '{fn_name}' updates oracle price/rate without safety controls. "
                        f"A compromised admin or exploited update mechanism can manipulate prices "
                        f"to drain funds via unfair liquidations, enable arbitrage attacks, or "
                        f"steal collateral."
                    ),
                    line=fn_start + 1,
                    code_snippet=fn_body[:200],
                    recommendation=(
                        "Add safety controls: (1) deviation bounds to limit max price changes, "
                        "(2) timelock delay with propose/execute pattern, or "
                        "(3) multi-signature requirement with confirmation threshold."
                    ),
                    category="Oracle Safety"
                )



    def check_unsafe_at_block_usage(self):
        """#93 Detect unsafe at-block usage with user-supplied block hashes.

        The Clarity `(at-block <block-hash> <expr>)` builtin evaluates an
        expression in the context of a historical block.  When a public
        function accepts a block hash from the caller and passes it directly
        to `at-block` without validation, an attacker can:
        - Read historical state to bypass current security checks
        - Exploit time-dependent logic (vesting, lock-up, price feeds)
        - Manipulate balance snapshots used in governance voting

        Safe patterns include:
        - Using stored/trusted block hashes (var-get) instead of parameters
        - Restricting usage to read-only functions (no state mutation risk)
        - Validating the block height is within an acceptable range (recency)
        - Keeping at-block in private helper functions only
        """
        at_block_re = re.compile(r'\(at-block\b')

        # Patterns indicating the block hash is validated or safe
        validation_patterns = [
            re.compile(r'asserts!.*block-height', re.IGNORECASE),
            re.compile(r'asserts!.*block-height', re.IGNORECASE),
            re.compile(r'unwrap!.*block-height', re.IGNORECASE),
            re.compile(r'>.*block-height', re.IGNORECASE),
            re.compile(r'<.*block-height', re.IGNORECASE),
            re.compile(r'>=.*block-height', re.IGNORECASE),
            re.compile(r'<=.*block-height', re.IGNORECASE),
        ]

        # Check: at-block using var-get (trusted source) is safe
        trusted_hash_re = re.compile(r'\(at-block\s+\(var-get\b')

        for fn_name, fn_start, _, fn_lines in self._iter_function_blocks('public'):
            fn_body = "\n".join(fn_lines)

            # Skip if no at-block usage
            if not at_block_re.search(fn_body):
                continue

            # Safe: at-block uses a stored/trusted block hash via var-get
            if trusted_hash_re.search(fn_body):
                continue

            # Safe: function validates block height before at-block
            has_validation = any(p.search(fn_body) for p in validation_patterns)
            if has_validation:
                continue

            self.add_finding(
                severity=Severity.MEDIUM,
                title="Unsafe at-block with User-Supplied Hash",
                description=(
                    f"Public function '{fn_name}' uses (at-block) with a "
                    f"caller-supplied block hash without validation. An attacker "
                    f"can pass arbitrary historical block hashes to read stale "
                    f"state, bypass current security checks, or manipulate "
                    f"time-dependent logic (vesting, voting snapshots, price feeds)."
                ),
                line=fn_start + 1,
                code_snippet=fn_body[:200],
                recommendation=(
                    "Validate the block hash: (1) use a stored/trusted hash via "
                    "(var-get) instead of accepting user input, (2) verify the "
                    "block height is within an acceptable recency window, or "
                    "(3) restrict at-block usage to read-only functions."
                ),
                category="State Safety"
            )


    def check_division_by_zero_risk(self):
        """#94 Detect division by potentially-zero denominator in public functions.

        In Clarity, dividing by zero causes a runtime error that aborts the
        entire transaction.  If the denominator is user-controlled (function
        parameter) or comes from a data-var that can be zero (e.g. an empty
        pool's total-shares), an attacker or edge-case scenario can trigger
        a DoS by forcing the denominator to zero.

        Safe patterns:
        - Asserting denominator > u0 before dividing
        - Using if/is-eq zero-check before division
        - Dividing by a constant literal (u100, u1000000, etc.)
        - Division in read-only or private functions (lower/no risk)
        """
        # Match (/ <numerator> <denominator>) — the denominator is any non-literal-uint expr
        div_re = re.compile(r'\(/\s+')
        literal_denom_re = re.compile(r'\(/\s+\S+\s+u\d+\)')
        zero_check_patterns = [
            re.compile(r'asserts!.*>\s+.+?\s+u0', re.IGNORECASE),
            re.compile(r'asserts!.*is-eq\s+.+?\s+u0', re.IGNORECASE),
            re.compile(r'if\s+\(is-eq\s+.+?\s+u0', re.IGNORECASE),
            re.compile(r'if\s+\(>\s+.+?\s+u0', re.IGNORECASE),
            re.compile(r'\(>\s+.+?\s+u0\)', re.IGNORECASE),
        ]

        for fn_name, fn_start, _, fn_lines in self._iter_function_blocks('public'):
            fn_body = "\n".join(fn_lines)

            # Skip if no division in this function
            if not div_re.search(fn_body):
                continue

            # Skip if ALL divisions use constant denominators
            divs_with_vars = False
            for line in fn_lines:
                stripped = self._strip_comments(line)
                if div_re.search(stripped) and not literal_denom_re.search(stripped):
                    divs_with_vars = True
                    break

            if not divs_with_vars:
                continue

            # Check if there's a zero-guard
            has_zero_check = any(p.search(fn_body) for p in zero_check_patterns)
            if has_zero_check:
                continue

            self.add_finding(
                severity=Severity.MEDIUM,
                title="Division by Zero Risk — Potential DoS",
                description=(
                    f"Public function '{fn_name}' performs division where the "
                    f"denominator could be zero (user parameter or unguarded "
                    f"data-var). In Clarity, division by zero aborts the "
                    f"transaction, enabling a denial-of-service vector."
                ),
                line=fn_start + 1,
                code_snippet=fn_body[:200],
                recommendation=(
                    "Add a zero-check before division: "
                    "(asserts! (> denominator u0) (err ERR_ZERO_DIVISION)). "
                    "Alternatively, handle the zero case with an if/is-eq guard."
                ),
                category="Arithmetic Safety"
            )


def compute_security_score(findings: List[Finding]) -> Tuple[str, int]:
    """Compute a security score (0-100) and letter grade for a contract.

    Scoring:
    - Start at 100 points
    - CRITICAL: -25 each
    - HIGH: -15 each
    - MEDIUM: -8 each
    - LOW: -3 each
    - INFO: -1 each
    - Minimum score: 0

    Grades: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)
    """
    score = 100
    for f in findings:
        if f.severity == "CRITICAL":
            score -= 25
        elif f.severity == "HIGH":
            score -= 15
        elif f.severity == "MEDIUM":
            score -= 8
        elif f.severity == "LOW":
            score -= 3
        elif f.severity == "INFO":
            score -= 1
    score = max(0, score)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return grade, score


def generate_report(findings: List[Finding], contract_name: str, 
                   output_format: str = 'json') -> str:
    """Generate security report in JSON or Markdown format"""
    
    if output_format == 'json':
        grade, score = compute_security_score(findings)
        report = {
            "contract": contract_name,
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
            "security_score": score,
            "security_grade": grade,
            "total_findings": len(findings),
            "severity_breakdown": {
                "CRITICAL": len([f for f in findings if f.severity == "CRITICAL"]),
                "HIGH": len([f for f in findings if f.severity == "HIGH"]),
                "MEDIUM": len([f for f in findings if f.severity == "MEDIUM"]),
                "LOW": len([f for f in findings if f.severity == "LOW"]),
                "INFO": len([f for f in findings if f.severity == "INFO"])
            },
            "findings": [f.to_dict() for f in findings]
        }
        return json.dumps(report, indent=2)
    
    elif output_format == 'markdown':
        grade, score = compute_security_score(findings)
        severity_counts = {
            "CRITICAL": len([f for f in findings if f.severity == "CRITICAL"]),
            "HIGH": len([f for f in findings if f.severity == "HIGH"]),
            "MEDIUM": len([f for f in findings if f.severity == "MEDIUM"]),
            "LOW": len([f for f in findings if f.severity == "LOW"]),
            "INFO": len([f for f in findings if f.severity == "INFO"])
        }
        
        report = f"""# 🛡️ Clarity Shield Security Report

**Contract:** `{contract_name}`  
**Scan Date:** {datetime.now().strftime("%Y-%m-%d")}  
**Security Score:** {grade} ({score}/100)  
**Total Findings:** {len(findings)}

## Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | {severity_counts['CRITICAL']} |
| 🟠 HIGH | {severity_counts['HIGH']} |
| 🟡 MEDIUM | {severity_counts['MEDIUM']} |
| 🔵 LOW | {severity_counts['LOW']} |
| ⚪ INFO | {severity_counts['INFO']} |

---

"""
        
        for idx, finding in enumerate(findings, 1):
            icon = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪"
            }[finding.severity]
            
            report += f"""## {icon} Finding #{idx}: {finding.title}

**Severity:** {finding.severity}  
**Category:** {finding.category}  
**Line:** {finding.line}

### Description
{finding.description}

### Code Snippet
```clarity
{finding.code_snippet}
```

### Recommendation
{finding.recommendation}

---

"""
        
        return report

    elif output_format == 'html':
        severity_colors = {
            'CRITICAL': '#dc2626', 'HIGH': '#ea580c',
            'MEDIUM': '#ca8a04', 'LOW': '#2563eb', 'INFO': '#6b7280'
        }
        severity_counts = {s: len([f for f in findings if f.severity == s])
                          for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']}

        findings_html = ''
        for idx, finding in enumerate(findings, 1):
            color = severity_colors.get(finding.severity, '#6b7280')
            findings_html += f"""
            <div class='finding'>
              <div class='finding-header'>
                <span class='severity-badge' style='background:{color}'>{finding.severity}</span>
                <span class='finding-title'>#{idx}: {finding.title}</span>
                <span class='confidence'>Confidence: {finding.confidence}</span>
              </div>
              <p><strong>Category:</strong> {finding.category} | <strong>Line:</strong> {finding.line}</p>
              <p>{finding.description}</p>
              <pre><code>{finding.code_snippet}</code></pre>
              <p class='recommendation'><strong>Fix:</strong> {finding.recommendation}</p>
            </div>"""

        bars = ''.join(f"""<div class='bar-item'>
          <div class='bar' style='height:{max(severity_counts[s]*8,2)}px;background:{severity_colors[s]}'></div>
          <span>{s}: {severity_counts[s]}</span></div>""" for s in severity_counts)

        report = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>Clarity Shield Report - {contract_name}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:900px;margin:0 auto;padding:2rem;background:#0f172a;color:#e2e8f0}}
h1{{color:#38bdf8}} h2{{color:#94a3b8;border-bottom:1px solid #334155;padding-bottom:.5rem}}
.summary{{display:flex;gap:2rem;margin:1.5rem 0;padding:1rem;background:#1e293b;border-radius:8px}}
.bar-item{{text-align:center;font-size:.85rem}} .bar{{width:40px;margin:0 auto 4px;border-radius:3px;min-height:2px}}
.finding{{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0;border-left:3px solid #334155}}
.finding-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem}}
.severity-badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:600}}
.finding-title{{font-weight:600;font-size:1.05rem}} .confidence{{margin-left:auto;font-size:.8rem;color:#94a3b8}}
pre{{background:#0f172a;padding:.75rem;border-radius:6px;overflow-x:auto}}
code{{color:#7dd3fc;font-size:.9rem}} .recommendation{{color:#86efac;font-style:italic}}
</style></head><body>
<h1>🛡️ Clarity Shield Security Report</h1>
<p><strong>Contract:</strong> {contract_name} | <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')} | <strong>Findings:</strong> {len(findings)}</p>
<div class='summary'>{bars}</div>
<h2>Findings</h2>
{findings_html}
<footer style='margin-top:2rem;color:#64748b;font-size:.85rem'>Generated by Clarity Shield v{VERSION}</footer>
</body></html>"""
        return report


def generate_sarif(all_findings: dict, tool_version: str = VERSION) -> str:
    """Generate SARIF 2.1.0 output for CI/CD integration (GitHub Code Scanning)"""
    rules = {}
    results = []

    for contract_name, findings in all_findings.items():
        for f in findings:
            rule_id = f.category.lower().replace(" ", "-") + "." + f.title.lower()[:40].replace(" ", "-")
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title[:60],
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                                  "LOW": "note", "INFO": "note"}.get(f.severity, "warning")
                    },
                    "helpUri": "https://github.com/clarity-shield/clarity-shield"
                }
            results.append({
                "ruleId": rule_id,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                          "LOW": "note", "INFO": "note"}.get(f.severity, "warning"),
                "message": {"text": f"{f.description}\n\nRecommendation: {f.recommendation}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": contract_name + ".clar"},
                        "region": {"startLine": f.line}
                    }
                }]
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Clarity Shield",
                    "version": tool_version,
                    "informationUri": "https://github.com/clarity-shield/clarity-shield",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }
    return json.dumps(sarif, indent=2)


def collect_contracts(path: Path, recursive: bool = False) -> List[Path]:
    """Collect .clar files from a path (file or directory)"""
    if path.is_file():
        return [path]
    if path.is_dir():
        pattern = "**/*.clar" if recursive else "*.clar"
        return sorted(path.glob(pattern))
    return []


def print_summary_dashboard(all_findings: Dict[str, List[Finding]]) -> None:
    """Print compact per-contract severity breakdown table with security score."""
    headers = ["Contract", "Score", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    rows: List[List[str]] = []
    for contract_name in sorted(all_findings.keys()):
        findings = all_findings[contract_name]
        counts = {
            severity: sum(1 for finding in findings if finding.severity == severity)
            for severity in SEVERITY_ORDER
        }
        grade, score = compute_security_score(findings)
        rows.append(
            [
                contract_name,
                f"{grade} ({score})",
                str(counts["CRITICAL"]),
                str(counts["HIGH"]),
                str(counts["MEDIUM"]),
                str(counts["LOW"]),
                str(counts["INFO"]),
            ]
        )

    if not rows:
        return

    widths = []
    for col_idx, header in enumerate(headers):
        widths.append(max(len(header), *(len(row[col_idx]) for row in rows)))

    def _hline(left: str, mid: str, right: str) -> str:
        return left + mid.join("─" * (width + 2) for width in widths) + right

    def _format_row(row: List[str]) -> str:
        cells = []
        for idx, value in enumerate(row):
            if idx == 0:
                cells.append(f" {value.ljust(widths[idx])} ")
            else:
                cells.append(f" {value.center(widths[idx])} ")
        return "│" + "│".join(cells) + "│"

    print("\n[+] Summary Dashboard", file=sys.stderr)
    print(_hline("┌", "┬", "┐"), file=sys.stderr)
    print(_format_row(headers), file=sys.stderr)
    print(_hline("├", "┼", "┤"), file=sys.stderr)
    for row in rows:
        print(_format_row(row), file=sys.stderr)
    print(_hline("└", "┴", "┘"), file=sys.stderr)


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="clarity-shield",
        description="🛡️  Clarity Shield — Smart Contract Security Scanner for Stacks"
    )
    parser.add_argument("target", help="Clarity contract file or directory to scan")
    parser.add_argument("--format", "-f", choices=["json", "markdown", "html", "sarif"],
                        default="markdown", help="Output format (default: markdown)")
    parser.add_argument("--recursive", "-r", action="store_true",
                        help="Recursively scan subdirectories")
    parser.add_argument("--no-save", action="store_true",
                        help="Print report to stdout instead of saving files")
    parser.add_argument("--severity", "-s", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default=None, help="Minimum severity to report")
    parser.add_argument("--config", "-c",
                        help="Path to config file (.toml/.yaml/.yml)")
    parser.add_argument("--summary", action="store_true",
                        help="Print compact summary dashboard table")
    parser.add_argument("--version", action="version", version=f"clarity-shield {VERSION}")

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    scanner_cfg = config.get("scanner", {}) if isinstance(config.get("scanner", {}), dict) else {}
    configured_default_severity = scanner_cfg.get("default_severity", config.get("default_severity"))
    if configured_default_severity is not None:
        try:
            configured_default_severity = _normalize_severity(str(configured_default_severity))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    target = Path(args.target)
    if not target.exists():
        print(f"Error: '{args.target}' not found", file=sys.stderr)
        sys.exit(1)

    contracts = collect_contracts(target, args.recursive)
    if not contracts:
        print(f"Error: No .clar files found in '{args.target}'", file=sys.stderr)
        sys.exit(1)

    effective_severity = args.severity or configured_default_severity
    min_idx = SEVERITY_ORDER.index(effective_severity) if effective_severity else len(SEVERITY_ORDER) - 1

    all_findings: Dict[str, List[Finding]] = {}
    total = 0
    worst_severity = None

    for contract_path in contracts:
        scanner = ClarityScanner(str(contract_path), config=config)
        findings = scanner.scan()

        # Filter by severity
        findings = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= min_idx]
        all_findings[scanner.contract_name] = findings
        total += len(findings)

        for f in findings:
            idx = SEVERITY_ORDER.index(f.severity)
            if worst_severity is None or idx < SEVERITY_ORDER.index(worst_severity):
                worst_severity = f.severity

        if args.format != "sarif":
            report = generate_report(findings, scanner.contract_name, args.format)
            if args.no_save:
                print(report)
            else:
                output_dir = Path('findings')
                output_dir.mkdir(exist_ok=True)
                ext = {'json': 'json', 'markdown': 'md', 'html': 'html'}.get(args.format, 'md')
                output_file = output_dir / f"{scanner.contract_name}_report.{ext}"
                with open(output_file, 'w', encoding="utf-8") as fh:
                    fh.write(report)
                print(f"[+] Report saved to: {output_file}", file=sys.stderr)

    if args.format == "sarif":
        sarif_output = generate_sarif(all_findings)
        if args.no_save:
            print(sarif_output)
        else:
            output_dir = Path('findings')
            output_dir.mkdir(exist_ok=True)
            output_file = output_dir / "clarity-shield.sarif"
            with open(output_file, 'w', encoding="utf-8") as fh:
                fh.write(sarif_output)
            print(f"\n[+] SARIF report saved to: {output_file}", file=sys.stderr)

    if args.summary:
        print_summary_dashboard(all_findings)

    print(f"\n[+] Total: {total} findings across {len(contracts)} contract(s)", file=sys.stderr)

    # Exit code based on severity
    if worst_severity == "CRITICAL":
        sys.exit(2)
    elif worst_severity == "HIGH":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

