#!/usr/bin/env python3
"""
Clarity Shield - Smart Contract Security Scanner for Stacks Blockchain
Detects common vulnerabilities in Clarity smart contracts
"""

import re
import json
import sys
from dataclasses import dataclass, asdict
from typing import List, Iterator, Tuple
from pathlib import Path
from enum import Enum
from datetime import datetime


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
    
    def to_dict(self):
        return asdict(self)


class ClarityScanner:
    """Main scanner class for Clarity contracts"""
    
    def __init__(self, contract_path: str):
        self.contract_path = Path(contract_path)
        self.contract_name = self.contract_path.stem
        self.findings: List[Finding] = []
        self.lines: List[str] = []
        
        with open(contract_path, 'r') as f:
            self.content = f.read()
            self.lines = self.content.split('\n')
    
    def scan(self) -> List[Finding]:
        """Run all vulnerability checks"""
        print(f"[*] Scanning {self.contract_name}...")
        
        self.check_tx_sender_vs_contract_caller()
        self.check_unwrap_usage()
        self.check_arithmetic_safety()
        self.check_public_function_auth()
        self.check_data_map_validation()
        self.check_hardcoded_principals()
        self.check_response_handling()
        self.check_missing_post_conditions()
        self.check_stx_transfer_safety()
        self.check_block_height_dependency()
        self.check_read_only_side_effects()
        self.check_trait_implementation_safety()
        self.check_reentrancy_patterns()
        self.check_magic_numbers()
        self.check_principal_injection()
        self.check_unbounded_loops()
        self.check_flash_loan_patterns()
        self.check_missing_event_logging()
        
        print(f"[+] Found {len(self.findings)} potential issues")
        return self.findings
    
    def add_finding(self, severity: Severity, title: str, description: str,
                   line: int, code_snippet: str, recommendation: str, category: str):
        """Add a security finding"""
        finding = Finding(
            severity=severity.value,
            title=title,
            description=description,
            line=line,
            code_snippet=code_snippet.strip(),
            recommendation=recommendation,
            category=category
        )
        self.findings.append(finding)

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


def generate_report(findings: List[Finding], contract_name: str, 
                   output_format: str = 'json') -> str:
    """Generate security report in JSON or Markdown format"""
    
    if output_format == 'json':
        report = {
            "contract": contract_name,
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
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


def generate_sarif(all_findings: dict, tool_version: str = "1.0.0") -> str:
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


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="clarity-shield",
        description="🛡️  Clarity Shield — Smart Contract Security Scanner for Stacks"
    )
    parser.add_argument("target", help="Clarity contract file or directory to scan")
    parser.add_argument("--format", "-f", choices=["json", "markdown", "sarif"],
                        default="markdown", help="Output format (default: markdown)")
    parser.add_argument("--recursive", "-r", action="store_true",
                        help="Recursively scan subdirectories")
    parser.add_argument("--no-save", action="store_true",
                        help="Print report to stdout instead of saving files")
    parser.add_argument("--severity", "-s", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default=None, help="Minimum severity to report")
    parser.add_argument("--version", action="version", version="clarity-shield 1.2.0")

    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: '{args.target}' not found")
        sys.exit(1)

    contracts = collect_contracts(target, args.recursive)
    if not contracts:
        print(f"Error: No .clar files found in '{args.target}'")
        sys.exit(1)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = severity_order.index(args.severity) if args.severity else len(severity_order) - 1

    all_findings = {}
    total = 0
    worst_severity = None

    for contract_path in contracts:
        scanner = ClarityScanner(str(contract_path))
        findings = scanner.scan()

        # Filter by severity
        findings = [f for f in findings if severity_order.index(f.severity) <= min_idx]
        all_findings[scanner.contract_name] = findings
        total += len(findings)

        for f in findings:
            idx = severity_order.index(f.severity)
            if worst_severity is None or idx < severity_order.index(worst_severity):
                worst_severity = f.severity

        if args.format != "sarif":
            report = generate_report(findings, scanner.contract_name, args.format)
            if args.no_save:
                print(report)
            else:
                output_dir = Path('findings')
                output_dir.mkdir(exist_ok=True)
                ext = 'json' if args.format == 'json' else 'md'
                output_file = output_dir / f"{scanner.contract_name}_report.{ext}"
                with open(output_file, 'w') as fh:
                    fh.write(report)
                print(f"[+] Report saved to: {output_file}")

    if args.format == "sarif":
        sarif_output = generate_sarif(all_findings)
        if args.no_save:
            print(sarif_output)
        else:
            output_dir = Path('findings')
            output_dir.mkdir(exist_ok=True)
            output_file = output_dir / "clarity-shield.sarif"
            with open(output_file, 'w') as fh:
                fh.write(sarif_output)
            print(f"\n[+] SARIF report saved to: {output_file}")

    print(f"\n[+] Total: {total} findings across {len(contracts)} contract(s)")

    # Exit code based on severity
    if worst_severity == "CRITICAL":
        sys.exit(2)
    elif worst_severity == "HIGH":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
