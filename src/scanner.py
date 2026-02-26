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


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <contract.clar> [--format json|markdown]")
        sys.exit(1)
    
    contract_path = sys.argv[1]
    output_format = 'markdown'
    
    if '--format' in sys.argv:
        idx = sys.argv.index('--format')
        if idx + 1 < len(sys.argv):
            output_format = sys.argv[idx + 1]
    
    if not Path(contract_path).exists():
        print(f"Error: Contract file '{contract_path}' not found")
        sys.exit(1)
    
    # Run scan
    scanner = ClarityScanner(contract_path)
    findings = scanner.scan()
    
    # Generate report
    report = generate_report(findings, scanner.contract_name, output_format)
    
    # Output report
    output_dir = Path('findings')
    output_dir.mkdir(exist_ok=True)
    
    ext = 'json' if output_format == 'json' else 'md'
    output_file = output_dir / f"{scanner.contract_name}_report.{ext}"
    
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"\n[+] Report saved to: {output_file}")
    print(f"[+] Summary: {len(findings)} findings")
    
    # Exit code based on severity
    has_critical = any(f.severity == "CRITICAL" for f in findings)
    has_high = any(f.severity == "HIGH" for f in findings)
    
    if has_critical:
        sys.exit(2)
    elif has_high:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
