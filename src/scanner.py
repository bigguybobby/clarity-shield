#!/usr/bin/env python3
"""
Clarity Shield - Smart Contract Security Scanner for Stacks Blockchain
Detects common vulnerabilities in Clarity smart contracts
"""

import re
import json
import sys
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from pathlib import Path
from enum import Enum


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
    
    def check_tx_sender_vs_contract_caller(self):
        """Detect authorization bypass via contract-caller misuse"""
        pattern = r'contract-caller.*(?:admin|owner|authorized)'
        
        for i, line in enumerate(self.lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
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
        in_public_function = False
        func_name = ""
        func_start_line = 0
        func_lines = []
        
        for i, line in enumerate(self.lines, 1):
            # Detect public function start
            public_match = re.search(r'\(define-public\s+\(([^\s)]+)', line)
            if public_match:
                in_public_function = True
                func_name = public_match.group(1)
                func_start_line = i
                func_lines = [line]
                continue
            
            if in_public_function:
                func_lines.append(line)
                
                # Check for closing parenthesis at function level
                if line.strip().startswith(')') and len(func_lines) > 3:
                    # Analyze complete function
                    func_body = '\n'.join(func_lines)
                    
                    # Skip if function name suggests it's meant to be public
                    skip_names = ['transfer', 'mint', 'burn', 'deposit', 'withdraw']
                    if any(name in func_name.lower() for name in skip_names):
                        # Check if has ANY authorization
                        has_auth = any(keyword in func_body for keyword in [
                            'tx-sender', 'asserts!', 'is-eq', 'owner', 'admin'
                        ])
                        
                        if not has_auth:
                            self.add_finding(
                                Severity.HIGH,
                                f"Missing Authorization Check in Public Function '{func_name}'",
                                f"The public function '{func_name}' performs state changes but "
                                "lacks authorization checks. Any caller can execute this function.",
                                func_start_line,
                                func_lines[0],
                                "Add authorization checks using 'tx-sender' validation: "
                                "(asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)",
                                "Access Control"
                            )
                    
                    in_public_function = False
                    func_lines = []
    
    def check_data_map_validation(self):
        """Check for unsafe data map access"""
        for i, line in enumerate(self.lines, 1):
            # Check map-set without validation
            if 'map-set' in line:
                context_start = max(0, i-5)
                context = '\n'.join(self.lines[context_start:i])
                
                has_validation = any(keyword in context for keyword in [
                    'asserts!', 'is-eq', 'map-get?', 'default-to'
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
            if re.search(r'map-get\?\s+\w+', line):
                context_end = min(len(self.lines), i+2)
                context = '\n'.join(self.lines[i-1:context_end])
                
                has_default = 'default-to' in context or 'match' in context
                
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
        for i, line in enumerate(self.lines, 1):
            # Check contract-call? usage
            if 'contract-call?' in line:
                context_end = min(len(self.lines), i+3)
                context = '\n'.join(self.lines[i-1:context_end])
                
                has_response_handling = any(keyword in context for keyword in [
                    'try!', 'match', 'unwrap!', 'is-ok', 'is-err'
                ])
                
                if not has_response_handling:
                    self.add_finding(
                        Severity.MEDIUM,
                        "Unhandled Response from Contract Call",
                        "Contract calls return response types that must be handled. "
                        "Ignoring response can lead to silent failures.",
                        i,
                        line,
                        "Handle the response using 'try!' to propagate errors or 'match' "
                        "to handle success/failure explicitly.",
                        "Error Handling"
                    )


def generate_report(findings: List[Finding], contract_name: str, 
                   output_format: str = 'json') -> str:
    """Generate security report in JSON or Markdown format"""
    
    if output_format == 'json':
        report = {
            "contract": contract_name,
            "scan_date": "2026-02-25",
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
**Scan Date:** 2026-02-25  
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
