# 🛡️ Clarity Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Stacks](https://img.shields.io/badge/Stacks-Blockchain-5546FF)](https://www.stacks.co/)

**Automated security scanner for Clarity smart contracts on the Stacks blockchain**

Clarity Shield is a static analysis tool that detects common vulnerabilities in Clarity smart contracts, helping developers build more secure applications on Stacks.

## 🎯 Why Clarity Shield?

While Clarity's decidable and non-Turing-complete design provides inherent safety guarantees, developers can still introduce security vulnerabilities through:
- Authorization logic errors
- Improper error handling
- Unsafe arithmetic operations
- Data validation gaps

**Clarity Shield fills the security tooling gap in the Stacks ecosystem** by providing automated vulnerability detection that leverages Clarity's unique language properties.

## ✨ Features

- 🔍 **12 Vulnerability Detectors**:
  - Authorization bypass via `contract-caller` misuse
  - Missing access control checks on public functions
  - Unsafe `unwrap!` / `unwrap-panic` usage (DoS vectors)
  - Unchecked arithmetic (integer overflow/underflow)
  - Data map validation issues
  - Unhandled response types from contract calls
  - Hardcoded principals (centralization risks)
  - Missing post-condition documentation on transfers
  - Unbounded STX transfers from contract balance (fund drain)
  - Block-height dependency in time-sensitive logic
  - State-changing calls in read-only functions
  - Dynamic dispatch via unsafe trait parameters

- 📊 **Multiple Output Formats**: JSON and Markdown reports with severity ratings
- 🚀 **CI/CD Integration**: GitHub Actions workflow included
- 🎨 **Clear Severity Ratings**: CRITICAL → INFO with actionable recommendations
- ⚡ **Fast**: Pure Python implementation with regex-based pattern matching
- 📝 **Detailed Reports**: Line numbers, code snippets, and fix recommendations

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/clarity-shield.git
cd clarity-shield
chmod +x clarity-shield
```

**Requirements**: Python 3.8+

### Basic Usage

```bash
# Scan a single contract
./clarity-shield scan contract.clar

# Scan with JSON output
./clarity-shield scan contract.clar --format json

# Scan entire directory
./clarity-shield scan ./contracts/ --recursive

# Save to specific file
./clarity-shield scan contract.clar --output report.md
```

### Example Output

```markdown
# 🛡️ Clarity Shield Security Report

**Contract:** `vulnerable-token`
**Total Findings:** 5

## Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 1 |

---

## 🔴 Finding #1: Authorization Bypass Risk

**Severity:** CRITICAL
**Line:** 15

### Description
Using 'contract-caller' for authorization allows any intermediate contract to 
impersonate the caller. An attacker can deploy a malicious contract that calls 
this function, bypassing access controls.

### Code Snippet
```clarity
(asserts! (is-eq contract-caller (var-get contract-owner)) (err u403))
```

### Recommendation
Use 'tx-sender' for authorization checks instead of 'contract-caller'. Only use 
'contract-caller' when you explicitly need to authorize the immediate calling contract.
```

## 🔬 Vulnerability Detection

### 1. Authorization Bypass (CRITICAL)

**Pattern**: Using `contract-caller` for access control

```clarity
;; ❌ VULNERABLE
(asserts! (is-eq contract-caller admin) (err u403))

;; ✅ SECURE
(asserts! (is-eq tx-sender admin) (err u403))
```

**Why it matters**: An attacker can deploy a malicious intermediate contract that becomes the `contract-caller`, bypassing your authorization checks.

### 2. Missing Authorization (HIGH)

**Pattern**: Public functions with state changes but no access control

```clarity
;; ❌ VULNERABLE
(define-public (mint (amount uint) (recipient principal))
  (ft-mint? token amount recipient))

;; ✅ SECURE
(define-public (mint (amount uint) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) ERR_UNAUTHORIZED)
    (ft-mint? token amount recipient)))
```

### 3. Unsafe Unwrap (HIGH)

**Pattern**: Using `unwrap-panic` or `unwrap!` without error handling

```clarity
;; ❌ VULNERABLE (DoS vector)
(unwrap-panic (stx-transfer? amount tx-sender recipient))

;; ✅ SECURE
(match (stx-transfer? amount tx-sender recipient)
  success (ok success)
  error (err error))
```

**Impact**: Transaction aborts can be exploited for denial-of-service attacks.

### 4. Unchecked Arithmetic (MEDIUM)

**Pattern**: Arithmetic operations on `uint` without bounds checking

```clarity
;; ❌ VULNERABLE
(let ((new-balance (+ balance amount)))
  ...)

;; ✅ SECURE
(let ((new-balance (+ balance amount)))
  (asserts! (<= new-balance u340282366920938463463374607431768211455) ERR_OVERFLOW)
  ...)
```

### 5. Data Map Validation (MEDIUM)

**Pattern**: Setting map values without validation

```clarity
;; ❌ VULNERABLE
(map-set balances user new-amount)

;; ✅ SECURE
(let ((current (default-to u0 (map-get? balances user))))
  (asserts! (>= current amount) ERR_INSUFFICIENT_BALANCE)
  (map-set balances user (- current amount)))
```

### 6. Unhandled Responses (MEDIUM)

**Pattern**: Contract calls without response handling

```clarity
;; ❌ VULNERABLE
(contract-call? .external-contract function)

;; ✅ SECURE
(try! (contract-call? .external-contract function))
```

### 7. Hardcoded Principals (INFO)

**Pattern**: Hardcoded addresses in authorization logic

```clarity
;; ⚠️  CENTRALIZATION RISK
(define-constant ADMIN 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)

;; ✅ BETTER
(define-data-var admin principal tx-sender)
```

## 🔗 CI/CD Integration

### GitHub Actions

Create `.github/workflows/clarity-security.yml`:

```yaml
name: Clarity Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Run Clarity Shield
        run: |
          chmod +x clarity-shield
          ./clarity-shield scan ./contracts/ --recursive --format json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: findings/
```

## 📚 Methodology

Clarity Shield uses a **MAP-HUNT-ATTACK** inspired approach:

1. **MAP**: Parse contract structure (public functions, data maps, contract calls)
2. **HUNT**: Pattern matching for known vulnerability signatures
3. **REPORT**: Generate actionable findings with severity ratings

This methodology is adapted from proven Solidity auditing techniques, tailored for Clarity's unique language properties.

## 🧪 Test Contracts

The `test-contracts/` directory contains example vulnerable contracts:

- `vulnerable-token.clar` - Token with authorization and error handling issues
- `vulnerable-vault.clar` - Vault with unsafe arithmetic and map access
- `vulnerable-nft.clar` - NFT marketplace with validation gaps
- `safe-token.clar` - Example of properly secured contract

Run against test contracts:

```bash
./clarity-shield scan test-contracts/ --recursive
```

## 📖 Documentation

- [Clarity Language Book](https://book.clarity-lang.org/)
- [Stacks Documentation](https://docs.stacks.co/)
- [Clarity Reference](https://github.com/clarity-lang/reference)

## 🎯 Limitations

- **Static Analysis Only**: Cannot detect complex logic bugs requiring runtime analysis
- **Pattern-Based**: May produce false positives on non-standard code patterns
- **No Formal Verification**: Not a substitute for professional security audits
- **Best Effort**: New vulnerability patterns may not be detected

**Always conduct professional security audits for production contracts.**

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional vulnerability detectors
- False positive reduction
- Integration with Clarinet
- VSCode extension
- Web-based UI

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 🏆 Hackathon

Built for **Stacks BUIDL Battle #2** (March 2-20, 2026)

Clarity Shield addresses the critical gap in security tooling for the Stacks ecosystem, making it easier for developers to build secure decentralized applications.

## 🔗 Links

- [Stacks Blockchain](https://www.stacks.co/)
- [Clarity Language](https://clarity-lang.org/)
- [Hiro Platform](https://www.hiro.so/)

---

**Built with ❤️ for the Stacks community**

*Security is not a feature, it's a foundation.*
