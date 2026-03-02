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

- 🔍 **65 Vulnerability Detectors**:
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

  - Unprotected mint functions (unlimited inflation) — CRITICAL
  - Unvalidated price oracle usage (manipulation risk) — HIGH  
  - Bypassable time-lock setters (withdrawal bypass) — HIGH

  - Unchecked cross-contract return values (silent failures) — HIGH
  - Redundant authorization checks (code quality) — INFO
  - Unprotected burn functions (asset destruction) — HIGH
  - Missing SIP-009 NFT standard compliance — MEDIUM
  - Unbounded `map-set` in public function (state bloat DoS) — HIGH
  - Missing SIP-010 `get-symbol` / `get-decimals` metadata methods — MEDIUM
  - Unsafe string concatenation without length checks — MEDIUM
  - Governance proposal execution without timelock — CRITICAL
  - Unvalidated trait parameter in public function — HIGH

- ⚙️ **Configurable Scans**: TOML/YAML config for detector enable/disable, severity defaults, and custom regex rules
- 📊 **Multiple Output Formats**: JSON, Markdown, HTML, and SARIF reports
- 🧾 **Summary Dashboard**: Compact per-contract severity table via `--summary`
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

**Requirements**: Python 3.8+ (zero dependencies)

```bash
# Or install via pip
pip install -e .
```

### Basic Usage

```bash
# Scan a single contract
./clarity-shield scan contract.clar

# Scan with JSON output
./clarity-shield scan contract.clar --format json

# Scan with config file (TOML recommended)
python3 src/scanner.py contract.clar --config clarity-shield.toml

# Print compact summary dashboard
python3 src/scanner.py test-contracts/ --recursive --summary --no-save

# Scan entire directory
./clarity-shield scan ./contracts/ --recursive

# Save to specific file
./clarity-shield scan contract.clar --output report.md
```

### Config File

Clarity Shield supports `--config` with `.toml`, `.yaml`, or `.yml`.
TOML is recommended because Python 3.11+ includes `tomllib`.

```bash
python3 src/scanner.py test-contracts/ -r --config clarity-shield.toml
```

Sample config: `clarity-shield.toml`

```toml
[scanner]
default_severity = "LOW"
enable_detectors = [61, 62, 63, 64, 65]
disable_detectors = [6]

[severity_overrides]
"64" = "CRITICAL"

[[custom_rules]]
id = "CUST-001"
title = "Custom Policy Check"
severity = "LOW"
pattern = "\\(asserts!"
description = "Example custom rule."
recommendation = "Review assertions for policy compliance."
```

### Summary Dashboard

Use `--summary` to print a compact cross-contract severity dashboard:

```text
┌─────────────┬──────────┬──────┬────────┬─────┬──────┐
│ Contract    │ CRITICAL │ HIGH │ MEDIUM │ LOW │ INFO │
├─────────────┼──────────┼──────┼────────┼─────┼──────┤
│ my-token    │    0     │  3   │   5    │  2  │  1   │
└─────────────┴──────────┴──────┴────────┴─────┴──────┘
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
- `vulnerable-v4.clar` - Covers detectors #61-65 (config-era additions)
- `safe-token.clar` - Example of properly secured contract

Run against test contracts:

```bash
./clarity-shield scan test-contracts/ --recursive
```

## 🌍 Real-World Testing

On **February 26, 2026**, Clarity Shield was run against **10 real contracts** in `test-contracts/real/` sourced from active Stacks ecosystem repos:

- `stacks-sbtc/sbtc`
- `citycoins/contracts`
- `Zest-Protocol/zest-contracts`
- `BitflowFinance/bitflow`
- `alexgo-io/alex-v1`

Source paths and pinned upstream commit hashes are documented in `test-contracts/real/SOURCES.md`.

### Run Command

```bash
./clarity-shield scan test-contracts/real/ --recursive --format json
```

### Results Summary

| Contract | Findings | Critical | High | Medium | Low | Info |
|----------|----------|----------|------|--------|-----|------|
| `alex__exchange` | 2 | 0 | 1 | 0 | 1 | 0 |
| `bitflow__router-xyk-alex-v-1-3` | 24 | 0 | 9 | 0 | 0 | 15 |
| `bitflow__stableswap` | 18 | 0 | 0 | 13 | 4 | 1 |
| `citycoins__miamicoin-core-v2` | 51 | 0 | 0 | 12 | 25 | 14 |
| `citycoins__newyorkcitycoin-core-v2` | 51 | 0 | 0 | 12 | 25 | 14 |
| `stacks-sbtc__sbtc-deposit` | 2 | 0 | 0 | 2 | 0 | 0 |
| `stacks-sbtc__sbtc-token` | 1 | 0 | 0 | 1 | 0 | 0 |
| `stacks-sbtc__sbtc-withdrawal` | 3 | 0 | 1 | 1 | 1 | 0 |
| `zest__liquidation-manager` | 21 | 0 | 6 | 14 | 1 | 0 |
| `zest__pool-borrow` | 10 | 0 | 3 | 6 | 1 | 0 |
| **Total** | **183** | **0** | **20** | **61** | **58** | **44** |

### Notes

- Initial pass on this same corpus surfaced **302 findings** with **2 criticals**.
- After detector tuning for real-world patterns (balanced function parsing + false-positive reduction), results dropped to **183 findings** and **0 criticals**.
- Most remaining findings are advisory patterns (`unwrap-panic`, `map-get?` optional handling, hardcoded principals, and block-height assumptions), which still warrant manual review in production audits.

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
