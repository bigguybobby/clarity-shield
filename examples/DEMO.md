# 🛡️ Clarity Shield - Live Demo

This document provides a step-by-step demo of Clarity Shield in action.

## 🎯 Scenario: Auditing a Token Contract

### Step 1: The Vulnerable Contract

Let's examine a token contract with security issues:

```clarity
;; vulnerable-token.clar
(define-fungible-token vulnerable-token)

(define-data-var contract-owner principal 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)

;; ❌ VULNERABILITY: No authorization check!
(define-public (mint (amount uint) (recipient principal))
  (ft-mint? vulnerable-token amount recipient))

;; ❌ VULNERABILITY: Using contract-caller instead of tx-sender
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq contract-caller (var-get contract-owner)) (err u403))
    (ok (var-set contract-owner new-owner))))

;; ❌ VULNERABILITY: unwrap-panic can cause DoS
(define-public (burn (amount uint))
  (begin
    (unwrap-panic (ft-burn? vulnerable-token amount tx-sender))
    (ok true)))
```

### Step 2: Run Clarity Shield

```bash
$ ./clarity-shield scan test-contracts/vulnerable-token.clar

🛡️  Clarity Shield v1.0.0
📂 Found 1 contract(s) to scan

============================================================
[*] Scanning vulnerable-token...
[+] Found 5 potential issues
📄 Report: findings/vulnerable-token_report.md

============================================================

📊 SCAN SUMMARY
Total Contracts: 1
Total Findings: 5
🔴 Critical: 1
🟠 High: 2

⚠️  CRITICAL ISSUES FOUND - Review immediately!
```

### Step 3: Review the Report

```markdown
# 🛡️ Clarity Shield Security Report

**Contract:** `vulnerable-token`
**Total Findings:** 5

## 🔴 Finding #1: Authorization Bypass Risk

**Line:** 19

### Description
Using 'contract-caller' for authorization allows any intermediate contract 
to impersonate the caller. An attacker can deploy a malicious contract 
that calls this function, bypassing access controls.

### Code Snippet
```clarity
(asserts! (is-eq contract-caller (var-get contract-owner)) (err u403))
```

### Recommendation
Use 'tx-sender' for authorization checks instead of 'contract-caller'.
```

### Step 4: Understanding the Attack

**The Vulnerability**:
```clarity
;; Victim contract uses contract-caller
(define-public (set-owner (new-owner principal))
  (asserts! (is-eq contract-caller OWNER) (err u403))
  (ok (var-set owner new-owner)))
```

**The Attack**:
```clarity
;; Attacker deploys malicious contract
(define-public (exploit-victim)
  ;; This call will pass because contract-caller is attacker's contract!
  (contract-call? .victim-contract set-owner tx-sender))
```

**The Fix**:
```clarity
;; Use tx-sender instead
(define-public (set-owner (new-owner principal))
  (asserts! (is-eq tx-sender OWNER) (err u403))
  (ok (var-set owner new-owner)))
```

---

## 🎯 Scenario: Comparing Vulnerable vs Secure Code

### Vulnerable Token
```bash
$ ./clarity-shield scan test-contracts/vulnerable-token.clar

Total Findings: 5
🔴 Critical: 1
🟠 High: 2
🟡 Medium: 1
```

**Issues Found**:
- Authorization bypass via contract-caller
- Missing authorization on mint
- Unsafe unwrap-panic
- Unhandled contract call response
- Hardcoded principal

### Secure Token
```bash
$ ./clarity-shield scan test-contracts/safe-token.clar

Total Findings: 0
✅ No critical or high severity issues found
```

**Security Features**:
- ✅ Uses tx-sender for authorization
- ✅ Proper error handling with match
- ✅ Uses try! for response propagation
- ✅ default-to for optional handling
- ✅ No hardcoded addresses

---

## 🚀 CI/CD Integration Demo

### GitHub Actions Workflow

```yaml
name: Clarity Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Clarity Shield
        run: |
          ./clarity-shield scan ./contracts/ --recursive
```

### Output in CI

```
Run ./clarity-shield scan ./contracts/ --recursive
🛡️  Clarity Shield v1.0.0
📂 Found 3 contract(s) to scan

[*] Scanning token-contract...
[+] Found 2 potential issues

🔴 Critical: 1
🟠 High: 1

Error: Process completed with exit code 2.
```

**Result**: CI fails, preventing vulnerable code from being merged! 🛡️

---

## 📊 Batch Scanning Demo

Scan an entire project:

```bash
$ ./clarity-shield scan ./contracts/ --recursive

🛡️  Clarity Shield v1.0.0
📂 Found 4 contract(s) to scan

============================================================
[*] Scanning token.clar...
[+] Found 3 potential issues

============================================================
[*] Scanning vault.clar...
[+] Found 5 potential issues

============================================================
[*] Scanning nft-marketplace.clar...
[+] Found 7 potential issues

============================================================
[*] Scanning governance.clar...
[+] Found 0 potential issues

============================================================

📊 SCAN SUMMARY
Total Contracts: 4
Total Findings: 15
🔴 Critical: 3
🟠 High: 4
🟡 Medium: 6
🔵 Low: 2
```

---

## 🎨 JSON Output for Automation

```bash
$ ./clarity-shield scan contract.clar --format json

{
  "contract": "vulnerable-token",
  "scan_date": "2026-02-25",
  "total_findings": 5,
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 1
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "title": "Authorization Bypass Risk",
      "description": "Using 'contract-caller' for authorization...",
      "line": 19,
      "code_snippet": "(asserts! (is-eq contract-caller ...))",
      "recommendation": "Use 'tx-sender' instead...",
      "category": "Authorization"
    }
  ]
}
```

**Use Cases**:
- Parse findings programmatically
- Feed into bug tracking systems
- Dashboard visualization
- Metrics aggregation

---

## 🔬 Advanced: Understanding Each Detector

### 1. Authorization Detector

**Pattern**: `contract-caller` + `admin|owner|authorized`

```clarity
❌ (asserts! (is-eq contract-caller admin) ...)
✅ (asserts! (is-eq tx-sender admin) ...)
```

### 2. Missing Auth Detector

**Pattern**: `define-public` + state changes + no `tx-sender` check

```clarity
❌ (define-public (mint ...) (ft-mint? ...))
✅ (define-public (mint ...) 
     (begin
       (asserts! (is-eq tx-sender owner) ...)
       (ft-mint? ...)))
```

### 3. Unwrap Detector

**Pattern**: `unwrap-panic` or `unwrap!`

```clarity
❌ (unwrap-panic (stx-transfer? ...))
✅ (try! (stx-transfer? ...))
```

### 4. Arithmetic Detector

**Pattern**: `+`, `-`, `*` on `uint` without bounds check

```clarity
❌ (let ((sum (+ a b))) ...)
✅ (let ((sum (+ a b)))
     (asserts! (<= sum u128-max) ...)
     ...)
```

---

## 🎓 Learning Path

### For Beginners
1. Run Clarity Shield on example contracts
2. Read the vulnerability guide
3. Compare vulnerable vs secure implementations
4. Fix one issue at a time

### For Experienced Developers
1. Integrate into CI/CD pipeline
2. Customize severity thresholds
3. Contribute new detectors
4. Use JSON output for automation

---

## 💡 Pro Tips

### Reduce False Positives
```bash
# Use safe-token.clar as reference
./clarity-shield scan test-contracts/safe-token.clar
# Should report 0 findings
```

### Focus on Critical Issues First
```bash
# Exit codes: 2 = critical, 1 = high, 0 = clean
./clarity-shield scan contract.clar
echo $?  # Check exit code
```

### Generate Both Reports
```bash
# Markdown for reading
./clarity-shield scan contract.clar --format markdown

# JSON for automation
./clarity-shield scan contract.clar --format json
```

---

## 🏆 Best Practices

1. **Run Early, Run Often**: Scan during development, not just before deployment
2. **Automate in CI**: Fail builds on critical issues
3. **Review All Findings**: Even INFO-level issues can be relevant
4. **Combine with Manual Review**: Automated tools complement, not replace, human auditors
5. **Keep Learning**: Read the vulnerability guide to understand WHY issues matter

---

## 🎬 End of Demo

**Questions to explore**:
- What happens if I ignore a finding?
- Can I customize which checks to run?
- How do I add my own detectors?
- What's the performance on large codebases?

See `CONTRIBUTING.md` and `docs/ARCHITECTURE.md` for answers!

---

**Built with ❤️ for the Stacks community**

🛡️ Security is not a feature, it's a foundation.
