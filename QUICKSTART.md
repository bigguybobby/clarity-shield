# 🚀 Quick Start Guide - Clarity Shield

Get started with Clarity Shield in under 2 minutes!

## Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd clarity-shield

# Make executable
chmod +x clarity-shield

# Verify installation
./clarity-shield --version
```

**Requirements**: Python 3.8+ (standard library only, no pip packages needed)

---

## Your First Scan

### Scan a Single Contract

```bash
./clarity-shield scan test-contracts/vulnerable-token.clar
```

**Output**:
```
🛡️  Clarity Shield v1.0.0
📂 Found 1 contract(s) to scan

============================================================
[*] Scanning vulnerable-token...
[+] Found 5 potential issues
📄 Report: findings/vulnerable-token_report.md

============================================================

📊 SCAN SUMMARY
Total Findings: 5
🔴 Critical: 1
🟠 High: 2

⚠️  CRITICAL ISSUES FOUND - Review immediately!
```

### View the Report

```bash
cat findings/vulnerable-token_report.md
```

---

## Scan Multiple Contracts

```bash
# Scan entire directory
./clarity-shield scan test-contracts/ --recursive
```

---

## Output Formats

### Markdown (Human-Readable)
```bash
./clarity-shield scan contract.clar --format markdown
```

### JSON (Machine-Readable)
```bash
./clarity-shield scan contract.clar --format json
```

---

## Try the Demo Contracts

### 1. Vulnerable Token
```bash
./clarity-shield scan test-contracts/vulnerable-token.clar
```
**Issues**: Authorization bypass, unsafe unwrap, hardcoded principal

### 2. Vulnerable Vault
```bash
./clarity-shield scan test-contracts/vulnerable-vault.clar
```
**Issues**: Arithmetic safety, data validation, auth issues

### 3. Vulnerable NFT Marketplace
```bash
./clarity-shield scan test-contracts/vulnerable-nft.clar
```
**Issues**: Missing access control, race conditions, validation gaps

### 4. Safe Token (Reference)
```bash
./clarity-shield scan test-contracts/safe-token.clar
```
**Result**: ✅ No issues found!

---

## Understanding Reports

### Severity Levels

| Icon | Severity | Meaning |
|------|----------|---------|
| 🔴 | CRITICAL | Exploitable vulnerability, immediate action required |
| 🟠 | HIGH | Serious issue, should be fixed before deployment |
| 🟡 | MEDIUM | Potential problem, review recommended |
| 🔵 | LOW | Minor issue, best practice violation |
| ⚪ | INFO | Informational, consider for improvements |

### Report Structure

Each finding includes:
- **Title**: Brief description
- **Severity**: Risk level
- **Category**: Vulnerability type
- **Line**: Source code line number
- **Code Snippet**: Vulnerable code
- **Description**: What's wrong and why it matters
- **Recommendation**: How to fix it

---

## CI/CD Integration (Optional)

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Clarity Shield
        run: |
          chmod +x clarity-shield
          ./clarity-shield scan ./contracts/ --recursive
```

**Result**: Builds fail if critical vulnerabilities are detected! 🛡️

---

## Common Use Cases

### 1. Pre-Deployment Check
```bash
./clarity-shield scan ./contracts/ --recursive
if [ $? -eq 0 ]; then
  echo "✅ Safe to deploy"
else
  echo "❌ Fix security issues first"
fi
```

### 2. PR Review
```bash
# Scan changed contracts only
git diff --name-only main | grep '.clar$' | xargs -I {} ./clarity-shield scan {}
```

### 3. Automated Reports
```bash
# Generate JSON for dashboards
./clarity-shield scan ./contracts/ --recursive --format json > security-report.json
```

---

## Exit Codes

Clarity Shield uses exit codes for automation:

- `0` - No critical or high severity issues
- `1` - High severity issues found
- `2` - Critical severity issues found

**Example**:
```bash
./clarity-shield scan contract.clar
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "🔴 CRITICAL issues - do not deploy!"
elif [ $EXIT_CODE -eq 1 ]; then
  echo "🟠 HIGH severity - review required"
else
  echo "✅ Clean scan"
fi
```

---

## Next Steps

### Learn More
- Read `README.md` for detailed documentation
- Check `docs/VULNERABILITY-GUIDE.md` for security best practices
- Review `docs/ARCHITECTURE.md` to understand how it works

### Extend Clarity Shield
- See `CONTRIBUTING.md` to add new detectors
- Fork the repo and customize for your needs

### Get Help
- Open an issue on GitHub
- Check existing documentation
- Review test contracts for examples

---

## Quick Reference

```bash
# Scan single file
./clarity-shield scan contract.clar

# Scan directory
./clarity-shield scan ./contracts/ --recursive

# JSON output
./clarity-shield scan contract.clar --format json

# Custom output location
./clarity-shield scan contract.clar --output report.md

# Check version
./clarity-shield --version
```

---

## What's Being Detected?

Clarity Shield checks for:

1. **Authorization Bypass** - `contract-caller` misuse
2. **Missing Access Control** - Public functions without auth
3. **Unsafe Unwrap** - DoS via `unwrap-panic`
4. **Arithmetic Issues** - Integer overflow/underflow
5. **Data Validation** - Unsafe map operations
6. **Response Handling** - Unhandled contract calls
7. **Centralization Risks** - Hardcoded principals

---

## Tips for Best Results

✅ **Scan early, scan often** - Run during development, not just before deployment

✅ **Review all findings** - Even low-severity issues can be important in context

✅ **Combine with manual review** - Automated tools complement, don't replace, human auditors

✅ **Keep contracts clean** - Fix issues as they're found, don't accumulate technical debt

✅ **Use in CI/CD** - Automated scanning prevents vulnerable code from being merged

---

## Troubleshooting

### "Command not found: clarity-shield"
```bash
chmod +x clarity-shield
./clarity-shield scan contract.clar
```

### "No .clar files found"
- Check file extension (must be `.clar`)
- Verify path is correct
- Use `--recursive` for subdirectories

### "Python version error"
- Requires Python 3.8+
- Check with: `python3 --version`

---

## That's It! 🎉

You're ready to start scanning Clarity contracts for security vulnerabilities.

**Happy auditing! 🛡️**

---

*For more details, see the full [README.md](README.md)*
