# Clarity Shield Demo Guide

This guide is the step-by-step flow for a hackathon demo of `clarity-shield`.

## 1. Setup
Run from repo root:

```bash
cd /path/to/clarity-shield
chmod +x clarity-shield demo.sh
```

Optional quick sanity check:

```bash
./clarity-shield --version
```

## 2. Fast Demo (Recommended for Recording)
Use the scripted flow:

```bash
./demo.sh
```

No-delay variant:

```bash
./demo.sh --fast
```

What this script does:
1. Scans `test-contracts/vulnerable-token.clar` (expected critical findings, non-zero exit)
2. Scans `test-contracts/safe-token.clar` (expected zero findings, exit `0`)
3. Scans `test-contracts/ --recursive` (project-wide summary and report generation)

## 3. Manual Live Demo Flow
Use this if you want to narrate each command yourself.

### Step A: Show the problem contract
Explain that Clarity currently has no dedicated automated vulnerability scanner and teams often rely on manual review.

```bash
./clarity-shield scan test-contracts/vulnerable-token.clar
```

Expected highlights:
- Findings are detected
- `Critical` and `High` counts are shown
- Exit code is `2` when critical issues exist

### Step B: Show a safe contract

```bash
./clarity-shield scan test-contracts/safe-token.clar
```

Expected highlights:
- `Total Findings: 0`
- "No critical or high severity issues found"
- Exit code `0`

### Step C: Show ecosystem-level scan

```bash
./clarity-shield scan test-contracts/ --recursive
```

Expected highlights:
- Multiple contracts scanned in one run
- Aggregated severity summary
- Per-contract reports written to `findings/*_report.md`

## 4. Talking Points During Demo
Use these short lines while commands run:

1. "Problem: Clarity has zero dedicated automated security tooling."
2. "Solution: Clarity Shield is the first automated vulnerability scanner for Clarity."
3. "The CLI is CI-ready through deterministic exit codes: critical=2, high=1, clean=0."
4. "We can scan one file for focused debugging or whole repos for release readiness."

## 5. Troubleshooting
If command fails unexpectedly:

```bash
# Ensure executable permissions
chmod +x clarity-shield

# Confirm test contracts exist
ls test-contracts/*.clar

# Re-run in fast mode for deterministic script output
./demo.sh --fast
```
