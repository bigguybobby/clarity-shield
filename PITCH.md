# Clarity Shield 3-Minute Pitch Script

## 0:00-0:30 | Problem
Clarity has zero dedicated automated security tooling.

If you build on Solidity, you have Slither and a mature scanner ecosystem. In Clarity, developers still rely on manual review, ad hoc scripts, and luck. That creates a real risk: authorization mistakes, unsafe error handling, and logic bugs can survive all the way to deployment.

For a growing ecosystem like Stacks, that slows teams down and increases the chance of expensive incidents.

## 0:30-1:10 | Solution
Clarity Shield is the first automated vulnerability scanner focused on Clarity smart contracts.

It is a developer-friendly CLI:
- Scan one contract or an entire directory
- Detect multiple vulnerability classes automatically
- Return machine-readable and human-readable reports
- Use CI-friendly exit codes to fail builds on critical issues

In short: we turn security checks from a manual bottleneck into a repeatable engineering step.

## 1:10-2:20 | Demo Walkthrough
Now I will run the scanner against real test contracts.

First, a known vulnerable token contract:

```bash
./clarity-shield scan test-contracts/vulnerable-token.clar
```

You can see Clarity Shield flag critical and high-severity findings, then exit with code `2` for critical risk.

Next, a safe reference contract:

```bash
./clarity-shield scan test-contracts/safe-token.clar
```

This one returns zero findings and exits cleanly.

Finally, the full contract suite:

```bash
./clarity-shield scan test-contracts/ --recursive
```

This shows the bigger picture: Clarity Shield scales from single-file checks to project-wide analysis, with report files generated automatically for each contract.

If you want a polished terminal flow for recording, run:

```bash
./demo.sh
```

## 2:20-3:00 | Impact on the Stacks Ecosystem
Clarity Shield gives Stacks builders a security baseline they do not have today.

It helps teams:
- Catch vulnerabilities earlier in development
- Standardize security checks in CI/CD
- Reduce audit preparation time
- Ship safer contracts with more confidence

The impact is ecosystem-wide: better tooling means better developer velocity, safer apps, and more trust in Stacks smart contracts.

Clarity Shield is not just a hackathon demo. It is foundational security infrastructure for the next wave of Clarity builders.
