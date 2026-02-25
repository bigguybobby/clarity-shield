# Clarity Shield Architecture

## Overview

Clarity Shield is designed as a modular, extensible static analysis framework for Clarity smart contracts.

## System Design

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Interface                        │
│                   (clarity-shield)                      │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  ClarityScanner     │
         │   (scanner.py)      │
         └─────────┬───────────┘
                   │
                   ├──→ check_tx_sender_vs_contract_caller()
                   ├──→ check_unwrap_usage()
                   ├──→ check_arithmetic_safety()
                   ├──→ check_public_function_auth()
                   ├──→ check_data_map_validation()
                   ├──→ check_hardcoded_principals()
                   └──→ check_response_handling()
                   │
                   ▼
         ┌─────────────────────┐
         │  Finding Collection │
         └─────────┬───────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  Report Generator   │
         │  (JSON/Markdown)    │
         └─────────────────────┘
```

## Core Components

### 1. ClarityScanner Class

**Responsibility**: Orchestrates all vulnerability checks

**Key Methods**:
- `scan()` - Main entry point, runs all detectors
- `add_finding()` - Records security issues
- Individual check methods for each vulnerability type

**Design Pattern**: Strategy pattern - each detector is an independent method

### 2. Detector Methods

Each detector follows a consistent pattern:

```python
def check_vulnerability_type(self):
    """Detect [vulnerability name]"""
    pattern = r'regex_pattern'
    
    for i, line in enumerate(self.lines, 1):
        if re.search(pattern, line):
            # Context analysis
            context = get_surrounding_lines(i)
            
            # Heuristics to reduce false positives
            if not has_mitigation(context):
                self.add_finding(
                    severity=Severity.HIGH,
                    title="Issue Title",
                    description="What the issue is",
                    line=i,
                    code_snippet=line,
                    recommendation="How to fix it",
                    category="Category"
                )
```

### 3. Finding Data Structure

```python
@dataclass
class Finding:
    severity: str        # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title: str           # Short description
    description: str     # Detailed explanation
    line: int            # Source line number
    code_snippet: str    # Vulnerable code
    recommendation: str  # Fix suggestion
    category: str        # Vulnerability category
```

### 4. Report Generator

Supports multiple output formats:
- **JSON**: Machine-readable, CI/CD integration
- **Markdown**: Human-readable, documentation

## Detection Methodology

### Pattern-Based Analysis

Clarity Shield uses regex-based pattern matching combined with contextual analysis:

1. **Pattern Matching**: Identify potential vulnerability signatures
2. **Context Analysis**: Examine surrounding code for mitigations
3. **Heuristic Filtering**: Reduce false positives
4. **Severity Assignment**: Rate based on exploitability and impact

### Example: Authorization Check Detection

```python
# 1. Pattern: Look for contract-caller in auth context
pattern = r'contract-caller.*(?:admin|owner|authorized)'

# 2. Context: Check if tx-sender is also used
has_tx_sender = 'tx-sender' in context

# 3. Heuristic: If both are present, might be intentional
if 'contract-caller' in line and not has_tx_sender:
    add_finding(Severity.CRITICAL, ...)
```

## Extensibility

### Adding New Detectors

1. Create new method in `ClarityScanner`:

```python
def check_new_vulnerability(self):
    """Detect [new vulnerability type]"""
    pattern = r'your_pattern'
    
    for i, line in enumerate(self.lines, 1):
        if re.search(pattern, line):
            self.add_finding(
                Severity.MEDIUM,
                "Vulnerability Title",
                "Description",
                i,
                line,
                "Recommendation",
                "Category"
            )
```

2. Call in `scan()` method:

```python
def scan(self):
    self.check_tx_sender_vs_contract_caller()
    # ... existing checks
    self.check_new_vulnerability()  # Add here
    return self.findings
```

### Adding Output Formats

Extend `generate_report()` function:

```python
elif output_format == 'html':
    return generate_html_report(findings, contract_name)
elif output_format == 'sarif':
    return generate_sarif_report(findings, contract_name)
```

## Performance Considerations

### Current Approach
- **O(n)** per detector where n = lines of code
- Regex compilation is done on-the-fly
- No AST parsing (intentional trade-off for simplicity)

### Optimization Opportunities
1. **Regex Compilation**: Pre-compile patterns
2. **Parallel Processing**: Run detectors concurrently
3. **AST Integration**: Use Clarinet's parser for deeper analysis
4. **Caching**: Cache scan results for unchanged files

## Future Enhancements

### Short-term (v1.1)
- [ ] Configurable severity thresholds
- [ ] Custom rule definitions (YAML)
- [ ] Ignore comments (e.g., `; clarity-shield-ignore`)
- [ ] HTML report generation

### Medium-term (v1.5)
- [ ] Integration with Clarinet LSP
- [ ] Call graph analysis for reentrancy
- [ ] Data flow tracking
- [ ] VSCode extension

### Long-term (v2.0)
- [ ] Symbolic execution
- [ ] Formal verification integration
- [ ] Machine learning for pattern detection
- [ ] Web-based dashboard

## Testing Strategy

### Unit Tests
- Test each detector in isolation
- Known vulnerable patterns should be detected
- Known safe patterns should not trigger

### Integration Tests
- Run against real Stacks contracts
- Compare with manual audit findings
- Measure false positive/negative rates

### Regression Tests
- Test against previous versions
- Ensure no degradation in detection

## Dependencies

**Runtime**:
- Python 3.8+ (standard library only, no external deps)

**Development**:
- pytest (testing)
- black (code formatting)
- mypy (type checking)

## Security Considerations

Clarity Shield itself should be secure:

1. **Input Validation**: Handle malformed .clar files gracefully
2. **Path Traversal**: Validate file paths in recursive mode
3. **Resource Limits**: Prevent DoS on very large contracts
4. **No Remote Execution**: Never execute or evaluate contract code

## Deployment

### Local Installation
```bash
git clone <repo>
cd clarity-shield
chmod +x clarity-shield
./clarity-shield scan contract.clar
```

### CI/CD Integration
See `.github/workflows/clarity-security.yml`

### Package Distribution (Future)
- PyPI package: `pip install clarity-shield`
- Homebrew tap: `brew install clarity-shield`
- Docker image: `docker run clarity-shield scan /contracts`

---

**Architecture Version**: 1.0  
**Last Updated**: 2026-02-25
