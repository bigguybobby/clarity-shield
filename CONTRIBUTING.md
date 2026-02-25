# Contributing to Clarity Shield

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Provide minimal reproduction case
3. Include Clarity Shield version and Python version
4. Share expected vs actual behavior

### Suggesting Enhancements

1. Search existing feature requests
2. Explain the use case
3. Provide example contracts that would benefit

### Adding New Detectors

To add a new vulnerability detector:

1. **Create Detection Method**:

```python
def check_your_vulnerability(self):
    """Detect [vulnerability description]"""
    pattern = r'your_regex_pattern'
    
    for i, line in enumerate(self.lines, 1):
        if re.search(pattern, line):
            self.add_finding(
                Severity.MEDIUM,
                "Vulnerability Title",
                "Detailed description of what's wrong",
                i,
                line,
                "How to fix it",
                "Category"
            )
```

2. **Register in scan() method**:

```python
def scan(self):
    # ... existing detectors
    self.check_your_vulnerability()
    return self.findings
```

3. **Add Test Contract**:

Create `test-contracts/test-your-vuln.clar` with vulnerable example.

4. **Update Documentation**:
   - Add to `docs/VULNERABILITY-GUIDE.md`
   - Update `README.md` features list

5. **Submit Pull Request**

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/clarity-shield.git
cd clarity-shield

# Make executable
chmod +x clarity-shield

# Run tests
./clarity-shield scan test-contracts/ --recursive
```

### Code Style

- Follow PEP 8
- Use type hints where helpful
- Add docstrings to functions
- Keep functions focused and testable

### Testing

Before submitting PR:

1. Test against all contracts in `test-contracts/`
2. Ensure no regression (run existing tests)
3. Add new test case for your detector

### Pull Request Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-detector`)
3. Commit changes (`git commit -am 'Add XYZ detector'`)
4. Push to branch (`git push origin feature/new-detector`)
5. Open Pull Request

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Added tests for new functionality
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Commit messages are clear

## Recognition

Contributors will be listed in:
- README.md Contributors section
- GitHub contributors graph
- Release notes for their additions

## Questions?

Open an issue with the `question` label.

---

**Thank you for making Clarity Shield better! 🛡️**
