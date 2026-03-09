# Clarity Shield — WORKING.md

## Status: Active Development
**Version:** 2.3.1 | **Detectors:** 70 | **Tests:** 47 (all passing)
**Deadline:** March 20, 2026 (Stacks BUIDL Battle, $20K prizes)

## Latest Changes (2026-03-09)
- ✅ Added 8 detector regression tests: reentrancy #13, arithmetic #3, auth #4, DoS #38
- New test-contracts/detector-regression.clar with positive + negative cases
- Test suite: 39 → 47 tests, all passing
- ✅ Added 13 CLI integration tests: --help, --version, error handling, JSON/SARIF/Markdown output, severity filter, exit codes, directory scan
- Test suite: 26 → 39 tests, all passing
- ✅ Committed pending look-ahead bleed fix (was blocked by Xcode license)
- ✅ Added 6 SARIF output tests: valid JSON, schema/version, tool info, results mapping, empty findings, severity mapping
- ✅ Added GitHub Actions CI workflow (`.github/workflows/ci.yml`) — runs pytest on Python 3.10/3.11/3.12 + CLI smoke test
- ✅ Added README badges: Tests CI status, Detectors count
- Test suite: 20 → 26 tests, all passing
- Git: Xcode license still not accepted — using `/Library/Developer/CommandLineTools/usr/bin/git` as workaround

## Previous Changes (2026-03-08)
- ✅ Fixed look-ahead bleed across function boundaries in detectors #29 and #34
  - `check_unprotected_mint` and `check_unprotected_burn` now use `_iter_function_blocks()`
  - Added `test-contracts/bleed-test.clar` regression contract + 3 tests

## Previous Changes (2026-03-02)
- ✅ Added pytest test suite: 17 tests covering core scanner, 5 individual detectors, output formats, repo contracts
- ✅ Fixed false positive in `check_unprotected_mint` (#29) and `check_unprotected_burn` (#34)

## Known Issues
- ⚠️ Xcode license not accepted — `/usr/bin/git` fails. Workaround: `/Library/Developer/CommandLineTools/usr/bin/git`. Need `sudo xcodebuild -license accept`
- Scanner prints `[*]` status lines to stdout mixed with JSON output (cosmetic)

## Architecture
- Single-file scanner: `src/scanner.py` (~2795 lines)
- 70 detectors registered in `DETECTOR_SPECS` list
- Config: TOML/YAML support with per-detector enable/disable
- Output: JSON, Markdown, HTML, SARIF
- Test contracts: 18 files in `test-contracts/`
- CI: GitHub Actions (pytest + CLI smoke test on 3 Python versions)

## Next Improvements (Priority)
1. ~~Fix look-ahead bleeding across function boundaries in detectors 29/34~~ ✅ DONE
2. ~~Add SARIF output test~~ ✅ DONE
3. ~~Add GitHub Actions CI workflow~~ ✅ DONE
4. ~~More detector-specific regression tests~~ ✅ DONE (reentrancy, arithmetic, auth, DoS)
5. ~~README badges~~ ✅ DONE
6. ~~Add CLI integration test (--help, --version flags)~~ ✅ DONE
7. Config file (TOML) test coverage
8. git push (needs Xcode license fix or GitHub token auth)
