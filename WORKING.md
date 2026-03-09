# Clarity Shield — WORKING.md

## Status: Active Development
**Version:** 2.3.1 | **Detectors:** 70 | **Tests:** 20 (all passing)
**Deadline:** March 20, 2026 (Stacks BUIDL Battle, $20K prizes)

## Latest Changes (2026-03-08)
- ✅ Fixed look-ahead bleed across function boundaries in detectors #29 and #34
  - `check_unprotected_mint` and `check_unprotected_burn` now use `_iter_function_blocks()`
  - Previously: 15-line raw look-ahead could see auth checks in adjacent functions → false negatives
  - Now: context is strictly bounded by paren-balanced function boundaries
  - Added `test-contracts/bleed-test.clar` regression contract
  - Added 3 new tests: TestLookAheadBleedFix (mint detected, burn detected, protected not flagged)
  - Test suite: 17 → 20 tests, all passing
- ⚠️ PENDING GIT COMMIT — Xcode license not accepted, `git` blocked. Need `sudo xcodebuild -license accept`

## Previous Changes (2026-03-02)
- ✅ Added pytest test suite: 17 tests covering core scanner, 5 individual detectors, output formats, repo contracts
- ✅ Fixed false positive in `check_unprotected_mint` (#29) and `check_unprotected_burn` (#34)
  - Now recognises indirect auth guards: `is-owner`, `is-admin`, `is-authorized`, `is-protocol`, `is-minter`
  - safe-token.clar: reduced from 10 → 9 findings (eliminated false "Unprotected Mint")

## Known Issues
- ⚠️ Xcode license not accepted — git commands fail. Run: `sudo xcodebuild -license accept`
- Scanner prints `[*]` status lines to stdout mixed with JSON output (cosmetic)
- safe-token still gets 9 findings (some are INFO/LOW style suggestions, not bugs)

## Architecture
- Single-file scanner: `src/scanner.py` (~2795 lines)
- 70 detectors registered in `DETECTOR_SPECS` list
- Config: TOML/YAML support with per-detector enable/disable
- Output: JSON, Markdown, HTML, SARIF
- Test contracts: 18 files in `test-contracts/`

## Next Improvements (Priority)
1. ~~Fix look-ahead bleeding across function boundaries in detectors 29/34~~ ✅ DONE
2. Add SARIF output test
3. Add GitHub Actions CI workflow
4. More detector-specific regression tests
5. README badges (tests passing, version, license)
