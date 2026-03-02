# Clarity Shield — WORKING.md

## Status: Active Development
**Version:** 2.3.0 | **Detectors:** 70 | **Tests:** 17 (all passing)
**Deadline:** March 20, 2026 (Stacks BUIDL Battle, $20K prizes)

## Latest Changes (2026-03-02)
- ✅ Added pytest test suite: 17 tests covering core scanner, 5 individual detectors, output formats, repo contracts
- ✅ Fixed false positive in `check_unprotected_mint` (#29) and `check_unprotected_burn` (#34)
  - Now recognises indirect auth guards: `is-owner`, `is-admin`, `is-authorized`, `is-protocol`, `is-minter`
  - safe-token.clar: reduced from 10 → 9 findings (eliminated false "Unprotected Mint")

## Known Issues
- 15-line look-ahead in mint/burn detectors can bleed into adjacent functions (pre-existing)
- Scanner prints `[*]` status lines to stdout mixed with JSON output (cosmetic)
- safe-token still gets 9 findings (some are INFO/LOW style suggestions, not bugs)

## Architecture
- Single-file scanner: `src/scanner.py` (2795 lines)
- 70 detectors registered in `DETECTOR_SPECS` list
- Config: TOML/YAML support with per-detector enable/disable
- Output: JSON, Markdown, HTML, SARIF
- Test contracts: 17 files in `test-contracts/`

## Next Improvements (Priority)
1. Fix look-ahead bleeding across function boundaries in detectors 29/34
2. Add SARIF output test
3. Add GitHub Actions CI workflow
4. More detector-specific regression tests
5. README badges (tests passing, version, license)
