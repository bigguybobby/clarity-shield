# Clarity Shield — WORKING.md

## Status: Active Development
**Version:** 2.23.0 | **Detectors:** 93 | **Tests:** 277 (all passing)
**Deadline:** March 20, 2026 (Stacks BUIDL Battle, $20K prizes)

## Latest Changes (2026-03-18, 22:00)
- ✅ Added Unsafe at-block Usage detector (#93)
- Detects public functions using (at-block) with caller-supplied block hashes
  without validation — attackers can read stale state, bypass checks, or
  manipulate time-dependent logic (vesting, voting snapshots, price feeds)
- Safe patterns recognized: var-get trusted hash, block-height validation,
  read-only functions, private functions
- MEDIUM severity, State Safety category
- New test contract: at-block-test.clar (2 vulnerable + 5 safe/non-relevant)
- 10 new tests in tests/test_at_block.py
- Updated DETECTOR_SPECS: 92 → 93 detectors
- Test suite: 267 → 277 tests, all passing

## Previous (2026-03-18, 14:00)
- Added Unvalidated Oracle Price Update detector (#92)
- 9 tests, oracle-update-test.clar
