# Clarity Shield — WORKING.md

## Status: Active Development
**Version:** 2.8.0 | **Detectors:** 78 | **Tests:** 135 (all passing)
**Deadline:** March 20, 2026 (Stacks BUIDL Battle, $20K prizes)

## Latest Changes (2026-03-13, 14:00)
- ✅ Added Unvalidated Fee/Rate Parameter detector (#78)
- Detects public functions accepting fee/percent/rate/commission/royalty/bps
  parameters without upper-bound validation (asserts! with <= or < checks)
- Uncapped fee percentages can be set to 100% (or 10000 bps), draining all funds
- Recognizes safe patterns: asserts! (<= param max), asserts! (< param max)
- HIGH severity, Input Validation category
- New test contract: fee-param-test.clar (2 vulnerable + 3 safe functions)
- 8 new tests in tests/test_fee_parameter.py
- Test suite: 127 → 135 tests, all passing

## Previous Changes (2026-03-13, 06:00)
- ✅ Added Single-Step Privilege Transfer detector (#77)
- Detects public functions that transfer owner/admin/authority roles to arbitrary
  principals in a single transaction without two-step confirmation (propose + accept)
- Single-step transfers risk permanent lockout if new address is wrong (typo, wrong network)
- Per-variable two-step detection: skips vars with pending/propose/accept patterns
- Recognizes safe patterns: tx-sender self-set, existing two-step ownership flows
- HIGH severity, Access Control category
- New test contract: privilege-transfer-test.clar (2 vulnerable + 3 safe functions)
- 8 new tests in tests/test_privilege_transfer.py
- Test suite: 119 → 127 tests, all passing

## Previous Changes (2026-03-12, 22:00)
- ✅ Added Insecure Randomness Source detector (#76)
- Detects public functions using block-height/burn-block-height/stx-liquid-supply/get-block-info?
  combined with mod/hash operations (sha256, hash160, keccak256) for pseudo-randomness
- Miners can manipulate on-chain values to influence lottery/selection/NFT-mint outcomes
- Recognizes safe patterns: VRF, oracle, commit-reveal, chainlink, external-random
- Checks longer matches first (burn-block-height before block-height) to report accurately
- HIGH severity, Randomness category
- New test contract: insecure-randomness-test.clar (2 vulnerable + 3 safe functions)
- 8 new tests in tests/test_insecure_randomness.py
- Test suite: 111 → 119 tests, all passing

## Previous Changes (2026-03-12, 14:00)
- ✅ Added Missing Zero-Amount Validation detector (#75)
- Detects public functions accepting amount params used in stx-transfer?/ft-transfer?/ft-mint? without checking amount > 0
- Zero-amount transfers can be abused for event spam, reward map manipulation, and metric inflation
- Recognizes safe patterns: asserts! (> amount u0), (>= amount u1), if-checks
- MEDIUM severity, Input Validation category
- New test contract: zero-amount-test.clar (2 vulnerable + 3 safe functions)
- 8 new tests in tests/test_zero_amount.py
- Test suite: 103 → 111 tests, all passing

## Previous Changes (2026-03-12, 06:00)
- ✅ Added Unbounded Reward Emission detector (#74)
- Detects public reward/claim/harvest/airdrop/distribute functions that transfer STX or FTs
  without cooldown, block-height checks, epoch guards, or per-user claim tracking
- Catches repeated-call drain attacks where attacker calls claim in same block to drain pool
- Recognizes safe patterns: block-height guards, claim maps, asserts!, epoch/cooldown/nonce refs
- New test contract: reward-emission-test.clar (2 vulnerable + 3 safe functions)
- 8 new tests in tests/test_reward_emission.py
- Test suite: 95 → 103 tests, all passing

## Previous Changes (2026-03-11, 22:00)
- ✅ Added Uncapped NFT Minting detector (#73)
- Detects nft-mint? in public functions without supply cap, per-address limit, or allowlist
- Catches unlimited NFT minting that can flood collections and destroy holder value
- Recognizes safe patterns: max-supply checks, numeric asserts, mint-count maps, allowlists
- Fixed detector #72 (ft-mint? supply cap) — was false-positive on nft-mint? contracts
  - Used negative lookbehind regex: (?<!n)ft-mint? to exclude nft-mint?
- New test contract: nft-mint-cap-test.clar (2 vulnerable + 2 safe functions)
- 8 new tests in tests/test_nft_mint_cap.py (incl. #72 regression test)
- Test suite: 87 → 95 tests, all passing

## Previous Changes (2026-03-11)
- ✅ Added Missing Token Supply Cap detector (#72)
- Detects ft-mint? in any public function without supply cap / max-supply validation
- Catches unbounded inflation in functions like claim, airdrop, reward (complements #29 which only checks named mint functions)
- Uses regex word-boundary matching to avoid false positives (e.g. "cap" inside "uncapped-token")
- New test contract: supply-cap-test.clar (4 functions, 2 vulnerable + 2 safe)
- 7 new tests in tests/test_supply_cap.py
- Test suite: 80 → 87 tests, all passing

## Previous Changes (2026-03-11)
- ✅ Added SIP-013 semi-fungible token compliance detector (#71)
- Detects incomplete SFT implementations via trait reference, balance-map pattern, or multi-token FT pattern
- Checks for 8 required SIP-013 functions: transfer, transfer-memo, get-balance, get-overall-balance, get-total-supply, get-overall-supply, get-token-uri, get-decimals
- 2 new test contracts: sip013-incomplete.clar, sip013-complete.clar
- 5 new tests in tests/test_sip013.py
- Test suite: 75 → 80 tests, all passing

## Previous Changes (2026-03-10)
- ✅ Removed 5 duplicate method definitions (dead code bug): check_fee_manipulation,
  check_deadline_missing_in_swap, check_integer_truncation_division,
  check_map_insert_without_existence_check, check_stx_transfer_to_variable_recipient
- Python silently uses the last definition — earlier copies were dead code (96 lines removed)
- Added 3 code quality meta-tests: no duplicate methods, all DETECTOR_SPECS have methods, unique IDs
- Test suite: 72 → 75 tests, all passing

## Previous Changes (2026-03-10)
- ✅ Fixed stdout/stderr separation: status lines ([*]/[+]) now go to stderr, report data stays on stdout
- Fixes CI pipeline issue where JSON/SARIF output was polluted by status messages
- Added 3 tests: JSON stdout purity, SARIF stdout purity, stderr status verification
- Fixed severity filter test to check stderr instead of stdout
- Test suite: 69 → 72 tests, all passing

## Previous Changes (2026-03-10)
- ✅ Added 22 config tests: TOML/YAML loading, enable/disable detectors, severity overrides, custom rules
- New tests/test_config.py covering all config subsystems
- Test suite: 47 → 69 tests, all passing

## Previous Changes (2026-03-09)
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

## Architecture
- Single-file scanner: `src/scanner.py` (~2830 lines)
- 75 detectors registered in `DETECTOR_SPECS` list
- Config: TOML/YAML support with per-detector enable/disable
- Output: JSON, Markdown, HTML, SARIF
- Test contracts: 22 files in `test-contracts/`
- CI: GitHub Actions (pytest + CLI smoke test on 3 Python versions)

## Next Improvements (Priority)
1. ~~Fix look-ahead bleeding across function boundaries in detectors 29/34~~ ✅ DONE
2. ~~Add SARIF output test~~ ✅ DONE
3. ~~Add GitHub Actions CI workflow~~ ✅ DONE
4. ~~More detector-specific regression tests~~ ✅ DONE (reentrancy, arithmetic, auth, DoS)
5. ~~README badges~~ ✅ DONE
6. ~~Add CLI integration test (--help, --version flags)~~ ✅ DONE
7. ~~Config file (TOML) test coverage~~ ✅ DONE
8. ~~Fix stdout/stderr separation for clean JSON/SARIF piping~~ ✅ DONE
9. ~~Remove duplicate method definitions (dead code)~~ ✅ DONE
10. git push (needs Xcode license fix or GitHub token auth)
11. ~~Add new detector: SIP-013 semi-fungible token compliance checks~~ ✅ DONE
13. ~~Add uncapped NFT minting detector~~ ✅ DONE
14. ~~Add unbounded reward emission detector~~ ✅ DONE
15. HTML report visual improvements (CSS/summary stats)
