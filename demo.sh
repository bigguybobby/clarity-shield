#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$ROOT_DIR/clarity-shield"
TEST_CONTRACTS="$ROOT_DIR/test-contracts"
FAST_MODE=0

if [[ "${1:-}" == "--fast" ]]; then
  FAST_MODE=1
fi

if [[ ! -x "$SCANNER" ]]; then
  echo "[ERROR] Scanner not executable: $SCANNER"
  echo "Run: chmod +x clarity-shield"
  exit 1
fi

if [[ ! -d "$TEST_CONTRACTS" ]]; then
  echo "[ERROR] Missing test contracts directory: $TEST_CONTRACTS"
  exit 1
fi

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  C_RESET="$(tput sgr0)"
  C_BOLD="$(tput bold)"
  C_DIM="$(tput dim)"
  C_RED="$(tput setaf 1)"
  C_GREEN="$(tput setaf 2)"
  C_YELLOW="$(tput setaf 3)"
  C_BLUE="$(tput setaf 4)"
  C_MAGENTA="$(tput setaf 5)"
  C_CYAN="$(tput setaf 6)"
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_MAGENTA=""
  C_CYAN=""
fi

pause() {
  local seconds="$1"
  if [[ "$FAST_MODE" -eq 0 ]]; then
    sleep "$seconds"
  fi
}

rule() {
  printf "%s\n" "----------------------------------------------------------------"
}

banner() {
  echo
  printf "%s%sClarity Shield Hackathon Demo%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%sFirst automated vulnerability scanner for Clarity smart contracts%s\n" "$C_BLUE" "$C_RESET"
  rule
  echo "Problem: Clarity has zero dedicated automated security tooling."
  echo "Goal: show critical findings in vulnerable contracts and clean results in safe code."
  rule
}

say_step() {
  echo
  printf "%s%s%s\n" "$C_BOLD" "$1" "$C_RESET"
}

print_command() {
  printf "%s$ %s%s\n" "$C_DIM" "$1" "$C_RESET"
}

print_highlighted_output() {
  local output="$1"
  while IFS= read -r line; do
    case "$line" in
      *"CRITICAL ISSUES FOUND"*)
        printf "%s%s%s\n" "$C_RED" "$line" "$C_RESET"
        ;;
      *"No critical or high severity issues found"*)
        printf "%s%s%s\n" "$C_GREEN" "$line" "$C_RESET"
        ;;
      *"Total Findings:"*)
        printf "%s%s%s\n" "$C_BOLD" "$line" "$C_RESET"
        ;;
      *"Critical:"*)
        printf "%s%s%s\n" "$C_RED" "$line" "$C_RESET"
        ;;
      *"High:"*)
        printf "%s%s%s\n" "$C_YELLOW" "$line" "$C_RESET"
        ;;
      *"[*] Scanning"*)
        printf "%s%s%s\n" "$C_CYAN" "$line" "$C_RESET"
        ;;
      *"Found 0 potential issues"*)
        printf "%s%s%s\n" "$C_GREEN" "$line" "$C_RESET"
        ;;
      *)
        printf "%s\n" "$line"
        ;;
    esac
  done <<< "$output"
}

run_scan() {
  local label="$1"
  shift
  local -a cmd=("$@")
  local cmd_str="${cmd[*]}"

  say_step "$label"
  print_command "$cmd_str"

  local output
  output="$("${cmd[@]}" 2>&1)"
  local status=$?

  print_highlighted_output "$output"

  if [[ $status -eq 0 ]]; then
    printf "%s[RESULT] Exit code %s: clean or low-only findings%s\n" "$C_GREEN" "$status" "$C_RESET"
  elif [[ $status -eq 1 ]]; then
    printf "%s[RESULT] Exit code %s: high-severity issues detected%s\n" "$C_YELLOW" "$status" "$C_RESET"
  elif [[ $status -eq 2 ]]; then
    printf "%s[RESULT] Exit code %s: critical issues detected%s\n" "$C_RED" "$status" "$C_RESET"
  else
    printf "%s[RESULT] Exit code %s%s\n" "$C_MAGENTA" "$status" "$C_RESET"
  fi
}

show_reports() {
  echo
  say_step "Generated reports"
  if [[ -d "$ROOT_DIR/findings" ]]; then
    ls -1 "$ROOT_DIR/findings"/*_report.md 2>/dev/null | sed "s|$ROOT_DIR/||" | sed 's/^/  - /' || true
  else
    echo "  - None"
  fi
}

main() {
  banner
  pause 1

  run_scan "1) Vulnerable token scan (expected: critical findings)" \
    "$SCANNER" scan "$TEST_CONTRACTS/vulnerable-token.clar"
  pause 1

  run_scan "2) Safe token scan (expected: no critical/high findings)" \
    "$SCANNER" scan "$TEST_CONTRACTS/safe-token.clar"
  pause 1

  run_scan "3) Full suite scan (expected: multiple criticals across contracts)" \
    "$SCANNER" scan "$TEST_CONTRACTS" --recursive

  show_reports

  echo
  rule
  printf "%s%sDemo complete. Clarity Shield catches vulnerabilities before mainnet.%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%sTip: use './demo.sh --fast' for a no-delay run.%s\n" "$C_DIM" "$C_RESET"
  rule
  echo
}

main "$@"
