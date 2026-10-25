#!/usr/bin/env bash
# run-static-scans.sh - run the installed static security scanners against a repository, read-only.
#
# Usage:
#   run-static-scans.sh [--path DIR] [--out DIR] [--json] [--timeout SECONDS] [--tools a,b,c]
#                       [--allow-network] [--semgrep-config PATH|RULESET] [--fail-on any|none]
#
#   --path DIR            repository to scan (default: current directory)
#   --out DIR             keep raw scanner output in a NEW timestamped folder inside DIR (never overwrites).
#                         Without it, raw output goes to a fresh temporary folder whose path is printed.
#   --json                print one machine-readable summary on stdout (human text goes to stderr)
#   --timeout SECONDS     limit per tool (default 300, max 3600)
#   --tools LIST          only these: semgrep,gitleaks,trivy,osv-scanner,npm-audit,pnpm-audit,pip-audit
#   --allow-network       permit tools that need the network (vulnerability databases, rule registries).
#                         Without it those tools are SKIPPED and reported as skipped, never as passed.
#   --semgrep-config X    a local rules file/folder, or a registry ruleset such as p/ci (needs --allow-network)
#   --fail-on any|none    CI gate: "any" exits 10 when a tool reported findings (default: none)
#
# What it never does: install anything, run project scripts, modify lockfiles or sources, delete files,
# upload source code, or print secret values (gitleaks runs with --redact).
# Scanner output is a set of UNVERIFIED ALERTS. It is evidence to investigate, not proof of a vulnerability.
#
# Exit codes: 0 at least one tool ran and the gate (if any) passed; 2 usage error;
#             10 --fail-on any and a tool reported findings; 20 NO tool ran (no coverage, not a pass).

set -u
set -o pipefail

JSON=0; ROOT="."; OUT_BASE=""; TIMEOUT=300; TOOLS=""; ALLOW_NET=0; SG_CONFIG=""; FAIL_ON="none"

usage_error() { echo "run-static-scans: $1" >&2; echo "Try --help." >&2; exit 2; }
need_value() { [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --path) need_value "$@"; ROOT="$2"; shift ;;
    --out) need_value "$@"; OUT_BASE="$2"; shift ;;
    --json) JSON=1 ;;
    --timeout) need_value "$@"; TIMEOUT="$2"; shift ;;
    --tools) need_value "$@"; TOOLS="$2"; shift ;;
    --allow-network) ALLOW_NET=1 ;;
    --semgrep-config) need_value "$@"; SG_CONFIG="$2"; shift ;;
    --fail-on) need_value "$@"; FAIL_ON="$2"; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done

case "$TIMEOUT" in ''|*[!0-9]*) usage_error "--timeout must be a whole number of seconds" ;; esac
{ [ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 3600 ]; } || usage_error "--timeout must be between 1 and 3600"
case "$FAIL_ON" in any|none) ;; *) usage_error "--fail-on must be 'any' or 'none'" ;; esac
[ -d "$ROOT" ] || usage_error "not a directory: $ROOT"
[ -r "$ROOT" ] || usage_error "directory is not readable: $ROOT"
ROOT="$(cd "$ROOT" && pwd)"

ALL_TOOLS="semgrep gitleaks trivy osv-scanner npm-audit pnpm-audit pip-audit"
if [ -n "$TOOLS" ]; then
  for t in ${TOOLS//,/ }; do
    case " $ALL_TOOLS " in *" $t "*) ;; *) usage_error "unknown tool: $t (known: ${ALL_TOOLS// /, })" ;; esac
  done
  WANTED="${TOOLS//,/ }"
else
  WANTED="$ALL_TOOLS"
fi

# ---- output folder (always new; nothing is overwritten) ----------------------
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -n "$OUT_BASE" ]; then
  [ -d "$OUT_BASE" ] || usage_error "--out folder does not exist: $OUT_BASE (create it first; this script will not)"
  [ -w "$OUT_BASE" ] || usage_error "--out folder is not writable: $OUT_BASE"
  OUT="$OUT_BASE/security-scan-$STAMP"
  [ -e "$OUT" ] && usage_error "refusing to overwrite existing $OUT"
  mkdir "$OUT" || usage_error "could not create $OUT"
else
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/security-scan-XXXXXX")" || usage_error "could not create a temporary folder"
fi
case "$OUT" in "$ROOT"|"$ROOT"/*) echo "run-static-scans: WARNING output folder is inside the scanned repository; do not commit it." >&2 ;; esac

say() { if [ "$JSON" -eq 1 ]; then echo "$@" >&2; else echo "$@"; fi; }
# SECRESEARCHER_DISABLE_TOOLS="name name" hides tools on purpose (used by selftest.sh, or to exclude a tool).
have() {
  case " ${SECRESEARCHER_DISABLE_TOOLS:-} " in *" $1 "*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}
has_file() { find "$ROOT" -maxdepth 4 \( -name node_modules -o -name .git -o -name .next -o -name vendor -o -name .venv \) -prune -o -type f -name "$1" -print -quit 2>/dev/null | grep -q .; }
with_timeout() {
  if have timeout; then timeout "$TIMEOUT" "$@"
  elif have gtimeout; then gtimeout "$TIMEOUT" "$@"
  else "$@"; fi
}

declare -a R_TOOL=() R_STATUS=() R_DETAIL=() R_FILE=()
record() { R_TOOL+=("$1"); R_STATUS+=("$2"); R_DETAIL+=("$3"); R_FILE+=("${4:-}"); }

# run_tool NAME OUTFILE FINDINGS_EXIT_CODE cmd...   (runs inside the repository, stdout kept in OUTFILE)
run_tool() {
  local name="$1" file="$2" findings_code="$3"; shift 3
  local err="$OUT/$name.stderr.txt" code
  ( cd "$ROOT" && with_timeout "$@" ) >"$file" 2>"$err"
  code=$?
  local tail_err; tail_err="$(tail -n 2 "$err" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
  if [ "$code" -eq 0 ]; then record "$name" "ran" "completed, no findings reported by the tool" "$file"
  elif [ "$code" -eq "$findings_code" ]; then record "$name" "ran-with-findings" "tool reported findings (UNVERIFIED alerts; see raw output)" "$file"
  elif [ "$code" -eq 124 ]; then record "$name" "timeout" "stopped after ${TIMEOUT}s; coverage is incomplete" "$file"
  else record "$name" "error" "exit $code: ${tail_err:-no message}" "$file"; fi
}

want() { case " $WANTED " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
skip_missing() { record "$1" "skipped-missing" "not installed; coverage gap (run check-tool-availability.sh for install hints)" ""; }
skip_net() { record "$1" "skipped-network-not-allowed" "needs network access; rerun with --allow-network if that is permitted for this code" ""; }
skip_na() { record "$1" "skipped-not-applicable" "$2" ""; }

say "Scanning: $ROOT"
say "Raw output: $OUT"
say ""

# ---- semgrep -----------------------------------------------------------------
if want semgrep; then
  if ! have semgrep; then skip_missing semgrep
  elif [ -z "$SG_CONFIG" ]; then skip_na semgrep "no rules given. Pass --semgrep-config <local rules> or --semgrep-config p/ci with --allow-network"
  elif [ ! -e "$SG_CONFIG" ] && [ "$ALLOW_NET" -ne 1 ]; then skip_net semgrep
  else
    # --metrics=off: no usage telemetry. Source code is analysed locally; only the rule download uses the network.
    run_tool semgrep "$OUT/semgrep.json" 1 semgrep scan --metrics=off --disable-version-check --quiet --error --json --config "$SG_CONFIG" "$ROOT"
  fi
fi

# ---- gitleaks (secret scanning, always redacted) -------------------------------
if want gitleaks; then
  if ! have gitleaks; then skip_missing gitleaks
  else
    run_tool gitleaks-worktree "$OUT/gitleaks-worktree.json" 1 gitleaks detect --no-git --source "$ROOT" --redact --no-banner --exit-code 1 --report-format json --report-path "$OUT/gitleaks-worktree.report.json"
    if [ -d "$ROOT/.git" ]; then
      run_tool gitleaks-history "$OUT/gitleaks-history.json" 1 gitleaks detect --source "$ROOT" --redact --no-banner --exit-code 1 --report-format json --report-path "$OUT/gitleaks-history.report.json"
    else
      skip_na gitleaks-history "not a git repository, so no history to scan"
    fi
  fi
fi

# ---- trivy -----------------------------------------------------------------------
if want trivy; then
  if ! have trivy; then skip_missing trivy
  elif [ "$ALLOW_NET" -ne 1 ]; then skip_net trivy
  else run_tool trivy "$OUT/trivy.json" 1 trivy fs --scanners vuln,secret,misconfig --exit-code 1 --quiet --format json "$ROOT"
  fi
fi

# ---- osv-scanner -----------------------------------------------------------------
if want osv-scanner; then
  if ! have osv-scanner; then skip_missing osv-scanner
  elif [ "$ALLOW_NET" -ne 1 ]; then skip_net osv-scanner
  else
    if osv-scanner scan --help >/dev/null 2>&1; then
      run_tool osv-scanner "$OUT/osv-scanner.json" 1 osv-scanner scan source -r --format json "$ROOT"
    else
      run_tool osv-scanner "$OUT/osv-scanner.json" 1 osv-scanner --format json -r "$ROOT"
    fi
  fi
fi

# ---- ecosystem audits (they read a lockfile and query an advisory service; none modify anything) ----
if want npm-audit; then
  if [ ! -f "$ROOT/package-lock.json" ]; then skip_na npm-audit "no package-lock.json in the repository root"
  elif ! have npm; then skip_missing npm-audit
  elif [ "$ALLOW_NET" -ne 1 ]; then skip_net npm-audit
  else run_tool npm-audit "$OUT/npm-audit.json" 1 npm audit --package-lock-only --json; fi
fi
if want pnpm-audit; then
  if [ ! -f "$ROOT/pnpm-lock.yaml" ]; then skip_na pnpm-audit "no pnpm-lock.yaml in the repository root"
  elif ! have pnpm; then skip_missing pnpm-audit
  elif [ "$ALLOW_NET" -ne 1 ]; then skip_net pnpm-audit
  else run_tool pnpm-audit "$OUT/pnpm-audit.json" 1 pnpm audit --json; fi
fi
if want pip-audit; then
  REQ="$(find "$ROOT" -maxdepth 2 -name 'requirements*.txt' -not -path '*/node_modules/*' -print -quit 2>/dev/null)"
  if [ -z "$REQ" ]; then skip_na pip-audit "no requirements*.txt (a pyproject-only project needs a manual pip-audit run)"
  elif ! have pip-audit; then skip_missing pip-audit
  elif [ "$ALLOW_NET" -ne 1 ]; then skip_net pip-audit
  else run_tool pip-audit "$OUT/pip-audit.json" 1 pip-audit -r "$REQ" -f json; fi
fi
if has_file yarn.lock; then
  skip_na yarn-audit "yarn.lock found: yarn audit differs between Yarn versions; run it manually"
fi

# ---- summary -----------------------------------------------------------------
RAN=0; FOUND=0; GAPS=0
for i in "${!R_TOOL[@]}"; do
  case "${R_STATUS[$i]}" in
    ran) RAN=$((RAN+1)) ;;
    ran-with-findings) RAN=$((RAN+1)); FOUND=$((FOUND+1)) ;;
    skipped-*|error|timeout) GAPS=$((GAPS+1)) ;;
  esac
done

CODE=0
[ "$RAN" -eq 0 ] && CODE=20
[ "$FAIL_ON" = "any" ] && [ "$FOUND" -gt 0 ] && CODE=10

jesc() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

if [ "$JSON" -eq 1 ]; then
  printf '{"root":"%s","outputFolder":"%s","timestamp":"%s","allowNetwork":%s,"failOn":"%s","toolsRan":%d,"toolsWithFindings":%d,"coverageGaps":%d,"results":[' \
    "$(jesc "$ROOT")" "$(jesc "$OUT")" "$STAMP" "$([ $ALLOW_NET -eq 1 ] && echo true || echo false)" "$FAIL_ON" "$RAN" "$FOUND" "$GAPS"
  for i in "${!R_TOOL[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    printf '{"tool":"%s","status":"%s","detail":"%s","rawOutput":"%s"}' "${R_TOOL[$i]}" "${R_STATUS[$i]}" "$(jesc "${R_DETAIL[$i]}")" "$(jesc "${R_FILE[$i]}")"
  done
  printf '],"exitCode":%d,"note":"findings are unverified scanner alerts; skipped tools are coverage gaps, not passes"}\n' "$CODE"
else
  printf '%-20s %-30s %s\n' TOOL STATUS DETAIL
  for i in "${!R_TOOL[@]}"; do printf '%-20s %-30s %s\n' "${R_TOOL[$i]}" "${R_STATUS[$i]}" "${R_DETAIL[$i]}"; done
  echo
  echo "Tools that ran: $RAN | with findings: $FOUND | not run / incomplete: $GAPS"
  echo "Findings from scanners are UNVERIFIED ALERTS. Skipped tools are coverage gaps, not passes."
fi

if [ "$CODE" -eq 20 ]; then
  say "NO COVERAGE: no scanner ran. This is not a clean result. Install a tool, supply --semgrep-config, or use --allow-network if permitted." >&2
fi
[ "$CODE" -eq 10 ] && say "GATE FAILED: --fail-on any and a tool reported findings (still unverified until investigated)." >&2
exit "$CODE"
