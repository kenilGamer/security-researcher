#!/usr/bin/env bash
# check-tool-availability.sh - report which security tools are installed and usable.
#
# Usage: check-tool-availability.sh [--json] [--require tool1,tool2,...]
#
# It only asks each tool for its version. It installs nothing, changes nothing and
# never contacts the network. Install hints are printed as text for the user to run.
#
# Exit codes:
#   0  the check ran (missing tools are reported, not hidden)
#   2  usage error
#   3  a tool named with --require is missing or does not run (never a false success)

set -u
set -o pipefail

JSON=0
REQUIRE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --require)
      shift
      if [ $# -eq 0 ] || [ -z "${1:-}" ]; then echo "check-tool-availability: --require needs a comma separated list" >&2; exit 2; fi
      REQUIRE="$1" ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "check-tool-availability: unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# name | version command | purpose | install hint (text only, never executed)
TOOLS=(
  "semgrep|semgrep --version|static analysis (rules matching code patterns)|pipx install semgrep   (or: brew install semgrep)"
  "codeql|codeql version --format=terse|deep dataflow analysis (needs a database build and suitable queries)|see https://docs.github.com/code-security/codeql-cli"
  "gitleaks|gitleaks version|secret scanning|brew install gitleaks   (or a release binary from github.com/gitleaks/gitleaks)"
  "trivy|trivy --version|dependency, secret, IaC and image scanning|brew install trivy   (or see aquasecurity.github.io/trivy)"
  "osv-scanner|osv-scanner --version|dependency vulnerabilities from lockfiles (OSV database)|go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest   (or a release binary)"
  "npm|npm --version|npm audit (Node dependencies)|install Node.js"
  "pnpm|pnpm --version|pnpm audit (Node dependencies)|npm install -g pnpm   (or corepack enable)"
  "yarn|yarn --version|yarn audit (Node dependencies)|corepack enable"
  "pip-audit|pip-audit --version|Python dependency vulnerabilities|pipx install pip-audit"
  "bandit|bandit --version|Python static security checks|pipx install bandit"
  "govulncheck|govulncheck -version|Go dependency vulnerabilities (reachability aware)|go install golang.org/x/vuln/cmd/govulncheck@latest"
  "cargo-audit|cargo audit --version|Rust dependency advisories|cargo install cargo-audit"
  "bundler-audit|bundle-audit --version|Ruby dependency advisories|gem install bundler-audit"
  "shellcheck|shellcheck --version|shell script analysis|brew install shellcheck   (or apt install shellcheck)"
  "zap|zap.sh -version|OWASP ZAP dynamic scanning (authorised targets only)|see https://www.zaproxy.org/download/"
  "git|git --version|history, tracked-file and blame checks|install git"
  "jq|jq --version|JSON processing (optional)|brew install jq   (or apt install jq)"
)

run_with_timeout() { # $1 seconds, rest command
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else "$@"; fi
}

json_escape() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; printf '%s' "$s"; }

declare -a STATUS_NAMES=() STATUS_VALUES=() STATUS_VERSIONS=()
for entry in "${TOOLS[@]}"; do
  IFS='|' read -r name vercmd purpose hint <<<"$entry"
  bin="${vercmd%% *}"
  if ! command -v "$bin" >/dev/null 2>&1; then
    status="missing"; version=""
  else
    # shellcheck disable=SC2086
    out="$(run_with_timeout 15 $vercmd 2>&1 | head -n 1)"; code=${PIPESTATUS[0]:-0}
    # A tool only counts as available when it exits 0 and prints something that looks like a version.
    if [ -n "$out" ] && [ "$code" -eq 0 ] && printf '%s' "$out" | grep -Eq '[0-9]+\.[0-9]+'; then status="available"; version="$out"
    else status="broken"; version="${out:-no output (exit $code)}"; fi
  fi
  STATUS_NAMES+=("$name"); STATUS_VALUES+=("$status"); STATUS_VERSIONS+=("$version")
done

if [ "$JSON" -eq 1 ]; then
  printf '{"tools":['
  for i in "${!STATUS_NAMES[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    IFS='|' read -r name _ purpose hint <<<"${TOOLS[$i]}"
    printf '{"name":"%s","status":"%s","version":"%s","purpose":"%s","installHint":"%s"}' \
      "$(json_escape "${STATUS_NAMES[$i]}")" "${STATUS_VALUES[$i]}" "$(json_escape "${STATUS_VERSIONS[$i]}")" "$(json_escape "$purpose")" "$(json_escape "$hint")"
  done
  printf '],"note":"nothing was installed or modified"}\n'
else
  printf '%-14s %-10s %s\n' TOOL STATUS "VERSION / WHAT IT IS FOR"
  for i in "${!STATUS_NAMES[@]}"; do
    IFS='|' read -r name _ purpose hint <<<"${TOOLS[$i]}"
    case "${STATUS_VALUES[$i]}" in
      available) printf '%-14s %-10s %s\n' "$name" available "${STATUS_VERSIONS[$i]}" ;;
      broken)    printf '%-14s %-10s %s\n' "$name" BROKEN "${STATUS_VERSIONS[$i]}" ;;
      missing)   printf '%-14s %-10s %s\n' "$name" missing "$purpose. To get it (not run for you): $hint" ;;
    esac
  done
  echo
  echo "Nothing was installed or modified. A missing tool means that coverage is missing, not that the code is clean."
fi

if [ -n "$REQUIRE" ]; then
  failed=0
  IFS=',' read -r -a want <<<"$REQUIRE"
  for w in "${want[@]}"; do
    w="${w// /}"; [ -z "$w" ] && continue
    found=0
    for i in "${!STATUS_NAMES[@]}"; do
      if [ "${STATUS_NAMES[$i]}" = "$w" ]; then
        found=1
        if [ "${STATUS_VALUES[$i]}" != "available" ]; then
          echo "REQUIRED TOOL NOT USABLE: $w (${STATUS_VALUES[$i]})" >&2; failed=1
        fi
      fi
    done
    if [ "$found" -eq 0 ]; then echo "REQUIRED TOOL UNKNOWN TO THIS SCRIPT: $w" >&2; failed=1; fi
  done
  [ "$failed" -eq 1 ] && exit 3
fi
exit 0
