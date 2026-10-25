#!/usr/bin/env bash
# selftest.sh - checks the helper scripts of this skill against a throwaway fixture repository.
#
# Usage: selftest.sh
# Creates a temporary folder, never touches any real project, removes the folder at the end.
# Uses tiny stand-in "scanners" on PATH to prove that findings, errors and missing tools are
# reported honestly (a missing or failing tool must never look like a clean result).
#
# Exit code: 0 all checks passed, 1 at least one failed.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/secresearcher-selftest-XXXXXX")" || { echo "cannot create a temp folder" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL - $1"; }
check() { # description, expected exit, actual exit
  if [ "$3" -eq "$2" ]; then ok "$1 (exit $3)"; else bad "$1 (expected exit $2, got $3)"; fi
}
contains() { # description, haystack, needle
  case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac
}
valid_json() { # description, text
  if command -v node >/dev/null 2>&1; then
    if printf '%s' "$2" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{JSON.parse(s)}catch(e){process.exit(1)}})'; then ok "$1 is valid JSON"; else bad "$1 is not valid JSON"; fi
  elif command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$2" | python3 -c 'import json,sys; json.load(sys.stdin)'; then ok "$1 is valid JSON"; else bad "$1 is not valid JSON"; fi
  else echo "  skip - $1 JSON validity (neither node nor python3 available)"; fi
}

echo "1. syntax"
for f in detect-stack.sh check-tool-availability.sh run-static-scans.sh selftest.sh; do
  bash -n "$HERE/$f" 2>/dev/null; check "bash -n $f" 0 $?
done

echo "2. fixture repository"
FIX="$TMP/fixture with space"; mkdir -p "$FIX/src/routes" "$FIX/tests" "$FIX/node_modules/skipme"
cat >"$FIX/package.json" <<'EOF'
{ "name": "fixture", "dependencies": { "express": "4.0.0", "jsonwebtoken": "9.0.0", "mongoose": "8.0.0" } }
EOF
echo "console.log('hi')" >"$FIX/src/server.js"
echo "module.exports = {}" >"$FIX/src/routes/auth.routes.js"
echo "FAKE=1" >"$FIX/.env"
echo "x" >"$FIX/tests/a.test.js"
echo "ignored" >"$FIX/node_modules/skipme/index.js"
BEFORE="$(cd "$FIX" && find . -type f | sort | tr '\n' ' ')"

echo "3. detect-stack.sh"
OUT="$(bash "$HERE/detect-stack.sh" "$FIX" 2>&1)"; check "detect-stack on the fixture" 0 $?
contains "finds Express (the fixture path contains a space)" "$OUT" "Express"
contains "finds the Mongoose dependency" "$OUT" "Mongoose/MongoDB"
contains "finds the JWT library" "$OUT" "JWT library"
contains "finds the manifest" "$OUT" "npm-package.json"
contains "lists the .env file without reading it" "$OUT" ".env"
case "$OUT" in *"FAKE=1"*) bad "must not print .env contents" ;; *) ok "does not print .env contents" ;; esac
case "$OUT" in *skipme*) bad "must ignore node_modules" ;; *) ok "ignores node_modules" ;; esac
JSON_OUT="$(bash "$HERE/detect-stack.sh" --json "$FIX" 2>/dev/null)"; valid_json "detect-stack --json" "$JSON_OUT"
bash "$HERE/detect-stack.sh" "$TMP/does-not-exist" >/dev/null 2>&1; check "detect-stack on a missing folder" 2 $?
bash "$HERE/detect-stack.sh" --bogus >/dev/null 2>&1; check "detect-stack rejects unknown options" 2 $?

echo "4. check-tool-availability.sh"
OUT="$(bash "$HERE/check-tool-availability.sh" 2>&1)"; check "tool check runs" 0 $?
contains "says nothing was installed" "$OUT" "Nothing was installed"
JSON_OUT="$(bash "$HERE/check-tool-availability.sh" --json 2>/dev/null)"; valid_json "tool check --json" "$JSON_OUT"
bash "$HERE/check-tool-availability.sh" --require not-a-real-tool >/dev/null 2>&1; check "--require of an unknown tool fails" 3 $?
bash "$HERE/check-tool-availability.sh" --require git,node-that-does-not-exist >/dev/null 2>&1; check "--require of a missing tool fails" 3 $?

echo "5. run-static-scans.sh argument handling"
bash "$HERE/run-static-scans.sh" --path "$TMP/nope" >/dev/null 2>&1; check "missing path" 2 $?
bash "$HERE/run-static-scans.sh" --path "$FIX" --tools bogus >/dev/null 2>&1; check "unknown tool name" 2 $?
bash "$HERE/run-static-scans.sh" --path "$FIX" --timeout abc >/dev/null 2>&1; check "non-numeric timeout" 2 $?
bash "$HERE/run-static-scans.sh" --path "$FIX" --fail-on sometimes >/dev/null 2>&1; check "invalid --fail-on" 2 $?
bash "$HERE/run-static-scans.sh" --path "$FIX" --out "$TMP/not-created" >/dev/null 2>&1; check "--out folder that does not exist" 2 $?

echo "6. run-static-scans.sh with every scanner hidden"
HIDE="semgrep gitleaks trivy osv-scanner npm pnpm pip-audit"
OUT="$(SECRESEARCHER_DISABLE_TOOLS="$HIDE" bash "$HERE/run-static-scans.sh" --path "$FIX" 2>&1)"; check "no scanner available gives NO COVERAGE, not success" 20 $?
contains "says NO COVERAGE" "$OUT" "NO COVERAGE"
contains "reports tools as missing" "$OUT" "skipped-missing"
JSON_OUT="$(SECRESEARCHER_DISABLE_TOOLS="$HIDE" bash "$HERE/run-static-scans.sh" --path "$FIX" --json 2>/dev/null)"; valid_json "scan summary" "$JSON_OUT"
contains "summary carries the unverified-alert note" "$JSON_OUT" "unverified"

echo "7. run-static-scans.sh with stand-in scanners"
FAKEBIN="$TMP/fakebin"; mkdir -p "$FAKEBIN"
make_fake() { printf '#!/bin/sh\nif [ "$1" = "--version" ] || [ "$1" = "version" ]; then echo "fake 0.0"; exit 0; fi\nexit %s\n' "$2" >"$FAKEBIN/$1"; chmod +x "$FAKEBIN/$1"; }

make_fake gitleaks 1
OUT="$(PATH="$FAKEBIN:$PATH" bash "$HERE/run-static-scans.sh" --path "$FIX" --tools gitleaks --fail-on any 2>&1)"; check "findings with --fail-on any" 10 $?
contains "status is ran-with-findings" "$OUT" "ran-with-findings"
PATH="$FAKEBIN:$PATH" bash "$HERE/run-static-scans.sh" --path "$FIX" --tools gitleaks >/dev/null 2>&1; check "findings without a gate still exit 0 (alerts are not verdicts)" 0 $?

make_fake gitleaks 0
OUT="$(PATH="$FAKEBIN:$PATH" bash "$HERE/run-static-scans.sh" --path "$FIX" --tools gitleaks --fail-on any 2>&1)"; check "clean tool run" 0 $?
contains "status is ran" "$OUT" " ran "

make_fake gitleaks 7
OUT="$(PATH="$FAKEBIN:$PATH" bash "$HERE/run-static-scans.sh" --path "$FIX" --tools gitleaks 2>&1)"; check "a crashing tool is an error, not a pass" 20 $?
contains "status is error" "$OUT" "error"

make_fake trivy 0
OUT="$(PATH="$FAKEBIN:$PATH" bash "$HERE/run-static-scans.sh" --path "$FIX" --tools trivy 2>&1)"; check "network tool without --allow-network" 20 $?
contains "is skipped, naming the reason" "$OUT" "skipped-network-not-allowed"

mkdir -p "$TMP/outbase"
make_fake gitleaks 0
PATH="$FAKEBIN:$PATH" bash "$HERE/run-static-scans.sh" --path "$FIX" --tools gitleaks --out "$TMP/outbase" >/dev/null 2>&1; check "--out writes into a new timestamped folder" 0 $?
COUNT="$(find "$TMP/outbase" -maxdepth 1 -type d -name 'security-scan-*' | wc -l | tr -d ' ')"
[ "$COUNT" = "1" ] && ok "exactly one new output folder" || bad "expected one output folder, found $COUNT"

echo "8. read-only guarantee"
AFTER="$(cd "$FIX" && find . -type f | sort | tr '\n' ' ')"
[ "$BEFORE" = "$AFTER" ] && ok "the scanned repository was not modified" || bad "the fixture repository changed"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
