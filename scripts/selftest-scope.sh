#!/usr/bin/env bash
# selftest-scope.sh - regression tests for resolve-scope.sh (scope/path resolution and bounded discovery).
#
# Usage: selftest-scope.sh
# Builds throwaway repositories in a temp folder and removes them. Nothing outside it is touched.
# Regression target: "/security-researcher deep apps/api" once became "ls /apps/api" followed by a
# filesystem-wide "find / -type d". These tests pin the correct behaviour.
#
# Exit code: 0 all checks passed, 1 at least one failed.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
RS="$HERE/resolve-scope.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/secresearcher-scope-XXXXXX")" || { echo "cannot create a temp folder" >&2; exit 1; }
TMP="$(cd "$TMP" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok   - $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL - $1"; }
check() { if [ "$3" -eq "$2" ]; then ok "$1 (exit $3)"; else bad "$1 (expected exit $2, got $3)"; fi; }
has()   { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1 (unexpectedly present: $3)" ;; *) ok "$1" ;; esac; }
run_in() { local d="$1"; shift; (cd "$d" && "$@"); } # run a command from a directory

echo "1. syntax and argument handling"
bash -n "$RS"; check "bash -n resolve-scope.sh" 0 $?
bash "$RS" --help >/dev/null 2>&1; check "--help" 0 $?
bash "$RS" --bogus >/dev/null 2>&1; check "unknown option" 2 $?
bash "$RS" --timeout abc x >/dev/null 2>&1; check "non-numeric --timeout" 2 $?
bash "$RS" --timeout 0 x >/dev/null 2>&1; check "--timeout 0" 2 $?
bash "$RS" --timeout 999 x >/dev/null 2>&1; check "--timeout above range" 2 $?
bash "$RS" --max-candidates 0 x >/dev/null 2>&1; check "--max-candidates 0" 2 $?
bash "$RS" a b >/dev/null 2>&1; check "two scopes rejected" 2 $?

echo "2. fixture repositories"
if ! command -v git >/dev/null 2>&1; then echo "  skip - git not available; Git cases not run"; GIT=0; else GIT=1; fi
REPO="$TMP/mono repo"                              # a path with a space on purpose
mkdir -p "$REPO/apps/api/src" "$REPO/apps/web" "$REPO/packages/lib" "$REPO/services/api" "$REPO/node_modules/apps/api" "$REPO/.next/apps/api"
[ "$GIT" -eq 1 ] && git -C "$REPO" init -q 2>/dev/null
PLAIN="$TMP/plain folder"; mkdir -p "$PLAIN/apps/api" "$PLAIN/docs"
SNAP() { (cd "$1" && find . -path ./.git -prune -o -print | sort | tr '\n' ' '); }
S_REPO="$(SNAP "$REPO")"

echo "3. valid relative scope (apps/api)"
OUT="$(run_in "$REPO" bash "$RS" apps/api)"; check "from the repository root" 0 $?
has "resolves under the repository (space in path preserved)" "$OUT" "RESOLVED=$REPO/apps/api"
hasnt "never produces /apps/api" "$OUT" "RESOLVED=/apps/api"
hasnt "never attempts /apps/api" "$OUT" "ATTEMPTED=/apps/api"

echo "4. missing relative scope"
OUT="$(run_in "$REPO" bash "$RS" apps/missing)"; check "reports not found" 3 $?
has "reports the repository root" "$OUT" "ROOT="
has "reports the attempted path" "$OUT" "ATTEMPTED=$REPO/apps/missing"
has "offers siblings of the closest existing parent" "$OUT" "CANDIDATE=$REPO/apps/api"
has "tells the caller to ask, not substitute" "$OUT" "ask the user"
hasnt "no RESOLVED line when nothing resolved" "$OUT" "RESOLVED="
OUT="$(run_in "$REPO" bash "$RS" api)"; check "bare name matches several directories -> not guessed" 3 $?
has "lists apps/api as a candidate" "$OUT" "CANDIDATE=$REPO/apps/api"
has "lists services/api as a candidate" "$OUT" "CANDIDATE=$REPO/services/api"
hasnt "excludes node_modules" "$OUT" "node_modules"
hasnt "excludes .next" "$OUT" ".next"

echo "5. absolute path supplied intentionally"
OUT="$(run_in "$PLAIN" bash "$RS" "$REPO/apps/web")"; check "existing absolute path is used as written" 0 $?
has "resolved exactly" "$OUT" "RESOLVED=$REPO/apps/web"
OUT="$(run_in "$REPO" bash "$RS" /apps/api)"; check "missing absolute path is NOT reinterpreted" 3 $?
hasnt "no RESOLVED for /apps/api" "$OUT" "RESOLVED="
has "the repo-relative reading is only offered as a candidate" "$OUT" "CANDIDATE=$REPO/apps/api"

echo "6. execution from a subdirectory of a Git repository"
if [ "$GIT" -eq 1 ]; then
  OUT="$(run_in "$REPO/apps/web" bash "$RS" apps/api)"; check "scope relative to the repo root works from a subfolder" 0 $?
  has "found via the repository root" "$OUT" "RESOLVED=$REPO/apps/api"
  has "mode is git" "$OUT" "MODE=git"
  OUT="$(run_in "$REPO/apps" bash "$RS" api)"; check "scope relative to the subfolder works" 0 $?
  has "found via the current directory" "$OUT" "RESOLVED=$REPO/apps/api"
  OUT="$(run_in "$REPO/apps/web" bash "$RS" .)"; check "'.' means the repository root" 0 $?
  has "root returned" "$OUT" "RESOLVED=$REPO"
  OUT="$(run_in "$REPO/apps/web" bash "$RS" ../../..)"; check "scope escaping the repository is refused" 2 $?
  # ambiguous: exists relative to cwd AND to the root
  mkdir -p "$REPO/apps/web/apps/api"
  OUT="$(run_in "$REPO/apps/web" bash "$RS" apps/api)"; check "ambiguous scope asks the user" 4 $?
  has "lists both" "$OUT" "CANDIDATE=$REPO/apps/web/apps/api"
  rmdir "$REPO/apps/web/apps/api" "$REPO/apps/web/apps"
fi

echo "7. non-Git working directory"
OUT="$(run_in "$PLAIN" bash "$RS" apps/api)"; check "relative scope in a plain folder" 0 $?
has "mode is non-git" "$OUT" "MODE=non-git"
has "resolved against the current directory" "$OUT" "RESOLVED=$PLAIN/apps/api"
OUT="$(run_in "$PLAIN" bash "$RS" apps/nope)"; check "missing scope in a plain folder" 3 $?
has "candidates stay inside the folder" "$OUT" "CANDIDATE=$PLAIN/apps/api"
OUT="$(run_in "$PLAIN/docs" env SECRESEARCHER_DISABLE_TOOLS=git bash "$RS" apps/api)"; check "git missing: falls back to the current directory only" 3 $?
has "git-less mode is non-git" "$OUT" "MODE=non-git"

echo "8. no filesystem-wide fallback"
FAKEBIN="$TMP/fakebin"; mkdir -p "$FAKEBIN"; FLOG="$TMP/find.log"
REALFIND="$(command -v find)"
printf '#!/bin/sh\necho "$@" >>"%s"\nexec "%s" "$@"\n' "$FLOG" "$REALFIND" >"$FAKEBIN/find"; chmod +x "$FAKEBIN/find"
: >"$FLOG"
OUT="$(run_in "$REPO" env PATH="$FAKEBIN:$PATH" bash "$RS" apps/missing)"; check "discovery with a logging find" 3 $?
[ -s "$FLOG" ] && ok "discovery did run find" || bad "expected find to be invoked"
BADARG=0
while IFS= read -r line; do
  first="${line%% *}"
  case "$line" in "$REPO "*|"$REPO") ;; *) BADARG=1; echo "      unexpected find call: $line" ;; esac
done <"$FLOG"
[ "$BADARG" -eq 0 ] && ok "every find was rooted inside the repository" || bad "find was run outside the repository"
grep -q -E '^/ |^/$' "$FLOG" && bad "find / was invoked" || ok "find / was never invoked"
grep -q -- '-xdev' "$FLOG" && grep -q -- '-maxdepth' "$FLOG" && ok "find is depth-limited and stays on one filesystem" || bad "find lacks -xdev/-maxdepth"
: >"$FLOG"
OUT="$(run_in / env PATH="$FAKEBIN:$PATH" bash "$RS" apps/api)"; check "from / outside a repository: refuses to search" 3 $?
has "explains the refusal" "$OUT" "refusing to search"
[ -s "$FLOG" ] && bad "find ran from /" || ok "no find was started from /"
if [ -n "${HOME:-}" ] && [ -d "$HOME" ] && ! git -C "$HOME" rev-parse >/dev/null 2>&1; then
  : >"$FLOG"
  OUT="$(run_in "$HOME" env PATH="$FAKEBIN:$PATH" bash "$RS" apps/definitely-not-here)"; check "from \$HOME outside a repository: refuses to search" 3 $?
  [ -s "$FLOG" ] && bad "find ran from \$HOME" || ok "no find was started from \$HOME"
else echo "  skip - \$HOME is itself a Git repository or missing"; fi

echo "9. timeout and cancellation"
PIDF="$TMP/slowfind.pid"
printf '#!/bin/sh\necho $$ >"%s"\nexec sleep 30\n' "$PIDF" >"$FAKEBIN/find"; chmod +x "$FAKEBIN/find"
rm -f "$PIDF"; START=$SECONDS
OUT="$(run_in "$REPO" env PATH="$FAKEBIN:$PATH" bash "$RS" --timeout 1 apps/missing)"; rc=$?; ELAPSED=$((SECONDS-START))
check "a hung search ends as 'not found'" 3 $rc
[ "$ELAPSED" -le 8 ] && ok "returned within the timeout window (${ELAPSED}s, limit 1s + slack)" || bad "took ${ELAPSED}s with --timeout 1"
has "says the candidate list may be incomplete" "$OUT" "may be incomplete"
SP="$(cat "$PIDF" 2>/dev/null || true)"
if [ -n "$SP" ]; then kill -0 "$SP" 2>/dev/null && bad "slow find (pid $SP) still running after timeout" || ok "no search process left behind after timeout"; else bad "slow find never started"; fi

rm -f "$PIDF"
# start the resolver itself in the background (not a wrapper subshell) so TERM reaches it
cd "$REPO" || exit 1
PATH="$FAKEBIN:$PATH" bash "$RS" --timeout 60 apps/missing >"$TMP/cancel.out" 2>&1 &
SPID=$!
cd "$HERE" || exit 1
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "$PIDF" ] && break; sleep 0.25 2>/dev/null || sleep 1; done
kill -TERM "$SPID" 2>/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do kill -0 "$SPID" 2>/dev/null || break; sleep 0.25 2>/dev/null || sleep 1; done
SP="$(cat "$PIDF" 2>/dev/null || true)"
if kill -0 "$SPID" 2>/dev/null; then bad "resolver still running after TERM"; kill -KILL "$SPID" 2>/dev/null; else ok "resolver stopped on TERM"; fi
if [ -n "$SP" ]; then kill -0 "$SP" 2>/dev/null && bad "search (pid $SP) still running after cancellation" || ok "no search process left behind after cancellation"; else bad "slow find never started in cancel test"; fi
wait "$SPID" 2>/dev/null

echo "10. read-only guarantee"
[ "$(SNAP "$REPO")" = "$S_REPO" ] && ok "the repository was not modified" || bad "the fixture repository changed"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
