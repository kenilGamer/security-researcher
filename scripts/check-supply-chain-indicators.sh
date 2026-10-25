#!/usr/bin/env bash
# check-supply-chain-indicators.sh - static, read-only look for supply-chain risk signals in a repository.
#
# Usage: check-supply-chain-indicators.sh [--path DIR] [--fail-on indicator|review|none]
#
#   --path DIR     repository to inspect (default: current directory)
#   --fail-on X    which levels make the exit code 10 (default: review)
#                    indicator  only INDICATOR lines
#                    review     INDICATOR and REVIEW lines
#                    none       never (findings are still printed)
#
# Output lines are tab separated:  LEVEL  category  location  detail
#   INDICATOR  a suspicious pattern (install-time download-and-run, credential-file access, obfuscation...)
#   REVIEW     a risky configuration worth a human look (unpinned action, floating image, non-registry source)
#   INFO       context only, e.g. "a postinstall script exists". Existence alone is NOT suspicious.
#   GAP        something that could not be checked (counts against coverage)
# Matched source lines are never echoed (they may contain secrets); only the file, line number and pattern name.
#
# It only reads files. It never runs package scripts, installs, pulls images, or contacts a network.
# git is used read-only, with fsmonitor and hooks disabled, because a hostile repository's own git config
# is untrusted input.
# "No indicators" is NOT proof that a repository or its dependencies are free of malware.
#
# Exit codes: 0 nothing flagged at the chosen level and no coverage gap; 2 usage error;
#             10 flagged (takes priority over 20); 20 incomplete coverage or nothing recognisable to inspect.

set -u
set -o pipefail

ROOT="."; FAIL_ON="review"
usage_error() { echo "check-supply-chain-indicators: $1" >&2; echo "Try --help." >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --path) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--path needs a value"; ROOT="$2"; shift ;;
    --fail-on) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--fail-on needs a value"; FAIL_ON="$2"; shift ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
case "$FAIL_ON" in indicator|review|none) ;; *) usage_error "--fail-on must be indicator, review or none" ;; esac
[ -d "$ROOT" ] && [ -r "$ROOT" ] || usage_error "not a readable directory: $ROOT"
ROOT="$(cd "$ROOT" && pwd)"

have() {
  case " ${SECRESEARCHER_DISABLE_TOOLS:-} " in *" $1 "*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}
N_IND=0; N_REV=0; N_INFO=0; N_GAP=0; RECOGNISED=0
TAB="$(printf '\t')"
emit() { # level category location detail
  case "$1" in INDICATOR) N_IND=$((N_IND+1)) ;; REVIEW) N_REV=$((N_REV+1)) ;; INFO) N_INFO=$((N_INFO+1)) ;; GAP) N_GAP=$((N_GAP+1)) ;; esac
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4//$TAB/ }"
}
rel() { printf '%s' "${1#"$ROOT"/}"; }
# mask long token-like strings before any script text is shown
mask() { sed -E 's/[A-Za-z0-9_+\/=-]{32,}/****/g' | cut -c1-140; }

PRUNE=( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name vendor -o -name .venv -o -name venv )

# ---- pattern checks on a piece of script text (name = label shown, never the matched text) ----
# usage: scan_file FILE LOCATION_LABEL
scan_file() {
  local f="$1" label="$2" name pat n
  [ -f "$f" ] && [ -r "$f" ] || return 0
  while IFS='~' read -r name pat; do
    n="$(grep -c -i -E -e "$pat" "$f" 2>/dev/null || true)"
    [ "${n:-0}" -gt 0 ] && emit INDICATOR "$name" "$label" "pattern matched on $n line(s); inspect the file (content not echoed)"
  done <<'PATTERNS'
download-and-execute~(curl|wget)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh([[:space:]]|$)
encoded-payload-decode~(base64[[:space:]]+(-d|--decode)|atob[[:space:]]*\(|Buffer\.from\([^)]*['"]base64['"])
dynamic-code-execution~(\beval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(|node[[:space:]]+(-e|--eval)[[:space:]]|python3?[[:space:]]+-c[[:space:]])
process-spawn~(child_process|execSync|spawnSync|\bexecFile\b)
credential-file-access~(\.npmrc|NPM_TOKEN|NODE_AUTH_TOKEN|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|AWS_SECRET_ACCESS_KEY|\.git-credentials|\.docker/config\.json|GITHUB_TOKEN)
environment-dump~(process\.env[[:space:]]*\)|JSON\.stringify\([[:space:]]*process\.env|\bprintenv\b|os\.environ\b[^[]*\))
external-url-in-script~https?://[A-Za-z0-9.-]+\.[a-z]{2,}
obfuscator-identifiers~(_0x[0-9a-f]{4,}|(\\x[0-9a-fA-F]{2}){12,})
encoded-powershell~powershell[^|]*[[:space:]]-(enc|encodedcommand)
PATTERNS
  # a single enormous line is a classic minified/obfuscated payload shape (heuristic, many false positives in dist/)
  if awk 'length($0) > 4000 { found=1 } END { exit !found }' "$f" 2>/dev/null; then
    emit REVIEW "very-long-line" "$label" "line over 4000 characters (minified or packed code); expected in bundles, unexpected in install scripts"
  fi
}

# ---- one package.json: lifecycle scripts ------------------------------------------------------
scan_package_json() { # file, label
  local pj="$1" label="$2" dir hook body k script ref
  dir="$(dirname "$pj")"
  while IFS= read -r line; do
    hook="$(printf '%s' "$line" | sed -E 's/^"([A-Za-z]+)".*/\1/')"
    body="$(printf '%s' "$line" | sed -E 's/^[^:]*:[[:space:]]*"(.*)"$/\1/')"
    emit INFO "lifecycle-script" "$label" "$hook: $(printf '%s' "$body" | mask)"
    # pattern-check the script text itself
    local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/sci-XXXXXX")" || continue
    printf '%s\n' "$body" >"$tmp"; scan_file "$tmp" "$label ($hook script)"; rm -f "$tmp"
    # follow a local "node path/to/file.js" one level, inside the package directory only
    ref="$(printf '%s' "$body" | sed -n -E 's/.*node[[:space:]]+(\.\/)?([A-Za-z0-9_.\/-]+\.(c|m)?js).*/\2/p' | head -n 1)"
    case "$ref" in ''|/*|*..*) ;; *) [ -f "$dir/$ref" ] && scan_file "$dir/$ref" "$label -> $ref" ;; esac
  done < <(grep -o -E '"(preinstall|install|postinstall|prepare|prepublish|prepublishOnly|prepack|postpack)"[[:space:]]*:[[:space:]]*"([^"\\]|\\.)*"' "$pj" 2>/dev/null | head -n 20)
}

# ---- 1. npm: root and installed packages ------------------------------------------------------
PJ_LIST="$(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f -name package.json -print 2>/dev/null | head -n 20)"
if [ -n "$PJ_LIST" ]; then
  RECOGNISED=1
  while IFS= read -r pj; do [ -z "$pj" ] && continue; scan_package_json "$pj" "$(rel "$pj")"; done <<<"$PJ_LIST"
  if [ -d "$ROOT/node_modules" ]; then
    COUNT=0
    while IFS= read -r pj; do
      [ -z "$pj" ] && continue; COUNT=$((COUNT+1))
      scan_package_json "$pj" "$(rel "$pj")"
    done < <(find "$ROOT/node_modules" -maxdepth 3 -type f -name package.json 2>/dev/null | head -n 5000)
    emit INFO "installed-tree" "node_modules" "$COUNT top-level package manifest(s) inspected (nested node_modules not inspected)"
  else
    emit GAP "installed-tree" "node_modules" "not present: install-time scripts of dependencies were NOT inspected (only the lockfile checks below ran)"
  fi
fi

# ---- 2. lockfile provenance ------------------------------------------------------------------
while IFS= read -r lf; do
  [ -z "$lf" ] && continue; RECOGNISED=1; L="$(rel "$lf")"
  case "$lf" in
    */package-lock.json)
      res="$(grep -c -E '"resolved"[[:space:]]*:' "$lf" 2>/dev/null || true)"
      integ="$(grep -c -E '"integrity"[[:space:]]*:' "$lf" 2>/dev/null || true)"
      [ "${res:-0}" -gt "${integ:-0}" ] && emit REVIEW "lockfile-integrity" "$L" "$((res-integ)) resolved entr(ies) have no integrity hash"
      n="$(grep -E '"resolved"[[:space:]]*:' "$lf" | grep -v -E '"https://registry\.(npmjs\.org|yarnpkg\.com)/' | wc -l | tr -d ' ')"
      [ "$n" -gt 0 ] && emit REVIEW "lockfile-source" "$L" "$n entr(ies) resolve outside the public npm registry (git, tarball URL or private mirror): confirm each is expected"
      grep -q -E '"resolved"[[:space:]]*:[[:space:]]*"http://' "$lf" && emit INDICATOR "lockfile-insecure-source" "$L" "package fetched over plain http"
      ;;
    */pnpm-lock.yaml)
      n="$(grep -c -E 'tarball:|resolution:[[:space:]]*\{[^}]*(commit|repo):' "$lf" 2>/dev/null || true)"
      [ "${n:-0}" -gt 0 ] && emit REVIEW "lockfile-source" "$L" "$n entr(ies) use a direct tarball or git source: confirm each is expected"
      ;;
    */yarn.lock)
      n="$(grep -E '^[[:space:]]+resolved ' "$lf" | grep -v -E 'registry\.(npmjs\.org|yarnpkg\.com)/' | wc -l | tr -d ' ')"
      [ "$n" -gt 0 ] && emit REVIEW "lockfile-source" "$L" "$n entr(ies) resolve outside the public npm registry"
      ;;
  esac
  # recent history of the lockfile (read-only git)
  if [ -d "$ROOT/.git" ] && have git; then
    export GIT_OPTIONAL_LOCKS=0
    G=(git -C "$ROOT" -c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.ext.allow=never)
    st="$("${G[@]}" status --porcelain -- "${lf#"$ROOT"/}" 2>/dev/null | head -n 1)"
    [ -n "$st" ] && emit REVIEW "lockfile-uncommitted" "$L" "has uncommitted changes: compare with 'git diff' before installing"
    "${G[@]}" log -n 5 --format='%h %ad %s' --date=short -- "${lf#"$ROOT"/}" 2>/dev/null | while IFS= read -r h; do
      printf 'INFO\tlockfile-history\t%s\t%s\n' "$L" "$(printf '%s' "$h" | mask)"
    done
  elif [ -d "$ROOT/.git" ]; then
    emit GAP "lockfile-history" "$L" "git is not available: lockfile change history and uncommitted changes were NOT checked"
  fi
done < <(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \) -print 2>/dev/null | head -n 20)
if [ -n "$PJ_LIST" ] && ! find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock \) -print 2>/dev/null | grep -q .; then
  emit REVIEW "no-lockfile" "$(rel "$ROOT")" "package.json without a lockfile: installs are not reproducible"
fi

# ---- 3. CI/CD workflows ----------------------------------------------------------------------
WF="$(find "$ROOT/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | head -n 50)"
if [ -n "$WF" ]; then
  RECOGNISED=1
  while IFS= read -r w; do
    [ -z "$w" ] && continue; W="$(rel "$w")"
    grep -n -E '^[[:space:]]*pull_request_target\b|^[[:space:]]*-[[:space:]]*pull_request_target\b|on:.*pull_request_target' "$w" 2>/dev/null | cut -d: -f1 | while read -r n; do
      printf 'REVIEW\tworkflow-pull-request-target\t%s:%s\tpull_request_target runs with secrets: confirm it never checks out or executes PR code\n' "$W" "$n"; done
    grep -n -E '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^./[:space:]][^@[:space:]]*/[^@[:space:]]+@' "$w" 2>/dev/null | while IFS=: read -r n rest; do
      ref="$(printf '%s' "$rest" | sed -E 's/.*@([^[:space:]#]+).*/\1/')"
      act="$(printf '%s' "$rest" | sed -E 's/.*uses:[[:space:]]*([^@[:space:]]+)@.*/\1/')"
      printf '%s' "$ref" | grep -q -E '^[0-9a-f]{40}$' && continue
      case "$act" in actions/*|github/*) lvl=INFO ;; *) lvl=REVIEW ;; esac
      printf '%s\tworkflow-unpinned-action\t%s:%s\t%s is pinned to a mutable ref, not a commit SHA\n' "$lvl" "$W" "$n" "$act"
    done
    grep -n -E 'permissions:[[:space:]]*write-all|(contents|packages|id-token|actions):[[:space:]]*write' "$w" 2>/dev/null | cut -d: -f1 | while read -r n; do
      printf 'INFO\tworkflow-write-permission\t%s:%s\tgrants write access: confirm it is needed for this job\n' "$W" "$n"; done
    grep -n -E 'npm[[:space:]]+publish|pnpm[[:space:]]+publish|twine[[:space:]]+upload|docker[[:space:]]+push' "$w" 2>/dev/null | cut -d: -f1 | while read -r n; do
      printf 'INFO\tworkflow-publishes\t%s:%s\tpublishes artifacts: review who can trigger this\n' "$W" "$n"; done
    grep -n -E '(curl|wget)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh' "$w" 2>/dev/null | cut -d: -f1 | while read -r n; do
      printf 'INDICATOR\tworkflow-download-and-execute\t%s:%s\tpipes a download into a shell\n' "$W" "$n"; done
    grep -n -E '\$\{\{[[:space:]]*github\.(head_ref|event\.(issue|pull_request|comment|review|head_commit|pages)[^}]*\.(title|body|message|name|ref|label))' "$w" 2>/dev/null | cut -d: -f1 | while read -r n; do
      printf 'REVIEW\tworkflow-expression-injection\t%s:%s\tuntrusted event field interpolated into a workflow: use an environment variable instead\n' "$W" "$n"; done
    grep -n -E 'echo[^#]*\$\{\{[[:space:]]*secrets\.' "$w" 2>/dev/null | cut -d: -f1 | while read -r n; do
      printf 'INDICATOR\tworkflow-secret-echo\t%s:%s\ta secret is interpolated into an echo\n' "$W" "$n"; done
  done <<<"$WF" >"${TMPDIR:-/tmp}/.sci.$$" 2>&1
  # the pipelines above ran in subshells; recount from their output
  while IFS= read -r l; do
    case "$l" in INDICATOR*) N_IND=$((N_IND+1)) ;; REVIEW*) N_REV=$((N_REV+1)) ;; INFO*) N_INFO=$((N_INFO+1)) ;; esac
    printf '%s\n' "$l"
  done <"${TMPDIR:-/tmp}/.sci.$$"
  rm -f "${TMPDIR:-/tmp}/.sci.$$"
fi

# ---- 4. Docker --------------------------------------------------------------------------------
DF="$(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( -name 'Dockerfile*' -o -name '*.Dockerfile' \) -print 2>/dev/null | head -n 20)"
if [ -n "$DF" ]; then
  RECOGNISED=1
  while IFS= read -r d; do
    [ -z "$d" ] && continue; D="$(rel "$d")"
    while IFS=: read -r n line; do
      ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+).*/\2/')"
      case "$ref" in scratch|'') continue ;; esac
      case "$ref" in
        *@sha256:*) ;;
        *)
          tag=""; case "${ref##*/}" in *:*) tag="${ref##*:}" ;; esac
          if [ -z "$tag" ]; then emit REVIEW "image-floating" "$D:$n" "$ref has no tag (defaults to latest)"
          elif [ "$tag" = "latest" ]; then emit REVIEW "image-floating" "$D:$n" "$ref uses :latest"
          else emit INFO "image-unpinned" "$D:$n" "$ref is tag-only, not digest-pinned"; fi ;;
      esac
    done < <(grep -n -i -E '^[[:space:]]*FROM[[:space:]]' "$d" 2>/dev/null)
    scan_dockerfile_hits="$(grep -n -E '(curl|wget)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh|^[[:space:]]*ADD[[:space:]]+https?://' "$d" 2>/dev/null | cut -d: -f1 | tr '\n' ' ')"
    [ -n "$scan_dockerfile_hits" ] && emit REVIEW "docker-remote-fetch-and-run" "$D" "downloads remote content at build time (lines: ${scan_dockerfile_hits}): pin and verify checksums"
  done <<<"$DF"
fi

# ---- summary ----------------------------------------------------------------------------------
[ "$RECOGNISED" -eq 1 ] || emit GAP "nothing-to-inspect" "$(rel "$ROOT")" "no package.json, lockfile, workflow or Dockerfile found under PATH: is PATH the repository root?"
echo
echo "SUMMARY indicators=$N_IND review=$N_REV info=$N_INFO gaps=$N_GAP"
FLAGGED=0
case "$FAIL_ON" in indicator) [ "$N_IND" -gt 0 ] && FLAGGED=1 ;; review) [ $((N_IND+N_REV)) -gt 0 ] && FLAGGED=1 ;; esac
echo "NOTE    INFO lines (for example an existing postinstall script) are context, not accusations. Absence of indicators does not prove a repository or its dependencies are clean."
if [ "$FLAGGED" -eq 1 ]; then echo "RESULT  FLAGGED for human review"; exit 10
elif [ "$N_GAP" -gt 0 ]; then echo "RESULT  INCOMPLETE: not flagged, but coverage gaps mean this is not a clean result"; exit 20
fi
echo "RESULT  nothing flagged at level '$FAIL_ON' within the checks above"
exit 0
