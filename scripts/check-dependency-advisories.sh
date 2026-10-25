#!/usr/bin/env bash
# check-dependency-advisories.sh - match lockfile versions against an advisory feed file, offline.
#
# Usage: check-dependency-advisories.sh --feed FILE [--path DIR] [--max-age-days N]
#
#   --feed FILE         advisory feed (format below). REQUIRED. This script never downloads anything:
#                       the agent assembles the feed from primary sources (see references/threat-intelligence.md)
#                       and the user can read it before it is used.
#   --path DIR          repository containing lockfiles (default: current directory)
#   --max-age-days N    the feed is STALE when older than N days (default 7, range 1-365)
#
# Feed format (UTF-8 text, one record per line, fields separated by "|"):
#   # retrieved: 2026-10-25T09:00:00Z            <- required header: when the intelligence was collected
#   ecosystem|package|constraint|id|published|source_url|note
#   npm|example-pkg|>=1.0.0,<1.4.2|GHSA-xxxx-xxxx-xxxx|2026-10-01|https://...|free text
# ecosystem: npm or pypi. constraint: comma-joined terms using =, <, <=, >, >= (all must hold).
#
# Reads lockfiles: package-lock.json (v2/v3), pnpm-lock.yaml, yarn.lock (v1), requirements*.txt (== pins).
# Anything it cannot parse is listed as a coverage gap, never skipped silently.
# Versions with pre-release/build parts (1.0.0-beta.1) cannot be ordered reliably by this script;
# a hit on one is reported as POTENTIAL and must be verified by hand.
# Feed content and lockfiles are untrusted input: they are only compared, never executed.
#
# A run with no match means "no match in THIS feed", not "not affected" and not "safe".
#
# Exit codes: 0 feed fresh, every lockfile parsed, no match; 2 usage error;
#             10 at least one match (takes priority over 20); 20 incomplete coverage
#             (stale/undated feed, no lockfile, unparsed lockfile, empty feed).

set -u
set -o pipefail

ROOT="."; FEED=""; MAXAGE=7
usage_error() { echo "check-dependency-advisories: $1" >&2; echo "Try --help." >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --feed) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--feed needs a value"; FEED="$2"; shift ;;
    --path) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--path needs a value"; ROOT="$2"; shift ;;
    --max-age-days) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--max-age-days needs a value"; MAXAGE="$2"; shift ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[ -n "$FEED" ] || usage_error "--feed is required (this script does not fetch advisories)"
[ -f "$FEED" ] && [ -r "$FEED" ] || usage_error "feed is not a readable file: $FEED"
case "$MAXAGE" in ''|*[!0-9]*) usage_error "--max-age-days must be a whole number" ;; esac
{ [ "$MAXAGE" -ge 1 ] && [ "$MAXAGE" -le 365 ]; } || usage_error "--max-age-days must be between 1 and 365"
[ -d "$ROOT" ] && [ -r "$ROOT" ] || usage_error "not a readable directory: $ROOT"
ROOT="$(cd "$ROOT" && pwd)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/dep-adv-XXXXXX")" || usage_error "could not create a temporary folder"
trap 'rm -rf "$TMP"' EXIT
GAPS=0; MATCHES=0
gap() { GAPS=$((GAPS+1)); echo "GAP     $*"; }
clean() { tr -d '\000-\010\013-\037' <<<"$1" | cut -c1-300; } # strip control characters from untrusted text

# ---- feed freshness ----------------------------------------------------------------
to_epoch() { # ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ" -> epoch seconds, or empty
  local s="$1" e
  e="$(date -u -d "$s" +%s 2>/dev/null)" && { printf '%s' "$e"; return; }
  e="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$s" +%s 2>/dev/null)" && { printf '%s' "$e"; return; }
}
echo "# Dependency advisory match   (run $(date -u +%Y-%m-%dT%H:%M:%SZ))"
RETR="$(sed -n -E 's/^#[[:space:]]*retrieved:[[:space:]]*([0-9T:Z-]+)[[:space:]]*$/\1/p' "$FEED" | head -n 1)"
if [ -z "$RETR" ]; then
  gap "feed has no '# retrieved: <ISO-8601 UTC>' header, so its freshness is unknown. Treat it as not current."
else
  NOW="$(date -u +%s)"; THEN="$(to_epoch "$RETR")"
  if [ -z "$THEN" ]; then gap "feed retrieval time '$(clean "$RETR")' could not be parsed; freshness unknown."
  elif [ "$THEN" -gt $((NOW+300)) ]; then gap "feed retrieval time is in the future ($RETR); freshness cannot be trusted."
  else
    AGE=$(( (NOW-THEN) / 86400 ))
    if [ "$AGE" -gt "$MAXAGE" ]; then gap "feed is STALE: retrieved $RETR, ${AGE} day(s) old (limit ${MAXAGE}). Refresh from primary sources before calling this current intelligence."
    else echo "FEED    retrieved $RETR (${AGE} day(s) old, limit ${MAXAGE})"; fi
  fi
fi
grep -v -E '^[[:space:]]*(#|$)' "$FEED" | tr -d '\r' >"$TMP/feed"
NFEED="$(wc -l <"$TMP/feed" | tr -d ' ')"
[ "$NFEED" -gt 0 ] || gap "feed contains no advisory records."
BAD="$(awk -F'|' 'NF<6 || $1!~/^(npm|pypi)$/' "$TMP/feed" | wc -l | tr -d ' ')"
[ "$BAD" -gt 0 ] && gap "$BAD feed line(s) are malformed or use an unsupported ecosystem and were ignored."
awk -F'|' 'NF>=6 && $1~/^(npm|pypi)$/' "$TMP/feed" >"$TMP/feed.ok"
echo "FEED    $(wc -l <"$TMP/feed.ok" | tr -d ' ') usable record(s)"

# ---- lockfile parsing ---------------------------------------------------------------
: >"$TMP/deps"   # eco|name|version|lockfile
LOCKS="$(find "$ROOT" -maxdepth 4 \( -name node_modules -o -name .git -o -name vendor -o -name .venv -o -name venv \) -prune -o -type f \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name 'requirements*.txt' \) -print 2>/dev/null | head -n 30)"
[ -n "$LOCKS" ] || gap "no supported lockfile found under $ROOT (looked for package-lock.json, pnpm-lock.yaml, yarn.lock, requirements*.txt)."
while IFS= read -r lf; do
  [ -z "$lf" ] && continue
  rel="${lf#"$ROOT"/}"; before="$(wc -l <"$TMP/deps" | tr -d ' ')"
  case "$lf" in
    */package-lock.json)
      awk -v lock="$rel" '
        {
          rest=$0
          if (match($0, /"(node_modules\/)+[^"]+"[[:space:]]*:[[:space:]]*\{/)) {
            k=substr($0, RSTART+1); sub(/".*/, "", k); n=k; sub(/^.*node_modules\//, "", n); pend=n
            rest=substr($0, RSTART+RLENGTH)
          }
          if (pend!="" && match(rest, /"version"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
            v=substr(rest, RSTART, RLENGTH); sub(/^"version"[[:space:]]*:[[:space:]]*"/, "", v); sub(/"$/, "", v)
            print "npm|" pend "|" v "|" lock; pend=""
          }
        }' "$lf" >>"$TMP/deps" ;;
    */pnpm-lock.yaml)
      sed -n -E "s#^  ['\"]?/?(@?[^@[:space:]'\"]+)@([0-9][^:(['\"[:space:]]*)[^:]*['\"]?:[[:space:]]*\$#npm|\1|\2|$rel#p" "$lf" | sort -u >>"$TMP/deps" ;;
    */yarn.lock)
      if grep -q -E '^__metadata:' "$lf" 2>/dev/null; then gap "$rel is a yarn berry lockfile; not parsed by this script."; continue; fi
      awk -v lock="$rel" '
        /^[^ #].*:[[:space:]]*$/ { h=$0; sub(/^"/, "", h); sub(/@.*/, "", h)
          if (substr($0,1,2)=="\"@" || substr($0,1,1)=="@") { h=$0; sub(/^"/, "", h); h=substr(h,2); sub(/@.*/, "", h); h="@" h }
          name=h; next }
        name!="" && /^  version / { v=$2; gsub(/"/, "", v); print "npm|" name "|" v "|" lock; name="" }' "$lf" >>"$TMP/deps" ;;
    */requirements*.txt)
      sed -n -E "s#^[[:space:]]*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^]]*\])?[[:space:]]*==[[:space:]]*([0-9][A-Za-z0-9.!+_-]*).*#pypi|\1|\3|$rel#p" "$lf" 2>/dev/null \
        | awk -F'|' '{ n=tolower($2); gsub(/[_.]/, "-", n); print $1 "|" n "|" $3 "|" $4 }' >>"$TMP/deps"
      grep -q -E '^[[:space:]]*[A-Za-z0-9][^=#]*(>=|~=|<|>)' "$lf" 2>/dev/null && gap "$rel contains unpinned requirements; only '==' pins can be matched."
      ;;
  esac
  after="$(wc -l <"$TMP/deps" | tr -d ' ')"
  if [ "$after" -eq "$before" ]; then gap "$rel yielded no packages (empty, unsupported format, or lockfile v1)."
  else echo "LOCK    $rel: $((after-before)) package version(s) read"; fi
done <<<"$LOCKS"
sort -u "$TMP/deps" -o "$TMP/deps"
# normalise python names in the feed the same way
awk -F'|' 'BEGIN{OFS="|"} { if ($1=="pypi") { n=tolower($2); gsub(/[_.]/, "-", n); $2=n } print }' "$TMP/feed.ok" >"$TMP/feed.norm"

# ---- version comparison (sort -V based) ------------------------------------------------
vcmp() { # prints -1, 0, 1 for $1 <=> $2
  [ "$1" = "$2" ] && { echo 0; return; }
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ] && echo -1 || echo 1
}
satisfies() { # version, constraint -> 0 yes, 1 no, 2 cannot decide
  local v="$1" c="$2" term op ref r
  case "$v" in *[!0-9.]*) return 2 ;; esac
  local IFS=','
  for term in $c; do
    term="${term// /}"
    case "$term" in
      '>='*) op=">="; ref="${term#>=}" ;; '<='*) op="<="; ref="${term#<=}" ;;
      '>'*) op=">"; ref="${term#>}" ;; '<'*) op="<"; ref="${term#<}" ;;
      '='*) op="="; ref="${term#=}" ;; *) return 2 ;;
    esac
    case "$ref" in ''|*[!0-9.]*) return 2 ;; esac
    r="$(vcmp "$v" "$ref")"
    case "$op" in
      '>=') [ "$r" -ge 0 ] || return 1 ;; '<=') [ "$r" -le 0 ] || return 1 ;;
      '>') [ "$r" -gt 0 ] || return 1 ;; '<') [ "$r" -lt 0 ] || return 1 ;;
      '=') [ "$r" -eq 0 ] || return 1 ;;
    esac
  done
  return 0
}

# ---- join dependencies with the feed on ecosystem+package, then evaluate constraints ------
awk -F'|' -v OFS='|' '
  NR==FNR { key=$1 "|" $2; rec[key]=rec[key] "\n" $0; next }
  { key=$1 "|" $2; if (key in rec) { n=split(rec[key], a, "\n"); for (i=2;i<=n;i++) print $0 "\t" a[i] } }' \
  "$TMP/feed.norm" "$TMP/deps" >"$TMP/cands" 2>/dev/null
POTENTIAL=0
while IFS=$'\t' read -r dep adv; do
  [ -z "$dep" ] && continue
  IFS='|' read -r _e name ver lock <<<"$dep"
  IFS='|' read -r _e2 _n constraint id pub url note <<<"$adv"
  satisfies "$ver" "$constraint"; rc=$?
  if [ $rc -eq 0 ]; then
    MATCHES=$((MATCHES+1))
    echo "MATCH   $(clean "$name")@$(clean "$ver") in $lock  advisory=$(clean "$id") published=$(clean "$pub") affected='$(clean "$constraint")'"
    echo "        source=$(clean "$url")  note=$(clean "$note")"
  elif [ $rc -eq 2 ]; then
    POTENTIAL=$((POTENTIAL+1)); MATCHES=$((MATCHES+1))
    echo "POTENTIAL $(clean "$name")@$(clean "$ver") in $lock  advisory=$(clean "$id") affected='$(clean "$constraint")'  (non-numeric version or constraint: verify by hand)"
    echo "        source=$(clean "$url")"
  fi
done <"$TMP/cands"

echo
echo "SUMMARY packages=$(wc -l <"$TMP/deps" | tr -d ' ') feed_records=$(wc -l <"$TMP/feed.norm" | tr -d ' ') matches=$MATCHES (potential=$POTENTIAL) coverage_gaps=$GAPS"
if [ "$MATCHES" -gt 0 ]; then
  echo "RESULT  FINDINGS. Each MATCH is a lead: confirm the vulnerable code path is reachable and the fixed version before acting."
  exit 10
elif [ "$GAPS" -gt 0 ]; then
  echo "RESULT  INCOMPLETE. No match was found, but coverage gaps (above) mean this is NOT a clean result."
  exit 20
fi
echo "RESULT  no match in this feed. That is not proof of safety: the feed only contains what was collected."
exit 0
