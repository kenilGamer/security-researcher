#!/usr/bin/env bash
# check-runtime-inventory.sh - read-only inventory of runtimes, package managers and container bases.
#
# Usage: check-runtime-inventory.sh [--path DIR] [--json]
#
#   --path DIR   repository to inspect for lockfiles, engines and Dockerfiles (default: current directory)
#   --json       one JSON array of {section,key,value,status} objects on stdout
#
# Records WHAT IS INSTALLED and WHAT THE REPOSITORY DECLARES, so advisories can be matched against real
# versions. It judges nothing: it does not say a version is vulnerable.
# It runs only "<tool> --version" (from a neutral directory, so project-local shims are not picked up),
# reads a few manifest files, and never installs, builds, pulls images or writes anywhere.
# A tool that is missing is reported as "not-installed", never as "fine".
#
# Exit codes: 0 inventory produced (at least one item has status ok); 2 usage error;
#             20 nothing could be inventoried (no coverage).

set -u
set -o pipefail

JSON=0; ROOT="."
usage_error() { echo "check-runtime-inventory: $1" >&2; echo "Try --help." >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --path) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--path needs a value"; ROOT="$2"; shift ;;
    --json) JSON=1 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[ -d "$ROOT" ] || usage_error "not a directory: $ROOT"
[ -r "$ROOT" ] || usage_error "directory is not readable: $ROOT"
ROOT="$(cd "$ROOT" && pwd)"

# SECRESEARCHER_DISABLE_TOOLS="name name" hides tools on purpose (used by the self-tests).
have() {
  case " ${SECRESEARCHER_DISABLE_TOOLS:-} " in *" $1 "*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}

ROWS="$(mktemp "${TMPDIR:-/tmp}/runtime-inv-XXXXXX")" || usage_error "could not create a temporary file"
trap 'rm -f "$ROWS"' EXIT
TAB="$(printf '\t')"
row() { # section key value status
  local v="${3//$'\n'/ }"; v="${v//$'\r'/}"; v="${v//$TAB/ }"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$v" "$4" >>"$ROWS"
}

# ---- host ---------------------------------------------------------------------
row host os "$(uname -sr 2>/dev/null || echo unknown)" ok
row host arch "$(uname -m 2>/dev/null || echo unknown)" ok
if [ -r /etc/os-release ]; then
  row host distro "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"' | head -n 1)" ok
else
  row host distro "no /etc/os-release (not a typical Linux host, or not readable)" unavailable
fi
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) row host note "Windows shell: kernel and service data come from the emulation layer, not the host. Use WSL2 for Linux inventories." limitation ;;
esac

# ---- runtimes and package managers ----------------------------------------------
tool_version() { # tool, version-flag
  local t="$1" flag="${2:---version}" out
  if ! have "$t"; then row runtime "$t" "not installed or not on PATH" not-installed; return; fi
  out="$(cd / && "$t" $flag 2>&1 | head -n 1)"
  if [ -n "$out" ]; then row runtime "$t" "$out" ok; else row runtime "$t" "installed but printed no version" unavailable; fi
}
for t in node npm pnpm yarn bun python3 pip3 php composer go ruby java docker git; do
  case "$t" in java) tool_version java -version ;; go) tool_version go version ;; *) tool_version "$t" --version ;; esac
done

# ---- declared by the repository -------------------------------------------------
PRUNE=( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build -o -name vendor -o -name .venv -o -name venv )
found=0
for f in .nvmrc .node-version .python-version .tool-versions; do
  if [ -f "$ROOT/$f" ]; then row project "$f" "$(head -n 1 "$ROOT/$f" | cut -c1-80)" ok; found=1; fi
done
while IFS= read -r pj; do
  [ -z "$pj" ] && continue
  rel="${pj#"$ROOT"/}"
  eng="$(grep -E -m1 '"node"[[:space:]]*:' "$pj" 2>/dev/null | sed -E 's/^[[:space:]]*//' | cut -c1-80)"
  pm="$(grep -E -m1 '"packageManager"[[:space:]]*:' "$pj" 2>/dev/null | sed -E 's/^[[:space:]]*//' | cut -c1-80)"
  [ -n "$eng" ] && row project "$rel engines.node" "$eng" ok
  [ -n "$pm" ] && row project "$rel packageManager" "$pm" ok
  found=1
done < <(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f -name package.json -print 2>/dev/null | head -n 20)
while IFS= read -r lf; do
  [ -z "$lf" ] && continue
  row project "lockfile" "${lf#"$ROOT"/}" ok; found=1
done < <(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock -o -name bun.lockb -o -name composer.lock -o -name poetry.lock -o -name Pipfile.lock -o -name 'requirements*.txt' \) -print 2>/dev/null | head -n 30)
[ -d "$ROOT/node_modules" ] && row project "node_modules" "present (installed tree can be inspected)" ok || row project "node_modules" "absent (installed tree cannot be inspected)" not-present

# ---- container bases (text only; nothing is pulled) -------------------------------
image_row() { # file, line number, image reference
  local file="$1" n="$2" ref="$3" pin="tag-only"
  case "$ref" in *@sha256:*) pin="digest-pinned" ;; esac
  case "$ref" in *:latest|latest) pin="floating-latest" ;; esac
  case "$ref" in *[:@]*) ;; *) pin="no-tag(floating)" ;; esac
  row container "${file#"$ROOT"/}:$n" "$ref ($pin)" ok
}
while IFS= read -r df; do
  [ -z "$df" ] && continue
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+).*/\2/')"
    case "$ref" in scratch|'') continue ;; esac
    image_row "$df" "$n" "$ref"; found=1
  done < <(grep -n -i -E '^[[:space:]]*FROM[[:space:]]' "$df" 2>/dev/null | head -n 20)
done < <(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( -name 'Dockerfile*' -o -name '*.Dockerfile' \) -print 2>/dev/null | head -n 20)
while IFS= read -r cf; do
  [ -z "$cf" ] && continue
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*//; s/["'"'"']//g; s/[[:space:]]*#.*$//; s/[[:space:]]+$//')"
    [ -z "$ref" ] && continue
    image_row "$cf" "$n" "$ref"; found=1
  done < <(grep -n -E '^[[:space:]]*image:[[:space:]]*[^[:space:]]' "$cf" 2>/dev/null | head -n 30)
done < <(find "$ROOT" -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type f \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' \) -print 2>/dev/null | head -n 10)

OKS="$(awk -F'\t' '$4=="ok"' "$ROWS" | wc -l | tr -d ' ')"

# ---- output ---------------------------------------------------------------------
jesc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }
if [ "$JSON" -eq 1 ]; then
  printf '['
  first=1
  while IFS="$TAB" read -r a b c d; do
    [ $first -eq 0 ] && printf ','
    printf '{"section":"%s","key":"%s","value":"%s","status":"%s"}' "$(jesc "$a")" "$(jesc "$b")" "$(jesc "$c")" "$(jesc "$d")"
    first=0
  done <"$ROWS"
  printf ']\n'
else
  echo "# Runtime inventory for: $ROOT   (collected $(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "(tool output only. It says what is present, not whether it is vulnerable or safe.)"
  prev=""
  while IFS="$TAB" read -r a b c d; do
    [ "$a" != "$prev" ] && { printf '\n## %s\n' "$a"; prev="$a"; }
    printf -- '- %-34s %-14s %s\n' "$b" "[$d]" "$c"
  done <"$ROWS"
  [ "$found" -eq 0 ] && echo && echo "NOTE: no manifests, lockfiles or Dockerfiles were found under PATH. Is PATH the repository root?"
fi
[ "$OKS" -gt 0 ] || { echo "check-runtime-inventory: NO COVERAGE - nothing could be inventoried" >&2; exit 20; }
exit 0
