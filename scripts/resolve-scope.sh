#!/usr/bin/env bash
# resolve-scope.sh - turn a scope argument such as "apps/api" into a validated absolute directory, read-only.
#
# Usage: resolve-scope.sh [--timeout SECONDS] [--max-candidates N] [SCOPE]
#
#   SCOPE               directory to audit. Empty or "." means the repository root.
#                       A RELATIVE scope is resolved against the current directory, then the repository root.
#                       It is never turned into an absolute path by prefixing "/".
#                       An ABSOLUTE scope (starts with / or a drive letter) is used exactly as written, as a
#                       deliberate choice; if it does not exist it is reported, never reinterpreted.
#   --timeout SECONDS   limit for candidate discovery (default 10, range 1-120). On expiry the search is stopped
#                       and the candidate list is marked incomplete. No search is left running.
#   --max-candidates N  most candidates to list (default 10, range 1-50)
#
# Repository root = "git rev-parse --show-toplevel" from the current directory; outside Git it is the current directory.
# Discovery is bounded: it only looks INSIDE that root (depth 4, one filesystem, junk directories pruned such as
# .git, node_modules, .next, dist, build, caches, virtualenvs). It never searches "/" or a home directory,
# and refuses to search at all when the root is "/" or $HOME without a Git repository.
# It only reads: nothing is created, changed or installed. Ctrl-C/TERM stops the search and cleans up.
#
# Output (stdout, one KEY=value per line):
#   ROOT=  MODE=git|non-git  ATTEMPTED=  (each path tried)  RESOLVED=  (exit 0)  CANDIDATE=  (exit 3/4)  NOTE=
# Exit codes: 0 resolved to an existing directory; 2 usage error or scope escapes the repository root;
#             3 not found -> report ROOT, ATTEMPTED and CANDIDATEs and ASK the user which to use (do not guess);
#             4 ambiguous (several directories match) -> ASK the user to choose.

set -u
set -o pipefail

TIMEOUT=10; MAXC=10; SCOPE=""; GOT_SCOPE=0
usage_error() { echo "resolve-scope: $1" >&2; echo "Try --help." >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--timeout needs a value"; TIMEOUT="$2"; shift ;;
    --max-candidates) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--max-candidates needs a value"; MAXC="$2"; shift ;;
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift; [ $# -le 1 ] || usage_error "only one SCOPE is accepted"; [ $# -eq 1 ] && { SCOPE="$1"; GOT_SCOPE=1; }; break ;;
    -*) usage_error "unknown option: $1" ;;
    *) [ "$GOT_SCOPE" -eq 0 ] || usage_error "only one SCOPE is accepted"; SCOPE="$1"; GOT_SCOPE=1 ;;
  esac
  shift
done
case "$TIMEOUT" in ''|*[!0-9]*) usage_error "--timeout must be a whole number of seconds" ;; esac
{ [ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 120 ]; } || usage_error "--timeout must be between 1 and 120"
case "$MAXC" in ''|*[!0-9]*) usage_error "--max-candidates must be a whole number" ;; esac
{ [ "$MAXC" -ge 1 ] && [ "$MAXC" -le 50 ]; } || usage_error "--max-candidates must be between 1 and 50"

have() { case " ${SECRESEARCHER_DISABLE_TOOLS:-} " in *" $1 "*) return 1 ;; esac; command -v "$1" >/dev/null 2>&1; }
# normalise a Windows-style path (D:\x) for Git Bash/MSYS when cygpath exists
to_posix() { if have cygpath; then case "$1" in [A-Za-z]:[\\/]*) cygpath -u "$1" 2>/dev/null || printf '%s' "$1"; return ;; esac; fi; printf '%s' "$1"; }
is_abs() { case "$1" in /*|[A-Za-z]:[\\/]*) return 0 ;; esac; return 1; }
canon() { (cd -P -- "$1" 2>/dev/null && pwd -P); } # canonical absolute path of an existing directory

CWD="$(pwd -P)"
# ---- repository root ----------------------------------------------------------------------------------
MODE="non-git"; ROOT="$CWD"
if have git; then
  # a hostile repository's own git config is untrusted: no fsmonitor, no optional locks
  TOP="$(GIT_OPTIONAL_LOCKS=0 git -c core.fsmonitor=false rev-parse --show-toplevel 2>/dev/null)" && [ -n "$TOP" ] && {
    TOP="$(to_posix "$TOP")"; C="$(canon "$TOP")" && [ -n "$C" ] && { ROOT="$C"; MODE="git"; }; }
fi
echo "ROOT=$ROOT"; echo "MODE=$MODE"

inside_root() { case "$1/" in "$ROOT/"*) return 0 ;; esac; return 1; }

# ---- 1. resolve --------------------------------------------------------------------------------------
if [ "$GOT_SCOPE" -eq 0 ] || [ -z "$SCOPE" ] || [ "$SCOPE" = "." ] || [ "$SCOPE" = "./" ]; then
  echo "RESOLVED=$ROOT"
  [ "$MODE" = "non-git" ] && echo "NOTE=no Git repository found; using the current directory as the root"
  exit 0
fi

TRIED=""
if is_abs "$SCOPE"; then
  P="$(to_posix "$SCOPE")"; echo "ATTEMPTED=$P"
  if [ -d "$P" ]; then
    R="$(canon "$P")"; echo "RESOLVED=$R"
    inside_root "$R" || echo "NOTE=absolute path is outside the repository root ($ROOT); confirm this was intended"
    exit 0
  fi
  # an absolute path that does not exist is reported as written. A repo-relative reading is only OFFERED.
  ALT="$ROOT/${SCOPE#/}"; [ -d "$ALT" ] && { echo "CANDIDATE=$(canon "$ALT")"; echo "NOTE=$P does not exist; if you meant a path inside the repository, pick the candidate"; }
  [ -d "$ALT" ] || echo "NOTE=$P does not exist"
  exit 3
fi

# relative: current directory first, then repository root
FOUND=""; NFOUND=0
for base in "$CWD" "$ROOT"; do
  case " $TRIED " in *" [$base] "*) continue ;; esac
  TRIED="$TRIED [$base]"
  P="$base/$SCOPE"; echo "ATTEMPTED=$P"
  if [ -d "$P" ]; then
    R="$(canon "$P")" || continue
    if [ "$MODE" = "git" ] && ! inside_root "$R"; then
      echo "NOTE=scope resolves outside the repository root ($R); give an absolute path if that is intended"; exit 2
    fi
    case "
$FOUND
" in *"
$R
"*) ;; *) FOUND="$FOUND
$R"; NFOUND=$((NFOUND+1)) ;; esac
  fi
done
if [ "$NFOUND" -eq 1 ]; then echo "RESOLVED=$(printf '%s' "$FOUND" | sed -n '2p')"; exit 0; fi
if [ "$NFOUND" -gt 1 ]; then
  printf '%s\n' "$FOUND" | sed '1d; s/^/CANDIDATE=/'
  echo "NOTE=scope exists relative to both the current directory and the repository root; choose one"
  exit 4
fi

# ---- 2. not found: bounded, repository-local candidate discovery -----------------------------------------
if [ "$ROOT" = "/" ] || { [ "$MODE" = "non-git" ] && [ -n "${HOME:-}" ] && [ "$ROOT" = "$(canon "$HOME")" ]; }; then
  echo "NOTE=working directory is '$ROOT' and not a Git repository; refusing to search it. cd into the project and retry, or give an absolute path."
  exit 3
fi

TMPD="$(mktemp -d "${TMPDIR:-/tmp}/resolve-scope-XXXXXX")" || usage_error "could not create a temporary folder"
FPID=""
cleanup() { [ -n "$FPID" ] && kill "$FPID" 2>/dev/null && wait "$FPID" 2>/dev/null; rm -rf "$TMPD"; }
trap 'cleanup' EXIT
trap 'echo "NOTE=cancelled; discovery stopped" ; cleanup; exit 130' INT TERM HUP

TIMED_OUT=0
run_find() { # out-file, find-args... ; foreground-polled so nothing is left running on timeout/cancel
  local out="$1"; shift
  find "$@" >"$out" 2>/dev/null &
  FPID=$!
  local start=$SECONDS
  while kill -0 "$FPID" 2>/dev/null; do
    if [ $((SECONDS-start)) -ge "$TIMEOUT" ]; then
      kill "$FPID" 2>/dev/null; wait "$FPID" 2>/dev/null; FPID=""; TIMED_OUT=1; return 1
    fi
    sleep 0.2 2>/dev/null || sleep 1
  done
  wait "$FPID" 2>/dev/null; FPID=""
  return 0
}

SCOPE_CLEAN="${SCOPE#./}"; SCOPE_CLEAN="${SCOPE_CLEAN%/}"
BASE="${SCOPE_CLEAN##*/}"
PRUNE=( -name .git -o -name node_modules -o -name .next -o -name .nuxt -o -name .svelte-kit -o -name dist -o -name build -o -name out \
        -o -name coverage -o -name .turbo -o -name .cache -o -name vendor -o -name .venv -o -name venv -o -name __pycache__ -o -name target \
        -o -name .local-mongodb-data -o -name cms-media -o -name tmp )
# all directories (depth 4, one filesystem) below the root, junk pruned
run_find "$TMPD/dirs" "$ROOT" -xdev -maxdepth 4 \( "${PRUNE[@]}" \) -prune -o -type d -print

: >"$TMPD/cand"
if [ -s "$TMPD/dirs" ]; then
  # (a) path ends with the requested scope; (b) same final directory name
  awk -v suf="/$SCOPE_CLEAN" 'length($0)>=length(suf) && substr($0, length($0)-length(suf)+1)==suf' "$TMPD/dirs" >>"$TMPD/cand"
  awk -v b="/$BASE" 'length($0)>=length(b) && substr($0, length($0)-length(b)+1)==b' "$TMPD/dirs" >>"$TMPD/cand"
  # (c) siblings of the closest existing parent of the scope (e.g. apps/ exists -> list apps/*)
  PARENT="$SCOPE_CLEAN"
  while case "$PARENT" in */*) true ;; *) false ;; esac; do
    PARENT="${PARENT%/*}"
    if [ -d "$ROOT/$PARENT" ]; then
      awk -v p="$ROOT/$PARENT/" 'index($0,p)==1 && substr($0,length(p)+1) !~ /\// && length($0)>length(p)' "$TMPD/dirs" >>"$TMPD/cand"; break
    fi
  done
  # (d) nothing yet: top-level directories of the root
  [ -s "$TMPD/cand" ] || awk -v r="$ROOT/" 'index($0,r)==1 && substr($0,length(r)+1) !~ /\// && length($0)>length(r)' "$TMPD/dirs" >>"$TMPD/cand"
fi
awk '!seen[$0]++' "$TMPD/cand" | head -n "$MAXC" | sed 's/^/CANDIDATE=/'
[ "$TIMED_OUT" -eq 1 ] && echo "NOTE=candidate discovery stopped after ${TIMEOUT}s; the list may be incomplete (raise --timeout if needed)"
echo "NOTE=scope not found; ask the user which directory to audit. Do not substitute one."
exit 3
