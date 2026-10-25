#!/usr/bin/env bash
# vps-readonly-triage.sh - read-only collection of compromise-triage evidence on the Linux host it runs on.
#
# Usage: vps-readonly-triage.sh --authorized [--days N] [--app-dir DIR]... [--out DIR] [--root DIR]
#
#   --authorized    REQUIRED. Confirms the user owns this host or is explicitly authorised to examine it.
#   --days N        "recent change" window in days (default 7, range 1-90)
#   --app-dir DIR   an application/deployment directory to check for recent changes and .env permissions
#                   (repeatable). File CONTENTS of .env files are never read.
#   --out DIR       also save the report in a NEW file inside the existing DIR (mode 600) and print its SHA-256
#   --root DIR      read files below DIR instead of / (used for fixtures). Command-based sections (ps, ss,
#                   systemctl, docker...) are then reported as skipped, never as clean.
#
# Run it ON the server (for example over an SSH session you opened yourself). It does not connect anywhere.
# It only reads: it never kills, deletes, disables, restarts, rotates, chmods, edits firewall rules or installs.
# Every search is bounded (-xdev, shallow depth, head limits) so it cannot starve a small VPS.
# Output can contain usernames, IP addresses, paths and command lines. It is EVIDENCE: keep it private and
# redact before it goes into a report. Command lines are masked for common secret patterns, but masking is
# best effort. Key material and file contents of credential files are never printed.
#
# Each section says ok, denied (permission), unavailable (tool or file missing) or skipped. Anything other than
# ok is a coverage gap. A NOTABLE line is a lead for a human, not proof of compromise.
# Compare the host with its normal behaviour before concluding anything, and preserve evidence before acting.
#
# Exit codes: 0 every section collected and nothing notable; 2 usage error or unsupported platform;
#             10 at least one NOTABLE lead (takes priority over 20); 20 coverage gaps (not a clean result).

set -u
set -o pipefail
umask 077

AUTH=0; DAYS=7; OUT_BASE=""; ROOT="/"; APPDIRS=""
usage_error() { echo "vps-readonly-triage: $1" >&2; echo "Try --help." >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --authorized) AUTH=1 ;;
    --days) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--days needs a value"; DAYS="$2"; shift ;;
    --app-dir) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--app-dir needs a value"; APPDIRS="$APPDIRS
$2"; shift ;;
    --out) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--out needs a value"; OUT_BASE="$2"; shift ;;
    --root) [ $# -ge 2 ] && [ -n "${2:-}" ] || usage_error "--root needs a value"; ROOT="$2"; shift ;;
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
  shift
done
[ "$AUTH" -eq 1 ] || usage_error "refusing to run without --authorized (confirm you own or may examine this host)"
case "$DAYS" in ''|*[!0-9]*) usage_error "--days must be a whole number" ;; esac
{ [ "$DAYS" -ge 1 ] && [ "$DAYS" -le 90 ]; } || usage_error "--days must be between 1 and 90"
[ -d "$ROOT" ] && [ -r "$ROOT" ] || usage_error "--root is not a readable directory: $ROOT"
ROOT="$(cd "$ROOT" && pwd)"; R="${ROOT%/}"
LIVE=0; [ "$ROOT" = "/" ] && LIVE=1
if [ -n "$OUT_BASE" ]; then
  [ -d "$OUT_BASE" ] && [ -w "$OUT_BASE" ] || usage_error "--out folder must exist and be writable: $OUT_BASE (this script will not create it)"
  OUT_BASE="$(cd "$OUT_BASE" && pwd)"
fi
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
if [ "$LIVE" -eq 1 ]; then
  case "$UNAME_S" in
    Linux) ;;
    Darwin) echo "NOTE: macOS support is partial; many Linux-specific sections will be reported unavailable." >&2 ;;
    *) usage_error "live triage supports Linux (and partly macOS) only, not '$UNAME_S'. On Windows use WSL2 for a Linux host, or run this on the server itself." ;;
  esac
fi
APPDIRS="$(printf '%s\n' "$APPDIRS" | sed '/^$/d')"
while IFS= read -r d; do [ -z "$d" ] && continue; [ -d "$R$d" ] || [ -d "$d" ] || usage_error "--app-dir is not a directory: $d"; done <<<"$APPDIRS"

have() {
  case " ${SECRESEARCHER_DISABLE_TOOLS:-} " in *" $1 "*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}

REPORT="$(mktemp "${TMPDIR:-/tmp}/vps-triage-XXXXXX")" || usage_error "could not create a temporary file"
trap 'rm -f "$REPORT"' EXIT
GAPS=0; NOTABLES=0
w() { printf '%s\n' "$*" >>"$REPORT"; }
section() { w ""; w "== $1 =="; }
status() { # ok|denied|unavailable|skipped  text
  w "[$1] $2"
  case "$1" in ok) ;; *) GAPS=$((GAPS+1)) ;; esac
}
notable() { NOTABLES=$((NOTABLES+1)); w "NOTABLE: $*"; }
livecmd() { # tool ; returns 0 when a live command may run, else records why not
  if [ "$LIVE" -ne 1 ]; then status skipped "$1: not run (fixture --root; no live system was examined)"; return 1; fi
  if ! have "$1"; then status unavailable "$1: not installed"; return 1; fi
  return 0
}
cmd_to_report() { # description, then command...; records permission failures as denied
  local desc="$1"; shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q -i -E 'permission denied|operation not permitted|must be root'; then
    status denied "$desc: permission denied (re-run with the privileges you are authorised to use, or accept the gap)"
    return 1
  elif [ $rc -ne 0 ]; then status unavailable "$desc: failed (exit $rc): $(printf '%s' "$out" | head -n 1 | cut -c1-120)"; return 1
  fi
  status ok "$desc"; [ -n "$out" ] && printf '%s\n' "$out" | redact | sed 's/^/    /' >>"$REPORT"
  return 0
}
mtime() { stat -c '%y' "$1" 2>/dev/null | cut -d. -f1 || stat -f '%Sm' "$1" 2>/dev/null; }
ci() { local out="" c u i; for ((i=0;i<${#1};i++)); do c="${1:$i:1}"; u="$(printf '%s' "$c" | tr a-z A-Z)"; out="$out[$c$u]"; done; printf '%s' "$out"; }
SECRETWORDS="$(ci token)|$(ci passwd)|$(ci password)|$(ci secret)|$(ci apikey)|$(ci api_key)|$(ci api-key)|$(ci authorization)|$(ci bearer)|$(ci credential)"
redact() { sed -E "s/(($SECRETWORDS)[=: ]+)[^[:space:]]+/\\1****/g; s/(AKIA|ghp_|gho_|github_pat_|npm_|xox[bap]-|sk-)[A-Za-z0-9_-]{8,}/\\1****/g"; }
readable() { [ -r "$1" ]; }

w "# VPS read-only triage"
w "collected_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
w "mode: $([ "$LIVE" -eq 1 ] && echo LIVE || echo "FIXTURE root=$ROOT (not a live system)")"
w "window_days: $DAYS"
w "caveat: attackers can alter logs, binaries and command output. Absence of leads is not proof of a clean host."

# ---- 1. host ----------------------------------------------------------------------------------
section "host"
if [ "$LIVE" -eq 1 ]; then
  status ok "uname: $(uname -a 2>/dev/null)"
  status ok "user: $(id 2>/dev/null)"
  have uptime && status ok "uptime: $(uptime 2>/dev/null)"
else status skipped "uname/id/uptime: fixture root"; fi
if readable "$R/etc/os-release"; then status ok "os-release: $(sed -n 's/^PRETTY_NAME=//p' "$R/etc/os-release" | tr -d '"')"; else status unavailable "/etc/os-release not readable"; fi
if livecmd node; then status ok "node: $(cd / && node --version 2>&1 | head -n 1)"; fi
if livecmd pm2; then status ok "pm2 present (run 'pm2 ls' yourself; its JSON output is withheld because it embeds environment variables)"; fi

# ---- 2. accounts and keys ---------------------------------------------------------------------
section "accounts and SSH keys"
if readable "$R/etc/passwd"; then
  status ok "/etc/passwd read ($(wc -l <"$R/etc/passwd" | tr -d ' ') accounts)"
  EXTRA0="$(awk -F: '$3==0 && $1!="root" {print $1}' "$R/etc/passwd")"
  [ -n "$EXTRA0" ] && notable "additional UID 0 account(s): $(printf '%s' "$EXTRA0" | tr '\n' ' ')"
  w "login-capable accounts:"; awk -F: '$7!~/(nologin|false|sync|shutdown|halt)$/ && $7!="" {printf "    %s uid=%s home=%s shell=%s\n",$1,$3,$6,$7}' "$R/etc/passwd" >>"$REPORT"
  NOPW="$(awk -F: '$2=="" {print $1}' "$R/etc/shadow" 2>/dev/null | tr '\n' ' ')"
  [ -r "$R/etc/shadow" ] && [ -n "$NOPW" ] && notable "account(s) with an empty password field: $NOPW"
  [ -r "$R/etc/shadow" ] || status denied "/etc/shadow not readable (empty-password check not done)"
else status unavailable "/etc/passwd not readable"; fi
for f in etc/passwd etc/shadow etc/group etc/sudoers; do
  [ -e "$R/$f" ] && w "    mtime /$f: $(mtime "$R/$f")"
done
AK_COUNT=0
while IFS= read -r ak; do
  [ -z "$ak" ] && continue
  AK_COUNT=$((AK_COUNT+1))
  n="$(grep -c -E '^(ssh-|ecdsa-|sk-)' "$ak" 2>/dev/null || echo 0)"
  w "    authorized_keys: ${ak#"$R"} keys=$n mtime=$(mtime "$ak")"
  if have ssh-keygen; then ssh-keygen -lf "$ak" 2>/dev/null | awk '{print "        fingerprint " $2 " " $NF}' >>"$REPORT"; fi
  grep -q -E '(^|[ ,])command=' "$ak" 2>/dev/null && w "        (contains forced-command entries)"
  find "$ak" -mtime -"$DAYS" 2>/dev/null | grep -q . && notable "authorized_keys modified within $DAYS day(s): ${ak#"$R"}"
done < <(find "$R/root/.ssh" "$R/home" -maxdepth 3 -name authorized_keys -type f 2>/dev/null | head -n 50)
status ok "authorized_keys files inspected: $AK_COUNT (key material not printed)"
if [ -d "$R/etc/sudoers.d" ]; then
  w "    sudoers.d: $(ls -1 "$R/etc/sudoers.d" 2>/dev/null | tr '\n' ' ')"
  find "$R/etc/sudoers.d" -type f -mtime -"$DAYS" 2>/dev/null | grep -q . && notable "sudoers.d changed within $DAYS day(s)"
fi

# ---- 3. processes -----------------------------------------------------------------------------
section "processes"
if livecmd ps; then
  cmd_to_report "process tree (pid ppid user elapsed command, secrets masked)" ps -eo pid,ppid,user,etime,args --sort=ppid,pid
  if [ -d /proc ]; then
    SUS=""
    for p in /proc/[0-9]*; do
      exe="$(readlink "$p/exe" 2>/dev/null)" || continue
      case "$exe" in
        *"(deleted)"*|/tmp/*|/var/tmp/*|/dev/shm/*) SUS="$SUS ${p#/proc/}:$exe" ;;
      esac
    done
    [ -n "$SUS" ] && notable "process(es) running from deleted or temporary executables:$SUS" || w "    no process runs from /tmp, /var/tmp, /dev/shm or a deleted binary (as far as /proc was readable)"
  else status unavailable "/proc not available"; fi
fi

# ---- 4. network -------------------------------------------------------------------------------
section "network"
if [ "$LIVE" -eq 1 ] && have ss; then
  cmd_to_report "listening sockets (ss -tulpn)" ss -H -tulpn
  cmd_to_report "established TCP connections (first 60)" bash -c "ss -H -tnp state established 2>&1 | head -n 60"
elif [ "$LIVE" -eq 1 ] && have netstat; then cmd_to_report "listening sockets (netstat)" netstat -tulpn
elif [ "$LIVE" -eq 1 ] && have lsof; then cmd_to_report "listening sockets (lsof)" bash -c "lsof -nP -iTCP -sTCP:LISTEN 2>&1 | head -n 60"
else status "$([ "$LIVE" -eq 1 ] && echo unavailable || echo skipped)" "no socket tool (ss, netstat, lsof) usable here"; fi
if readable "$R/etc/ld.so.preload"; then notable "/etc/ld.so.preload exists (loads libraries into every process; uncommon on a normal host)"; fi

# ---- 5. persistence ---------------------------------------------------------------------------
section "persistence"
if livecmd systemctl; then
  cmd_to_report "enabled systemd unit files" systemctl list-unit-files --state=enabled --no-pager --no-legend
  cmd_to_report "systemd timers" systemctl list-timers --all --no-pager --no-legend
fi
if [ -d "$R/etc/systemd/system" ]; then
  RECENT_UNITS="$(find "$R/etc/systemd/system" -maxdepth 2 -type f -name '*.service' -mtime -"$DAYS" 2>/dev/null | head -n 30)"
  if [ -n "$RECENT_UNITS" ]; then notable "systemd unit file(s) changed in the last $DAYS day(s): $(printf '%s' "$RECENT_UNITS" | sed "s#$R##" | tr '\n' ' ')"; else w "    no /etc/systemd/system service file changed in the last $DAYS day(s)"; fi
fi
CRONFILES="$(find "$R/etc/crontab" "$R/etc/cron.d" "$R/etc/cron.hourly" "$R/etc/cron.daily" "$R/var/spool/cron" "$R/var/spool/cron/crontabs" -maxdepth 1 -type f 2>/dev/null | head -n 80)"
if [ -n "$CRONFILES" ]; then
  status ok "cron files present: $(printf '%s\n' "$CRONFILES" | wc -l | tr -d ' ')"
  while IFS= read -r cf; do
    [ -z "$cf" ] && continue
    w "    ${cf#"$R"} (mtime $(mtime "$cf"))"
    grep -v -E '^[[:space:]]*(#|$)' "$cf" 2>/dev/null | redact | cut -c1-200 | sed 's/^/        /' >>"$REPORT"
    find "$cf" -mtime -"$DAYS" 2>/dev/null | grep -q . && notable "cron file changed within $DAYS day(s): ${cf#"$R"}"
    grep -q -i -E '(curl|wget)[^|;&]*\|[[:space:]]*(ba|z)?sh|/dev/tcp/|base64[[:space:]]+-d' "$cf" 2>/dev/null && notable "cron entry downloads/decodes and runs content: ${cf#"$R"}"
  done <<<"$CRONFILES"
else status unavailable "no cron files readable"; fi
[ -f "$R/etc/rc.local" ] && w "    /etc/rc.local exists (mtime $(mtime "$R/etc/rc.local"))"

# ---- 6. authentication logs -------------------------------------------------------------------
section "authentication history"
AUTHLOG=""
for c in var/log/auth.log var/log/secure; do readable "$R/$c" && { AUTHLOG="$R/$c"; break; }; done
if [ -n "$AUTHLOG" ]; then
  status ok "using ${AUTHLOG#"$R"} (log retention limits what this can show; rotated logs are not read)"
  w "    failed password attempts: $(grep -c -E 'Failed password' "$AUTHLOG" 2>/dev/null || echo 0)"
  w "    successful logins (user, method, source) - top 15:"
  grep -E 'Accepted (password|publickey|keyboard-interactive)' "$AUTHLOG" 2>/dev/null \
    | sed -E 's/.*Accepted ([a-z-]+) for ([^ ]+) from ([^ ]+).*/\2 \1 \3/' | sort | uniq -c | sort -rn | head -n 15 | sed 's/^/        /' >>"$REPORT"
  w "    sudo commands (last 15, masked):"
  grep -E 'sudo:.*COMMAND=' "$AUTHLOG" 2>/dev/null | tail -n 15 | redact | cut -c1-220 | sed 's/^/        /' >>"$REPORT"
  grep -q -E 'Accepted password for root' "$AUTHLOG" 2>/dev/null && notable "successful password login for root recorded"
else
  if livecmd journalctl; then cmd_to_report "sshd journal (last 40 lines)" bash -c "journalctl -u ssh -u sshd --no-pager -n 40 2>&1"; fi
  status unavailable "no readable auth.log or secure file"
fi
if livecmd last; then cmd_to_report "recent logins (last -n 15)" last -n 15 -w; fi

# ---- 7. filesystem ----------------------------------------------------------------------------
section "filesystem (bounded searches)"
for t in tmp var/tmp dev/shm; do
  [ -d "$R/$t" ] || continue
  EX="$(find "$R/$t" -xdev -maxdepth 3 -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) 2>/dev/null | head -n 30)"
  HID="$(find "$R/$t" -xdev -maxdepth 2 -name '.*' ! -name '.' ! -name '..' ! -name '.X*' ! -name '.ICE*' ! -name '.font*' 2>/dev/null | head -n 30)"
  if [ -n "$EX" ]; then notable "executable file(s) in /$t: $(printf '%s' "$EX" | sed "s#$R##" | tr '\n' ' ')"; else w "    no executable files in /$t (depth 3)"; fi
  [ -n "$HID" ] && w "    hidden entries in /$t: $(printf '%s' "$HID" | sed "s#$R##" | tr '\n' ' ')"
done
if [ -d "$R/etc" ]; then
  w "    /etc files changed in the last $DAYS day(s) (depth 2, first 40):"
  find "$R/etc" -xdev -maxdepth 2 -type f -mtime -"$DAYS" 2>/dev/null | head -n 40 | sed "s#$R#        #" >>"$REPORT"
fi
while IFS= read -r ad; do
  [ -z "$ad" ] && continue
  base="$ad"; [ -d "$R$ad" ] && base="$R$ad"
  w "    app dir ${ad}: files changed in the last $DAYS day(s), excluding node_modules/.git/.next (first 40):"
  find "$base" -xdev -maxdepth 4 \( -name node_modules -o -name .git -o -name .next \) -prune -o -type f -mtime -"$DAYS" -print 2>/dev/null | head -n 40 | sed "s#^$R#        #" >>"$REPORT"
  while IFS= read -r ef; do
    [ -z "$ef" ] && continue
    perm="$(stat -c '%a %U:%G' "$ef" 2>/dev/null || stat -f '%Lp %Su:%Sg' "$ef" 2>/dev/null)"
    w "        env file ${ef#"$R"} perms=$perm (contents NOT read)"
    case "${perm%% *}" in *[2367]) notable "env file is world-accessible: ${ef#"$R"} ($perm)" ;; esac
  done < <(find "$base" -xdev -maxdepth 3 -name node_modules -prune -o -type f -name '.env*' -print 2>/dev/null | head -n 20)
done <<<"$APPDIRS"
status ok "filesystem searches completed (bounded; not a full-disk scan)"

# ---- 8. packages ------------------------------------------------------------------------------
section "package changes"
if readable "$R/var/log/apt/history.log"; then
  status ok "apt history (last 25 lines)"; tail -n 25 "$R/var/log/apt/history.log" | cut -c1-220 | sed 's/^/    /' >>"$REPORT"
elif [ "$LIVE" -eq 1 ] && have rpm; then cmd_to_report "recent rpm installs" bash -c "rpm -qa --last 2>&1 | head -n 20"
else status unavailable "no readable apt history or rpm database"; fi
if livecmd npm; then cmd_to_report "global npm packages" bash -c "cd / && npm ls -g --depth=0 2>&1 | head -n 40"; fi

# ---- 9. containers ----------------------------------------------------------------------------
section "containers"
if livecmd docker; then
  if cmd_to_report "running containers" docker ps --format '{{.Names}}  image={{.Image}}  ports={{.Ports}}  status={{.Status}}'; then
    # environment variables are deliberately NOT requested
    INSPECT="$(docker ps -q 2>/dev/null | head -n 40 | xargs -r docker inspect -f '{{.Name}} image={{.Image}} privileged={{.HostConfig.Privileged}} netmode={{.HostConfig.NetworkMode}} user={{.Config.User}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null)"
    [ -n "$INSPECT" ] && printf '%s\n' "$INSPECT" | sed 's/^/    /' >>"$REPORT"
    printf '%s' "$INSPECT" | grep -q 'privileged=true' && notable "a running container is privileged"
    printf '%s' "$INSPECT" | grep -q -E 'docker\.sock' && notable "a running container mounts the Docker socket"
    printf '%s' "$INSPECT" | grep -q -E 'mounts=([^ ]*:[^ ]* )*/:' && notable "a running container mounts the host root"
    printf '%s' "$INSPECT" | grep -q 'netmode=host' && w "    note: at least one container uses host networking"
  fi
fi

# ---- output -----------------------------------------------------------------------------------
section "summary"
w "notable_leads: $NOTABLES"
w "coverage_gaps: $GAPS"
if [ "$NOTABLES" -gt 0 ]; then w "result: LEADS FOUND - review each NOTABLE line; they are not proof of compromise"
elif [ "$GAPS" -gt 0 ]; then w "result: INCOMPLETE - no leads in what was collected, but gaps mean this is not a clean result"
else w "result: no leads in the data collected - this does not prove the host is uncompromised"; fi
w "reminder: if compromise is plausible, preserve evidence (disk/memory snapshots, copies of logs) BEFORE containment, and decide containment with the owner. This script changed nothing."

cat "$REPORT"
if [ -n "$OUT_BASE" ]; then
  DEST="$OUT_BASE/vps-triage-$(date -u +%Y%m%dT%H%M%SZ).txt"
  [ -e "$DEST" ] && usage_error "refusing to overwrite $DEST"
  cp "$REPORT" "$DEST" && chmod 600 "$DEST" 2>/dev/null
  if have sha256sum; then echo "saved: $DEST  sha256=$(sha256sum "$DEST" | cut -d' ' -f1)"
  elif have shasum; then echo "saved: $DEST  sha256=$(shasum -a 256 "$DEST" | cut -d' ' -f1)"
  else echo "saved: $DEST  (no sha256 tool: integrity hash not recorded)"; fi
fi
[ "$NOTABLES" -gt 0 ] && exit 10
[ "$GAPS" -gt 0 ] && exit 20
exit 0
