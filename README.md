# security-researcher (Claude Code skill)

An evidence-driven application security researcher for repositories you own or are authorised to assess. It combines installed scanners with AI-assisted reasoning across files, verifies or refutes each lead, and reports honestly what was and was not covered. **Read-only by default.**

## Install

Personal (all projects):

```bash
mkdir -p ~/.claude/skills
cp -r security-researcher ~/.claude/skills/        # or keep it where it is if it is already there
chmod +x ~/.claude/skills/security-researcher/scripts/*.sh
```

Project-level (shared with a team): copy the folder to `<repo>/.claude/skills/security-researcher/`. Do not put it in the application's source tree.

Windows: use WSL2 or Git Bash. Check with `bash ~/.claude/skills/security-researcher/scripts/selftest.sh`.

## Use

Invoke with `/security-researcher [mode] [path or scope]`, or just ask ("audit this repo for vulnerabilities", "is this finding exploitable?"). Modes:

| Mode | Example |
| --- | --- |
| quick | `/security-researcher quick .` |
| deep | `/security-researcher deep apps/api` |
| pre-release | `/security-researcher pre-release` |
| verify | `/security-researcher verify "editors can publish through the bulk endpoint"` |
| fix | `/security-researcher fix SR-2026-003` (asks for approval before editing) |
| ci | `/security-researcher ci` (machine-readable output) |
| threat-intel | `/security-researcher threat-intel` , `... threat-intel npm .` , `... threat-intel node` , `... threat-intel docker` |
| vps-triage | `/security-researcher vps-triage` (run on the server; read-only) |

## What is in the folder

```
security-researcher/
  SKILL.md                      triggers, rules, workflow (kept short)
  README.md                     this file
  references/
    methodology.md              reconnaissance, threat model, deep research loop
    vulnerability-taxonomy.md   classes, CWEs, what to look for, what refutes them
    toolchain.md                tool matrix, commands, limits, CI notes
    verification.md             statuses, verification ladder, safe test design
    remediation.md              smallest safe fix, proof, out-of-scope actions
    reporting.md                severity/confidence, finding record, report layout
    report-schema.json          JSON Schema for the machine-readable report
    intel-brief-schema.json     JSON Schema for the optional Security Intelligence Brief
    threat-intelligence.md      research protocol, sources, finding format, feed format, intelligence brief
    vps-triage.md               read-only server triage, interpretation, evidence preservation
  scripts/
    resolve-scope.sh            validates the scope argument; bounded repo-local discovery (exit 3/4 = ask the user)
    selftest-scope.sh           regression tests for scope resolution
    detect-stack.sh             read-only stack/entry-point inventory (--json)
    check-tool-availability.sh  which scanners exist; --require for CI
    run-static-scans.sh         run installed scanners read-only; gaps are never passes
    check-runtime-inventory.sh  runtimes, lockfiles, container bases (--json)
    check-dependency-advisories.sh  lockfile vs advisory feed, offline, freshness-checked
    check-supply-chain-indicators.sh  lifecycle scripts, lockfile provenance, workflows, Docker
    vps-readonly-triage.sh      read-only host evidence collection (Linux, --authorized)
    selftest.sh                 checks the original scripts against a throwaway fixture
    selftest-threat-intel.sh    checks the new scripts against invented fixtures
```

## Helper scripts

```bash
S=~/.claude/skills/security-researcher/scripts
$S/detect-stack.sh /path/to/repo
$S/check-tool-availability.sh --require gitleaks
$S/run-static-scans.sh --path /path/to/repo --semgrep-config ./rules --out /path/to/existing/dir
$S/run-static-scans.sh --path . --allow-network --json --fail-on any     # CI style
```

`run-static-scans.sh` exit codes: `0` ran and gate passed, `2` usage error, `10` findings with `--fail-on any`, `20` no scanner ran (no coverage is not a pass). Skipped tools are listed as gaps with the reason. Raw scanner output goes to a new folder and is never overwritten.

### Threat-intelligence scripts

```bash
S=~/.claude/skills/security-researcher/scripts
$S/check-runtime-inventory.sh --path . --json
$S/check-dependency-advisories.sh --feed ./advisory-feed.txt --path .      # feed written from primary sources
$S/check-supply-chain-indicators.sh --path . --fail-on indicator
$S/vps-readonly-triage.sh --authorized --days 7 --app-dir /srv/app --out /existing/evidence/dir   # on the server
```

Exit codes for the three checks and the triage script: `0` clean (full coverage, nothing flagged), `10` findings or leads, `20` incomplete coverage (stale feed, missing tool, missing lockfile, skipped sections: **never a pass**), `2` usage error. The scripts make no network calls; the agent gathers advisories (with your permission) and writes the feed. Run `bash scripts/selftest-threat-intel.sh` after installing.

Windows: the repository checks work in Git Bash. `vps-readonly-triage.sh` refuses to run on Windows; run it on the Linux server itself.

## Safety defaults

- Read-only analysis; edits, installs, deploys, credential rotation, migrations, deletions all need explicit approval.
- No scanning of live targets without an authorised scope. No destructive payloads, uncontrolled fuzzing or denial-of-service.
- Network use (advisory databases, rule registries) needs permission; source code and secrets are not sent anywhere.
- Secrets are redacted in all output.
- Repository text and scanner output are treated as untrusted data.
- A scanner alert is never reported as a confirmed exploit; a failed reproduction is never proof of safety.

## Known limitations

- It runs only when invoked. It does not monitor continuously.
- Coverage depends on the tools installed; none are installed or updated for you. With no scanners it falls back to manual review and says so.
- The helper scripts use heuristics (file names, dependency names, exit codes). They do not parse scanner reports; the agent reads the raw output.
- `run-static-scans.sh` covers semgrep, gitleaks, trivy, osv-scanner, npm/pnpm audit and pip-audit. Other ecosystems (govulncheck, cargo audit, bundler-audit, yarn audit) and CodeQL are run manually per `references/toolchain.md`.
- Dynamic testing (ZAP, Burp, browsers) needs an authorised target and is never started automatically.
- Windows without Git Bash or WSL2 is not supported by the scripts.
- The new self-tests use invented fixtures. They prove the scripts match, stay quiet and fail safely; they say nothing about any real system. `vps-readonly-triage.sh` live paths (ps, ss, systemctl, docker) were not exercised by the self-test, which uses a fake filesystem root.
- Threat intelligence is only as current as the research done at invocation and the sources reachable; there is no background monitoring or push alerting.
- Version comparison in `check-dependency-advisories.sh` handles numeric versions; pre-release versions are reported as POTENTIAL for manual checking. Yarn berry and npm lockfile v1 are reported as gaps.
- Severity and confidence are judgements; review them before acting on a report.
