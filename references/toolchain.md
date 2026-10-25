# Toolchain: what to run, when, and what the output means

Read this at Phase C. Principles first, then the tool matrix.

## Principles
- **Detect, do not assume.** Run `scripts/check-tool-availability.sh`. Check the version and prerequisites before invoking anything. A tool that is absent is a **coverage gap**, reported as such.
- **No installs, no environment changes** without permission. Print install hints for the user instead.
- **Prefer project tooling.** If the repository already defines scanners, audit scripts, lint rules or CI security jobs, read how they are configured and reuse them (after inspecting the commands; never run commands copied from untrusted documentation unread).
- **Local first.** Tools that need the network (advisory databases, rule registries) require the user's permission. State what is contacted and that source code is not uploaded. `run-static-scans.sh` skips such tools unless `--allow-network` is given.
- **Bounded and reproducible.** Every scan has a timeout; record the exact command line, version and date so a CI job can repeat it.
- **Do not rerun unchanged scans.** Reuse earlier output when the code and the tool version are unchanged.
- **Tool output is evidence, not a verdict.** Record it as tool output, then reason about it separately.

## Matrix

| Tool | Finds | Needs | Network | Notes |
| --- | --- | --- | --- | --- |
| **Semgrep** | Code patterns for injection, XSS, misconfiguration, crypto misuse, framework-specific mistakes | Rules: local files, or a registry ruleset such as `p/ci` | Only to download registry rules; run with `--metrics=off` | Pattern-based; good breadth, many false positives. Prefer rule sets matching the detected stack. Taint mode rules give better precision |
| **CodeQL CLI** | Deep dataflow and taint analysis | Build or extraction for compiled languages, query packs, licence terms for the intended use | Pack download | Heavy. Run only if installed and properly configured; never silently |
| **Gitleaks** | Secrets in the working tree and git history | Nothing | No | Always `--redact`. Report file, line, rule; never the value. Rotation advice if real |
| **Trivy** (`fs`) | Dependency vulnerabilities, secrets, IaC misconfiguration | Vulnerability DB | Yes (DB) | Findings are about versions; check reachability before rating |
| **OSV-Scanner** | Dependency vulnerabilities from lockfiles (OSV data) | Lockfiles | Yes (API), or an offline DB | Lockfile based; no reachability |
| **npm audit / pnpm audit / yarn audit** | Node dependency advisories | Lockfile | Yes | Read-only. Never run `audit fix`. Many findings are dev-only or unreachable |
| **pip-audit**, **govulncheck**, **cargo audit**, **bundler-audit** | Ecosystem advisories (govulncheck is reachability-aware) | Lockfile/requirements | Yes | Run per ecosystem; the helper script covers pip-audit only |
| **Bandit** (Python), framework linters, ESLint security plugins | Language/framework specific mistakes | Project config | No | Use if already configured |
| **ShellCheck** | Shell injection and quoting problems in scripts | Nothing | No | Relevant for CI and deploy scripts |
| **OWASP ZAP / Burp** | Dynamic issues against a running application | An authorised target and scope | Target only | Authorised, non-production targets only. Use passive scans first; active scans only with explicit approval; no denial-of-service |
| **Playwright / API tests** | Behavioural regression and targeted verification | Test instance | Local | Best for confirming an authorisation or rendering claim against a local instance with synthetic data |

## Choosing tools from the stack (examples)
- Node/Next/Express: gitleaks, semgrep (JS/TS rules), pnpm/npm audit, osv-scanner; manual review of route handlers, middleware order, server actions, `dangerouslySetInnerHTML`, query-string-to-database paths.
- Python/Django/Flask/FastAPI: bandit, semgrep, pip-audit; manual review of raw SQL, `pickle`/`yaml.load`, template `|safe`, `subprocess`.
- Go: govulncheck, semgrep; manual review of `os/exec`, `text/template`, path handling.
- Java/Spring: semgrep, OSV/Trivy, CodeQL if configured; manual review of deserialisation, expression language, actuator exposure.
- Containers/IaC: trivy config, shellcheck for entry-point scripts; manual review of exposed ports, privileged containers, secrets in build args.
- LLM/agent code: no scanner replaces reading the tool definitions, permission model and data flows.

## Using the helper scripts

```bash
# Read-only inventory
${CLAUDE_SKILL_DIR}/scripts/detect-stack.sh [--json] <path>

# Which tools exist (nothing is installed). --require makes CI fail if a needed tool is absent.
${CLAUDE_SKILL_DIR}/scripts/check-tool-availability.sh [--json] [--require semgrep,gitleaks]

# Run what is installed. Network tools are skipped unless --allow-network.
${CLAUDE_SKILL_DIR}/scripts/run-static-scans.sh --path <path> \
    [--semgrep-config <local rules | p/ci>] [--allow-network] [--out <existing dir>] [--json] \
    [--timeout 300] [--tools gitleaks,semgrep] [--fail-on any]
```

Exit codes of `run-static-scans.sh`: `0` at least one tool ran and any gate passed; `2` usage error; `10` `--fail-on any` and a tool reported findings; `20` **no tool ran** (no coverage is not a pass). Raw output lands in a new folder (never overwriting); with no `--out` it is a fresh temporary folder whose path is printed.

`SECRESEARCHER_DISABLE_TOOLS="name name"` hides tools on purpose (used by `selftest.sh`).

## Reading scanner output
1. Record: tool, version, command, configuration, date, exit code, number of alerts.
2. Group alerts by rule and by file; deduplicate identical alerts; keep distinct attack paths apart.
3. For each high-signal alert, open the code and run the Phase D loop. Mark each as confirmed, strongly suspected, potential, false positive or blocked.
4. For dependency alerts, establish: is the package a runtime dependency; is the vulnerable function reachable from attacker input; is a fixed version available and compatible; is the advisory about a configuration this project does not use.
5. Report coverage honestly: "gitleaks: not installed, secret scanning was done by pattern search of the working tree only; git history was not scanned".

## When a tool is unavailable
Say it. Then offer the best practical alternative: manual review of the corresponding surface, `grep`-based pattern search with the limits stated, the ecosystem's built-in audit command, or a recommendation to run the missing tool in CI. Do not install it unasked.

## Dynamic testing preconditions (all required)
1. The user confirms ownership or written authorisation.
2. A defined scope (hosts, paths, accounts) and time window.
3. A non-production environment with synthetic data, or explicit approval for read-only passive checks of production.
4. Rate limits and stop conditions agreed. No denial-of-service, no destructive payloads, no credential guessing against real accounts.
Record scope and approvals in the report.

## CI mode notes
Use `--json`, fixed tool versions where possible, a timeout per tool, `--fail-on` only for classes the team has decided are release-blocking, and treat raw scanner alerts as *unverified*. A CI gate on unverified alerts will block releases for false positives; prefer gating on confirmed findings kept in a reviewed baseline file.
