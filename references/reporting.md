# Reporting

Read this when you write results. Be concise and evidence-rich. Separate Confirmed vulnerabilities, suspected issues, false positives and informational recommendations; never mix them in one list.

## Severity and confidence are two separate judgements

**Severity** (impact if it is real): start from CVSS 3.1 or 4.0 where it applies, then adjust for context and explain the adjustment in one or two sentences.
- Exposure: public internet, authenticated users only, internal network, local only.
- Privileges required and user interaction.
- Data sensitivity and blast radius (one user, one tenant, everyone).
- Existing controls that reduce exploitability or impact.
- Whether exploitation needs a precondition that is unlikely in practice.

| Severity | Typical meaning |
| --- | --- |
| Critical | Unauthenticated or low-effort compromise of confidentiality, integrity or availability at scale (remote code execution, full account takeover, mass data exposure, unauthorised publishing of arbitrary content) |
| High | Serious compromise needing some privilege or condition (privilege escalation, significant data exposure, stored XSS for administrators, SSRF reaching internal services) |
| Medium | Limited impact or significant preconditions (reflected XSS with interaction, information disclosure of low-sensitivity data, missing rate limits on sensitive actions) |
| Low | Minor impact or very hard to exploit |
| Info / Hardening | No demonstrated exploit; improves defence in depth |

**Confidence** (how sure you are the finding is real): High, Medium or Low, tied to the verification status. A Confirmed finding has high confidence by definition; a Potential one has low. Do not raise severity because confidence is high, or the reverse.

Do not inflate. If a finding needs an administrator account the attacker does not have, say so and rate accordingly.

Order of presentation: confirmed critical, confirmed high, plausible critical attack paths needing verification, important authorisation and business-logic flaws, medium and lower, hardening.

## Finding record (every field required; write "unknown" rather than guess)

```
ID:                 SR-<yyyy>-<nnn> (unique within the report)
Title:              one line, specific to this application
Classification:     class (+ CWE-<id>), and OWASP category if applicable (check the current edition)
Severity:           Critical | High | Medium | Low | Info   (+ CVSS vector if used, + context adjustment)
Confidence:         High | Medium | Low
Status:             Confirmed | Strongly suspected | Potential | Not reproducible | False positive | Blocked
Affected:           path:startLine-endLine (one or more)
Evidence:           the relevant code (short excerpt, secrets redacted), tool output clearly labelled as such
Entry point:        route / handler / job / input
Data flow:          source -> hop -> hop -> sink (files and functions)
Preconditions:      what must be true for exploitation
Attacker:           who, with what access or knowledge
Scenario:           concrete steps and effect
Impact:             what is gained, in this application's terms
Existing controls:  what is present and why it does / does not stop the attack
Counter-evidence:   what was checked that argues against the finding
Verification:       what was done, what was observed, what was not done and why
Reproduction:       steps or a safe test case (inert payloads; authorised scope only)
Remediation:        smallest safe fix and the root cause it addresses
Regression test:    what the test asserts and where it belongs
References:         primary sources (advisory, CVE record, OWASP, vendor doc) - only ones actually consulted
```

## Markdown report layout

1. **Executive summary** - what was assessed, the headline result in two or three sentences, counts by severity and status, release-blocking items, the single most important next step.
2. **Scope and exclusions** - repository and commit, branch, areas in scope, areas not reviewed, authorisation basis, environments touched (none for read-only analysis).
3. **Repository and technology overview** - stack, entry points, authentication model, data stores, infrastructure.
4. **Threat model** - assets, actors, trust boundaries, ranked abuse cases, assumptions and how each was checked.
5. **Tools executed** - table: tool, version, command/config, result, coverage notes; plus tools **not** available or skipped and why.
6. **Tests completed and skipped** - exact commands, environment, pass/fail counts; tests skipped and why.
7. **Findings by severity** - one finding record each; confirmed first.
8. **Evidence and verification status** - summary table: ID, severity, confidence, status.
9. **Attack-path analysis** - chains across components with the findings they combine.
10. **Remediation guidance** - grouped by root cause; sequencing; what needs owner decisions.
11. **Regression testing plan** - tests to add, where, and what they assert.
12. **Residual risks and limitations** - unexplored areas, unverified assumptions, tool gaps, time or scope limits.
13. **Recommended next actions** - prioritised, with which need approval.

Use separate sections for: Confirmed vulnerabilities; Suspected issues (Strongly suspected, Potential); Refuted (Not reproducible with conditions, False positive with reason); Blocked; Informational and hardening.

Keep the report truthful about what was *not* done. "No findings" must be accompanied by what was examined and what was not.

## Machine-readable report
Validate against `references/report-schema.json`. Required top-level fields: `schemaVersion`, `generatedAt`, `mode`, `scope`, `tools`, `testsRun`, `findings`, `limitations`. Each finding mirrors the record above with enumerated `severity`, `confidence` and `status`. CI consumers should gate on `status == "Confirmed"` (and chosen severities), never on unverified alerts.

Example (abridged):
```json
{
  "schemaVersion": "1.0",
  "generatedAt": "2026-01-01T00:00:00Z",
  "mode": "pre-release",
  "scope": { "repository": "example", "commit": "abc1234", "included": ["api/"], "excluded": ["infra/"] },
  "tools": [ { "name": "gitleaks", "version": "8.x", "status": "ran", "notes": "working tree only" } ],
  "testsRun": [ { "command": "node --test tests/authz.test.mjs", "result": "pass", "passed": 12, "failed": 0 } ],
  "findings": [ {
    "id": "SR-2026-001", "title": "Editors can overwrite published posts through the bulk endpoint",
    "classification": "Broken access control", "cwe": ["CWE-862"],
    "severity": "High", "confidence": "High", "status": "Confirmed",
    "affected": [ { "path": "cms/hooks/publishing.ts", "startLine": 34, "endLine": 48 } ],
    "remediation": "Refuse updates that are not explicit draft saves.",
    "regressionTest": "HTTP test: editor PATCH of a published doc returns 403 and the stored text is unchanged"
  } ],
  "limitations": [ "Dynamic testing not performed" ]
}
```

## Saving
Write a report to disk only when the user asks or has configured a location. Choose a new file name (include date and mode); never overwrite an existing report; do not write inside the application's source tree unless asked. Mention the path. Redact secrets and personal data. Do not publish or send the report anywhere without permission.

## Wording
Plain, specific, calibrated: "Confirmed: an editor can ... (test X returns 200 and the stored text changed)" and "Strongly suspected: ... not reproduced because no running instance was available". Avoid alarmist or marketing language. Credit uncertainty where it exists.
