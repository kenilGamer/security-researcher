# Verification: turning a lead into a defensible conclusion

Read this at Phase E and in `verify` mode.

## Statuses (use exactly these)

| Status | Meaning | Minimum evidence |
| --- | --- | --- |
| **Confirmed** | Direct evidence shows the security failure | A reproduced result (test or observed behaviour) **or** code evidence that leaves no plausible control on the path, with the path traced end to end |
| **Strongly suspected** | A credible attack path exists; exploitation not established | A traced path with a named missing/weak control and no discovered counter-evidence, but no reproduction |
| **Potential** | A suspicious pattern needing more investigation | The pattern and why it might matter; what is still unknown |
| **Not reproducible** | The proposed issue could not be reproduced under the tested conditions | The exact conditions tried. This is **not** proof of absence |
| **False positive** | Evidence shows the finding is not the claimed vulnerability | The specific control or fact that refutes it (file and line) |
| **Blocked** | Verification could not proceed | What was missing (tool, environment, permission, data) and what would unblock it |

Never report a scanner alert as Confirmed on the alert alone. Never treat a failed reproduction as proof of safety. Downgrade honestly when you find counter-evidence.

## Verification ladder (use the lowest rung that settles the question)

1. **Read and trace.** Follow the code path with search; list each control on it.
2. **Pure-logic test.** A unit test of the function or hook with crafted inputs; no server, no network.
3. **Local instance with synthetic data.** Start the application locally against a disposable database; send real requests (HTTP) from each actor (anonymous, low-privilege, other tenant, admin). This is the preferred way to confirm access-control claims.
4. **Browser test.** For XSS/CSRF/redirect/rendering claims, a headless browser against the local instance.
5. **Shared environment.** Only inside the authorised scope, only read-only or with synthetic accounts, with the user's explicit approval.
6. **Production.** Only passive, read-only observation with explicit approval. No exploit attempts.

## Safe test design
- Use a disposable data store; verify the connection target before writing (never print credentials); never point tests at production data.
- Use synthetic accounts and data. Random credentials generated per run, discarded afterwards.
- Make the test assert the security property ("an editor's PATCH of a published document returns 403 and the stored document is unchanged"), not just that a request returned some status.
- Cover the *bypass variants* you hypothesised: missing field, array/duplicate parameters, other method, bulk endpoint, legacy data, case/encoding variants, concurrency.
- Test both directions: the attack fails **and** the legitimate workflow still works (so a fix that breaks the feature is noticed).
- Prove the test can fail: run it against the unfixed code, or temporarily against a deliberately weakened copy, and record the red result before claiming the green one. If you cannot, say so.
- Keep payloads inert (marker strings, `window.__marker=1`, harmless file names). No destructive payloads, persistence or data exfiltration.
- Restore state afterwards (stop servers, delete temporary databases and folders) and report that you did.

## Seeking counter-evidence (do this before assigning Confirmed or Strongly suspected)
Check each: an upstream validator or framework default; a second authorisation layer (data layer, proxy, network); the input's type or encoding making the payload unusable; a feature flag or configuration that disables the path in the deployed environment; the route being unreachable from the stated actor; the sink being unreachable; the impact being limited to the attacker's own data; an existing test that already covers it. Record what you checked even when it found nothing.

## Preconditions and impact
State who the attacker is, what they need to know or hold (account, role, token, network position), and what they gain (data read, data changed, privilege, code execution, availability). Impact is what an attacker can realistically do, not the worst case a class name suggests.

## Dependency findings
Verify: runtime or development dependency; the installed version actually resolved by the lockfile; whether the vulnerable code path is reachable with attacker-influenced input; whether the advisory's preconditions exist here (specific configuration, platform, feature). Cite the advisory from a primary source (vendor advisory, CVE record, OSV/GHSA entry). If you could not check it, say "not verified".

## Secrets findings
Determine whether the value looks real or is a placeholder, where it lives (working tree, history, build output), whether it is reachable by the public (client bundle, public repository), and what it grants if you can tell without using it. **Never use a discovered credential to test it.** Recommend rotation when exposure is plausible, and history cleanup as a secondary step.

## Report the verification honestly
For every finding give: status; what you did; what you saw; what you did not do and why; what would raise or lower confidence. If a verification step failed or was skipped, the report says so.

## Verify-mode checklist (a single reported issue)
1. Restate the claim precisely (actor, action, expected unauthorised effect).
2. Locate the exact code path; list every control on it.
3. Look for counter-evidence.
4. Choose the lowest verification rung that can settle it; run it if authorised.
5. Conclude with a status, the evidence, and what remains uncertain.
6. If Confirmed, rate severity and suggest remediation and a regression test; do not patch without approval.
