# Remediation: smallest safe fix, proven

Read this at Phase F and in `fix` mode. Default is **analysis only**: propose a fix and wait for approval before editing anything.

## Before touching code
1. Confirm the finding's status is Confirmed (or the user explicitly wants a defensive fix for a Strongly suspected one, and says so).
2. Obtain explicit approval for the files to be changed. Authentication, authorisation, database schema, production configuration, secrets, build/deploy settings and security-sensitive business logic need an explicit, specific yes. Do not slip them into a "while I was here" change.
3. Record the starting state: current branch, `git status`, staged/unstaged/untracked changes. Preserve all unrelated work. Never use `git reset`, `git clean`, `git stash`, destructive checkouts or broad reverts. If the working tree already holds changes, work around them and report which files you touched.
4. Run the existing relevant tests first to learn the baseline (what already fails).

## Designing the fix
- **Fix the root cause at the right layer.** Prefer the central control (data-layer access rule, shared middleware, parameterised query, safe API) over per-call patches. Fail closed: when the input or state is unexpected, deny.
- **Smallest change** that closes the demonstrated attack and its siblings (the same flaw on the other paths you identified: bulk endpoints, restore/duplicate flows, alternative routes).
- **Preserve intended behaviour.** List what legitimate workflows must still work and test them.
- **No weakening.** Do not loosen another control to make a fix or test pass. Do not disable checks, add broad `catch` blocks that swallow errors, use `as any` or ignore type errors.
- **No new dependencies** without approval; do not upgrade versions as a side effect.
- **Do not hide the symptom.** Returning 200 for a missing resource, catching and discarding an authorisation error, or filtering the output without fixing the access path is not a fix.
- **Defence in depth where cheap**: validation at the boundary plus encoding at the sink; authorisation in the data layer plus the UI.
- **Secrets**: removal from code is not remediation; the credential must be rotated by its owner. Never rotate or revoke on your own.

## Common fix patterns
| Weakness | Fix |
| --- | --- |
| Missing authorisation | Enforce at the data/service layer; deny by default; test every actor and every route to the resource, including bulk and generated endpoints |
| IDOR | Scope every query by the caller's identity or tenant; do not rely on obscure ids |
| SQL/NoSQL injection | Parameterised queries; allow-list dynamic identifiers; reject object-typed input where a scalar is expected |
| XSS | Context-correct output encoding; avoid raw HTML sinks; escape `<` in JSON embedded in script tags; sanitise with a maintained library at the sink; add a CSP as defence in depth |
| SSRF | Allow-list destinations; resolve and validate the IP after redirects; block internal ranges; do not return raw responses |
| Path traversal | Allow-list file names; resolve and verify containment in the root after decoding; refuse separators |
| Upload | Allow-list types by sniffed content; generated names; size limits; serve with `nosniff` and a sandboxing CSP, ideally from another origin |
| JWT/session | Pin algorithm; strong secret from the environment; validate `exp/aud/iss`; revoke sessions server-side |
| Race condition | Atomic operation, unique index or transaction covering the whole check-and-act |
| Cache/host issues | Include the varying input in the cache key; one trusted normalisation point; ignore untrusted forwarding headers |
| LLM agency | Least-privilege tools, server-side authorisation inside tools, human confirmation for destructive actions, treat model output as untrusted |

## Proving the fix
1. **Regression test first.** Write the test that fails on the vulnerable code (record the red result), covering the original attack plus the variants identified. Add a test that the legitimate workflow still works.
2. Apply the fix. Run the new test (green), then the **relevant existing suites** (access control, publishing, media, the area touched), the type checker, and the build when safe.
3. Re-run the relevant scanner(s) and compare with the baseline; do not claim a scanner "passes" if it was unavailable.
4. **Inspect the diff**: only intended files; no formatting churn; no debug code; no secrets; no unrelated changes; line endings preserved.
5. Report: root cause, change summary, exact diff (or file list), tests run with commands and results, tests not run and why, residual risk, follow-ups that need the owner's decision (migrations, rotation, configuration, architecture).

## Out of scope without explicit approval
Deploying; changing production environment variables or infrastructure; database migrations or bulk updates; deleting data; seeding; credential rotation; dependency upgrades; rewriting history. Stop and ask.

## Residual risk statement
Always end with what the fix does **not** address: other instances not yet found, assumptions about deployment, unverified paths, data that may already have been exposed.
