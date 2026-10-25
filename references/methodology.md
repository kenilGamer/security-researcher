# Methodology: reconnaissance, threat model, deep research

Read this when you start Phase A. The goal is understanding the real application well enough to reason about attacks, not to fill a template.

## Phase A: reconnaissance

Order of work (stop early in quick mode):

1. **Orientation.** Run `scripts/detect-stack.sh`. Read `README`, `CLAUDE.md`/`AGENTS.md`, `SECURITY.md`, architecture and deployment docs, CI configuration. Note claims you will need to verify; documentation is evidence of intent, not of behaviour.
2. **Entry points.** List every way input arrives: HTTP routes and handlers, server actions, GraphQL, webhooks, WebSocket handlers, CLI arguments, message-queue consumers, cron jobs, file imports, email handlers, admin panels, framework-generated routes (for example an ORM/CMS that auto-creates REST endpoints).
3. **Identity and access.** Where identity is established (cookies, JWTs, API keys, SSO, sessions in a store), where it is checked (middleware, route guards, per-handler checks, database rules, framework access functions), and where it is *not* checked (internal routes, background jobs, GraphQL resolvers, auto-generated endpoints).
4. **Data stores and sinks.** Databases and query builders, file systems, object storage, caches, queues, search indexes, outbound HTTP clients, shell/process execution, template engines, deserialisers, `eval`-like facilities, LLM calls and tool execution.
5. **Infrastructure.** Reverse proxy and host/header handling, TLS termination, container and orchestrator configuration, environment and secret management, network exposure (what binds to which interface), CI/CD permissions, backups.
6. **Existing controls.** Input validation libraries, output encoding, CSP and security headers, CSRF protection, rate limiting, lockout, audit logging, dependency policies, existing security tests. Controls you find reduce risk only if they are on the path an attacker would use.
7. **Cross-check with reality.** Confirm at least the most important claims by reading the code that implements them.

Record: stack facts, entry-point list, auth model in two sentences, list of sinks, list of controls, and the questions you could not answer.

### Monorepo and multi-service notes
Treat each deployable unit as its own trust zone; map how they call each other and what each trusts about the other (shared secrets, internal headers such as `X-Forwarded-*`, service-to-service tokens, shared databases or queues). Trust placed in a header or network position is a recurring source of bypasses.

## Phase B: lightweight threat model

Produce a short document (a page or less, bullet form) with:

| Section | Content |
| --- | --- |
| Assets | What is worth attacking: credentials, personal data, payment data, unpublished content, source code, build pipeline, admin capabilities, availability |
| Actors and capabilities | Anonymous visitor; authenticated low-privilege user; a user of another tenant; editor vs administrator; compromised dependency; insider; attacker who controls content the app later processes (uploaded files, rich text, LLM inputs) |
| Trust boundaries | Browser to server, public host to admin host, app to database/queue/cache, app to third-party APIs, CI to production, LLM output to tool execution |
| Entry points | From Phase A, ranked by exposure |
| Privileged operations | Publish, delete, change roles, change settings, export data, run jobs, execute tools, manage secrets |
| Abuse cases | One sentence each, in terms of the attacker's goal ("a low-privilege editor makes unpublished edits public") |
| Assumptions to verify | Things the design relies on ("the proxy always sets Host", "role is never null") and how you will test each |

Prioritise by (likelihood x impact) for **this** application. A generic OWASP checklist is not a threat model. Prefer attack paths that cross a trust boundary or a privilege boundary.

STRIDE and attack-tree thinking are useful prompts: for each boundary ask what could be spoofed, tampered with, repudiated, disclosed, denied or elevated.

## Phase D: deep research technique

For each prioritised surface use this loop:

1. **Source.** Where does attacker-controlled data enter? Include indirect sources (stored values, headers, file names, metadata, query strings parsed into objects, JSON bodies with unexpected types, repeated parameters).
2. **Path.** Follow the value through every function and file until it reaches a sink. Use search to find callers and callees rather than guessing. Note every transformation: parsing, coercion, normalisation, decoding, truncation, case folding.
3. **Controls.** For each hop: is it validated, encoded, authorised, parameterised? Is the check performed on the same representation that is later used (time-of-check/time-of-use, check on decoded vs used on raw, check on one field and use of another)?
4. **Order.** Check middleware and hook order, early returns, error handlers that fail open, and framework behaviour that runs before your code (for example hooks that receive a different state than the stored one).
5. **Bypass search.** Ask what happens with: missing/null/duplicate/array/oversized values, different HTTP method, different content type, alternative route to the same function (REST vs GraphQL vs bulk endpoint vs admin UI vs background job), different case or encoding, concurrent requests, replay, a legacy record that predates a new field.
6. **Sibling comparison.** If one handler is protected, compare every sibling handler for the same resource. Missing authorisation is usually the one handler that differs from its siblings.
7. **Tests and config.** Existing tests show intended behaviour and often reveal what was never tested. Check production versus development configuration differences.
8. **Scenario.** Write: attacker, preconditions, steps, effect, what the attacker needs to know in advance.
9. **Counter-evidence.** Try to prove yourself wrong: an upstream filter, a framework default, a network restriction, a second authorisation layer, a type constraint, a feature flag. Record what you checked.
10. **Smallest safe verification.** Prefer reading code and a unit test; then a local instance with synthetic data; only then anything touching a shared environment, and only inside the authorised scope. See `verification.md`.

### Multi-step chains
Individual weaknesses that scanners rate as low can combine: for example a file upload that stores an attacker-chosen name, a public file route that serves by name, and a rich-text field that renders a link to it. When two findings share a component, ask whether one provides a precondition for the other. Report the chain as its own finding with its own severity and reference the parts.

### Interactions that deserve explicit attention
- Frontend validation that the backend does not repeat.
- Authorisation enforced in the UI, router or a cache layer but not in the data layer.
- Caches keyed without the user, tenant, host or role.
- Queues and workers that execute with broader privileges than the request that enqueued the job.
- Framework-generated endpoints that bypass custom controllers.
- Proxy and application disagreeing about host, path normalisation or header trust.
- Environment-specific guards (development open, production closed) that are mis-set in staging.
- Defaults applied on read (for example a schema default that changes the meaning of a missing legacy value).

## Stopping criteria
Stop a line of investigation when you have a confirmed finding with evidence, a refutation with evidence, or a blocker that needs the user (access, authorisation, environment). Stop the engagement when the high-risk paths from the threat model are each in one of those states, or the agreed time or scope is used up, and report the unexplored remainder honestly.
