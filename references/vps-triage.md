# VPS triage (read-only)

For `vps-triage` mode: examining a Linux server the user owns or is explicitly authorised to examine, to decide whether compromise is plausible. Default is **read-only observation**.

## Preconditions

1. Ownership/authorisation confirmed in this conversation (ask the one minimum question if not).
2. The user runs the script on the server, or opens the session for you; you do not connect to hosts on your own initiative.
3. Production impact: the script is bounded (shallow `find`, `head` limits, no full-disk scans), but still tell the user it will run on a live system.

## Collect

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/vps-readonly-triage.sh --authorized --days 7 \
     --app-dir /srv/app --out /path/to/existing/evidence-dir
```

Sections: host, accounts and SSH keys, processes, network, persistence (systemd, timers, cron), authentication history, bounded filesystem checks (`/tmp`, `/var/tmp`, `/dev/shm`, `/etc`, app directories, `.env` permissions without contents), package changes, containers. Exit codes: `0` nothing notable and full coverage, `10` at least one NOTABLE lead, `20` coverage gaps, `2` usage error or unsupported platform.

Tool output is **evidence**; your interpretation is separate. Every section not marked `[ok]` is a gap: say which, and why (permission, missing tool, log rotated).

Windows cannot run this for a Linux server. Use the server's own shell, or WSL2 for a WSL host. macOS is partial.

## Interpret

A NOTABLE line is a lead, not a verdict. Compare with the host's normal behaviour (deploy tooling, backups, monitoring agents, provider images) before concluding. Typical reasoning:

| Lead | Benign explanations to rule out | Raises concern when |
| --- | --- | --- |
| Extra UID 0 account | Provider or imaging tooling | Created recently, unknown to owner, has SSH keys |
| `authorized_keys` changed in window | Owner rotated keys or deployed | Key unknown to the owner; forced commands; root's file |
| Executable in `/tmp`, `/dev/shm` | Package installers, build tools, node-gyp | Hidden name, running process, recent, outbound connections |
| Process from deleted binary or temp path | Package upgrade without restart | Not explained by a recent upgrade; network activity |
| New/changed systemd unit, timer, cron | Owner's deploy or config change | Fetches remote content, runs from temp/home, odd name mimicking a system unit |
| `/etc/ld.so.preload` present | Rare legitimate hardening/monitoring | Unknown library; recent; user-writable path |
| Successful root password login | Admin who has not disabled it | Unknown source address; follows brute-force failures |
| Privileged or socket-mounting container | Intentional (CI, monitoring) | Unexpected image, recent start, unknown digest |
| `.env` world-accessible | Misconfiguration | Any exposure plus evidence others read it |

Consider the Node.js app too: unexpected child processes of the Node/pm2 process, outbound connections from the app user, recently modified files in the deployment directory that do not match the deployed release, and `postinstall` activity during recent deploys (cross-check with `check-supply-chain-indicators.sh` on the release).

Attackers can edit logs, replace `ps`, `ss`, and `last`, and use rootkits. Output from a possibly compromised host can lie. Prefer comparing with an independent view (provider console, network flow logs, an offline disk image) when stakes are high.

## If compromise is plausible

1. **Preserve first.** Recommend snapshotting the disk/volume at the provider, saving volatile data (process list, connections) and copying logs to a safe place with hashes (the script prints a SHA-256 of a saved report). Do not clean up, reboot, or run "removal" tools before that.
2. **Scope.** Which accounts, keys, tokens, `.env` secrets, CI credentials, databases and other hosts were reachable from this machine? Which time window?
3. **Recommend containment; do not perform it.** Options for the owner to decide: isolate network (provider firewall/security group, not an in-host rule change), revoke/rotate credentials from a clean machine, rebuild from a known-good image and redeploy from a verified commit. State the trade-off of each (evidence loss, downtime).
4. **Never do automatically:** delete files, kill processes, change firewall rules, disable accounts, rotate secrets, restart or reboot services, uninstall packages. Each requires the owner's explicit approval, and evidence preservation comes before any of them.
5. Suspicious binaries or scripts: analyse **statically** (hashes, strings, readable script text) or in an isolated environment the user provides. Never execute them. Do not upload samples or private data to third-party services without approval.

## Report

Use the Security Intelligence Brief structure for threat context, and report triage as: scope, collection time and mode, sections collected / gapped, leads with evidence and benign explanations considered, confidence, preserved-evidence status, recommended containment (for the owner's decision), and what was not examined. Redact IP addresses, usernames and hostnames if the report leaves the machine.
