---
name: vzjrr-fivem-hardening
description: >-
  Post-incident FiveM/txAdmin hardening: closes the attack surface that allowed the
  compromise so it cannot recur. Covers txAdmin and RDP/SSH exposure, admin hygiene,
  resource provenance and supply chain, database and secret handling, backups,
  logging and change detection. Run after eradication, or standalone on a healthy
  server as preventive work.
disable-model-invocation: false
---

# vzjRR Security Assessment for FiveM
## Agent 3 — Hardening & Prevention

**Credit / watermark:** `vzjRR Security Assessment for FiveM`
**Mode:** Configuration changes, with the owner's approval, on a server that has already been eradicated and rotated.

---

## Purpose

Eradication removes this intrusion. Hardening removes the *conditions* that allowed it.
A server that gets cleaned and left as it was will be compromised again, usually by the
same route, often within weeks.

Work through each control. For each, record: **current state → target state → done /
declined / not applicable**. A declined control is a decision the owner is entitled to
make; record it as an accepted risk rather than silently skipping it.

---

## 1. Attack surface

| Control | Target state |
|---|---|
| txAdmin web (40120) | Not exposed to the internet. VPN, IP allowlist, or authenticated reverse proxy with TLS. |
| RDP (3389) | Not internet-facing. VPN or IP allowlist. NLA on. Never the default Administrator name with a reused password. |
| SSH (22) | Key-only auth, `PermitRootLogin no`, `PasswordAuthentication no`, IP allowlist or VPN. |
| MySQL (3306) | Bound to `127.0.0.1`. No `%` wildcard-host accounts. |
| RCON | Disabled if unused; otherwise a long unique password, never internet-reachable. |
| Game ports (30120/30110) | The only ports that need to be publicly open. |
| Firewall default | Deny inbound by default; allow explicitly. |

**Internet-exposed RDP with a reused password is the single most common initial-access
route for compromised FiveM hosts.** If you fix one thing, fix that.

---

## 2. Identity and admin hygiene

- One master txAdmin admin. Every other admin is a named individual, never a shared login.
- Unique passwords everywhere. No credential is reused between txAdmin, RDP, the DB,
  the hosting panel, and Discord.
- 2FA on the Cfx.re/Keymaster account, the hosting provider, and Discord.
- Remove admin access the moment someone leaves the team — same day.
- Least privilege: FXServer does not need to run as Administrator or root.
- Quarterly review of `admins.json`, ACE grants, host accounts, and SSH keys.

---

## 3. Resource supply chain (this is where the infection came from)

This family's overwhelmingly common entry point is a leaked, cracked, or
escrow-bypassed resource installed by the owner.

- **Stop installing leaked resources.** There is no safe way to run a resource obtained
  from a leak site: the injected loader *is* the business model of those sites.
- Buy from Cfx.re's asset store or the developer directly; keep receipts and links.
- Before installing anything new, scan it **outside** the server:
  ```bash
  python3 tools/vzjrr_scan.py --path /staging/new-resource --out /audit/new-resource
  ```
- Read every `fxmanifest.lua` in full, with a grep for whitespace padding — do not
  trust a visual read.
- Record every resource's origin URL, version, and install date in an inventory file.
- Keep a hash baseline (below) so a later change stands out.

---

## 4. Secrets handling

- Move secrets out of `server.cfg` into a separate file that is `exec`'d and excluded
  from backups shared with third parties and from any git repository.
- Never paste `server.cfg` into a Discord support channel, a pastebin, or an AI chat
  without redacting the license key, DB password, RCON password and tokens first.
- Restrict filesystem permissions on config files to the service account.
- Rotate the license key and DB password on a schedule, and immediately whenever anyone
  with access leaves.

---

## 5. Backups you can actually restore from

- **Offline or immutable copies.** A backup on the same host that the attacker can
  reach and encrypt is not a backup.
- Keep enough history to reach *before* the intrusion window — this incident shows why:
  a 7-day retention would not have contained a known-good copy.
- **Scan every backup before restoring it.** Restoring an infected backup is a listed
  re-infection vector.
- Test a restore periodically. An untested backup is a hypothesis.

---

## 6. Change detection (so the next one is caught in hours, not weeks)

Create a hash baseline of the clean tree, and diff it on a schedule:

```bash
# Baseline, right after verification passes
python3 tools/vzjrr_scan.py --path "<SERVER_ROOT>" --out "<AUDIT_ROOT>/baseline"
find "<SERVER_ROOT>" -type f \( -name '*.lua' -o -name '*.js' -o -name '*.mjs' -o -name '*.cfg' \) \
  -exec sha256sum {} + | sort -k2 > "<AUDIT_ROOT>/baseline/hashes.txt"
```

```powershell
Get-ChildItem "<SERVER_ROOT>" -Recurse -Include *.lua,*.js,*.mjs,*.cfg |
  Get-FileHash -Algorithm SHA256 | Sort-Object Path |
  Export-Csv "<AUDIT_ROOT>\baseline\hashes.csv" -NoTypeInformation
```

Then schedule a weekly re-scan and diff, and alert on any change to `admins.json`,
`server.cfg`, or any `fxmanifest.lua`. Those three files change rarely and matter enormously.

---

## 7. Logging and monitoring

- Keep FXServer and txAdmin logs long enough to cover a slow-burn intrusion (90 days).
- Ship logs off-host — an attacker with host access edits local logs.
- Alert on: new txAdmin admin added, `admins.json` or `server.cfg` modified, a resource
  added or a manifest changed, failed-logon spikes, outbound connections to
  panel/paste/webhook infrastructure.
- Keep Windows Defender (or an equivalent) **enabled with no exclusions**, and treat any
  new exclusion as an incident in itself.

---

## 8. Host maintenance

- Patch the OS and FXServer artifacts on a schedule; run a supported artifact build.
- Remove software the server does not need — every extra service is attack surface.
- Do not browse the web, download resources, or open Discord on the game server host.
- Separate the database host from the game host if the budget allows.

---

## 9. Incident readiness

- Write down who to contact, where backups live, and how to take the server offline fast.
- Keep this toolkit and a known-good resource inventory somewhere **off** the server.
- Rehearse: if you had to rebuild from scratch tomorrow, how long would it take, and
  what would you be missing? Fix the gaps the answer reveals.

---

## Deliverable

`HARDENING_REPORT.md` in the audit directory: a table of every control with
current state, target state, action taken, and owner-accepted risks for anything
declined — plus a dated schedule for the recurring items (baseline diff, access review,
key rotation, restore test).

---

## Output stamp

Every report footer must include exactly:
`Prepared by: vzjRR Security Assessment for FiveM`
