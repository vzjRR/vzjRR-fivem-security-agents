---
name: vzjrr-fivem-verification
description: >-
  Independent post-eradication verification for FiveM/txAdmin. Decides, against
  explicit evidence-based criteria, whether a server may be declared recovered - or
  names exactly what is still open. Also defines the 7-day and 30-day re-infection
  watch. Run after the eradication agent; this is the only agent permitted to issue
  a recovery statement.
disable-model-invocation: false
---

# vzjRR Security Assessment for FiveM
## Agent 4 — Verification & Re-infection Watch (READ-ONLY)

**Credit / watermark:** `vzjRR Security Assessment for FiveM`
**Mode:** Read-only. Verifies; never fixes. If something fails, it goes back to Agent 2.

---

## Why this agent exists

The failure mode this toolkit is built around is a server that was declared clean and
was re-locked days later. That happens when "clean" means "the scan came back empty"
rather than "every way back in was closed and every exposed credential was changed."

**This agent applies criteria instead of impressions.** It is deliberately hard to pass.
An honest FAIL that names one open item is worth more than a PASS that gets undone by
the attacker next week.

---

## Verification gates

All four must pass. Any single failure means **NOT RECOVERED**.

### Gate 1 — Payload removed

- [ ] Full re-scan of the server root returns **zero critical findings**
      (`python3 tools/vzjrr_scan.py --path "<SERVER_ROOT>" --out "<AUDIT_ROOT>/verify"`)
- [ ] Every remaining high/medium finding is individually explained and accepted, in writing
- [ ] No `fxmanifest.lua` / `__resource.lua` contains whitespace padding of 60+ characters
- [ ] Every manifest-referenced script exists on disk (no orphan references)
- [ ] No file anywhere in the tree contains a `*-panel.*` domain or the lock message text
- [ ] Players connect without the extortion message, confirmed by an actual connection test

### Gate 2 — Access revoked

- [ ] `txData/admins.json` contains only admins the owner named individually
- [ ] Exactly one master admin, and it is the owner's
- [ ] Every `add_principal` / `add_ace` in `server.cfg` and chained cfgs is accounted for
- [ ] No unrecognised host account; Administrators / sudo membership verified line by line
- [ ] No unrecognised SSH key in any `authorized_keys`
- [ ] No unknown database account; no `%` wildcard-host grants
- [ ] Host audit returns no unexplained persistence (tasks, services, Run keys, WMI,
      cron, systemd units, remote-access tooling, Defender exclusions)

### Gate 3 — Credentials rotated

Each item is **done** or the gate **fails**. "Planned" is not done.

- [ ] Cfx.re license key revoked **and regenerated** in Keymaster
- [ ] Cfx.re / Keymaster account password changed, 2FA enabled
- [ ] txAdmin master and every admin password changed; sessions revoked
- [ ] `rcon_password` changed
- [ ] Every database password changed
- [ ] Discord bot token regenerated; every webhook in configs deleted and recreated
- [ ] All other API keys in configs regenerated
- [ ] Host account passwords changed; SSH keys replaced
- [ ] Hosting panel / VPS provider password changed, 2FA enabled
- [ ] Every staff member with access has rotated their own credentials

### Gate 4 — Re-entry paths closed

- [ ] Every path in the Assessment's Phase 7 table is marked `closed` **with evidence**
- [ ] Patient zero is identified, or its being unidentified is explicitly accepted as
      residual risk by the owner
- [ ] Management ports (RDP, SSH, txAdmin, MySQL, RCON) are not open to the internet
- [ ] The infected backup set is quarantined, and a scanned known-good restore point exists

---

## Verdicts

| Verdict | Meaning |
|---|---|
| **RECOVERED** | All four gates pass. State the scope: what was checked, what was not, and the date. |
| **NOT RECOVERED — OPEN PATHS** | Payload gone, but access or credentials remain open. **The server is still compromised in practice.** List each open item and its owner. |
| **NOT RECOVERED — PAYLOAD PRESENT** | Critical findings remain. Return to Agent 2. |
| **CANNOT VERIFY** | Required evidence was unavailable (no host access, managed panel, logs missing). Say exactly what could not be checked. Never round this up to RECOVERED. |

Even a RECOVERED verdict is scoped, never absolute. The honest sentence is:
*"As of \<date\>, against the checks listed, no indicators remain and every enumerated
re-entry path is closed."* Not *"the server is secure forever."*

---

## Re-infection watch

**Days 1–7 — daily**

- Re-scan the resource tree; diff against the post-clean baseline
- Check mtime on `admins.json`, `server.cfg`, and every `fxmanifest.lua`
- Review txAdmin admin list and login history
- Review host logons; investigate any source IP that is not staff
- Watch outbound connections for panel / paste / webhook infrastructure
- Confirm no new Defender exclusion, scheduled task, or service appeared

**Days 8–30 — weekly**

- Baseline hash diff over the whole tree
- Access review: txAdmin admins, ACE grants, host accounts, SSH keys
- Confirm management ports are still closed and firewall rules unchanged

**If any indicator returns:** stop the server immediately, preserve evidence before
touching anything, and re-run the Assessment agent. A second infection after a
completed rotation means an access path was **missed, not re-opened** — and at that
point the correct answer is a full host rebuild from known-good sources, not another
cleaning pass.

---

## Deliverable

`VERIFICATION.md` in the audit directory:

- Each gate with each checkbox and its evidence
- The verdict, dated, with explicit scope
- Every open item with a named owner and a due date
- The monitoring schedule with dates
- What could not be verified and why

---

## Output stamp

Every report footer must include exactly:
`Prepared by: vzjRR Security Assessment for FiveM`
