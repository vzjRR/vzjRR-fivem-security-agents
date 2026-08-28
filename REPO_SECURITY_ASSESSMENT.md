# Security Assessment of This Repository

**Scope:** `vzjRR/vzjRR-fivem-security-agents` at commit `f141dd0`, assessed 2026-08-28.
**Question asked:** is this toolkit itself safe, and why did a server cleaned with it get
re-infected by `blum-panel.me`?

**Summary:** no malicious code was found in this repository. The re-infection is explained
by **design gaps in the agents' scope**, not by anything hostile in the toolkit. Those gaps
are addressed by the changes in this branch.

---

## Part 1 — Is the repository itself malicious?

**No.** Every file was read in full.

| Item | Result |
|---|---|
| `agents/*/AGENT.md`, `agents/*/SKILL.md` | Prose instructions only. No executable content, no network calls, no prompt-injection or data-exfiltration patterns. |
| `README.md`, `USAGE_FOR_AI.md` | Documentation only. |
| `dist/unlock_and_materialize.py` (inside both zips) | Benign. Standard PBKDF2-HMAC-SHA256 (480k iterations) + Fernet decryption with an HMAC integrity check. **It correctly guards against zip-slip** — it rejects members with absolute paths or `..` components before extracting. It performs no network access and executes nothing it extracts. |
| `dist/*.zip` | Checksums in `dist/*.sha256` match the files as committed. |
| `dist/*/protected/agent.sealed` | Encrypted, as documented (magic `VZJR1`, ~6.0 bits/byte entropy over a base64 Fernet token). |
| `.gitignore` | Correctly excludes the unlock key, `.pem` files and `.env`. |
| Git history | Two commits, both consistent with the stated purpose. No secrets committed. |

### Finding R-1 — The sealed payload cannot be reviewed (Medium)

`protected/agent.sealed` is encrypted, so **nobody can audit its contents before running
it** — including the AI agent a user points at this repo, and including this assessment.
`MANIFEST.json` frames that opacity as a feature ("nobody can silently edit the sealed
core"). It cuts both ways: tamper-evidence protects against modification, but it also
means the code being materialized has never been read by the person running it.

This is the same trust structure — *run this opaque thing, trust the packaging* — that got
the server infected in the first place, via a leaked resource with a hidden loader.

**Recommendation:** ship the scanner tooling as readable source (this branch does: `tools/`
and `ioc/` are plain text). Keep sealed packages, if you want them at all, for
distribution convenience only — never as the sole form of the tooling.

### Finding R-2 — "Fetch this URL and follow it exactly" is a fragile trust model (Medium)

The README's primary workflow tells an AI agent to fetch a raw GitHub URL and follow it
exactly. That is convenient, and it means the instructions an agent obeys are whatever
that URL returns at that moment — with no pinning and no review step. Anyone who gains
write access to the repository, or to the account, changes the behaviour of every user's
next run silently.

**Recommendation:** pin to a tag or commit SHA rather than `main` in the documented URLs,
and tell users to read the agent file before running it. Enable branch protection and 2FA
on the GitHub account.

### Finding R-3 — The agents did not state their own limits (Low, fixed here)

The old agents implied a complete methodology while covering only part of the problem.
Nothing warned the user that a clean resource scan is not a clean server. The rewritten
agents state this explicitly and repeatedly, and `LIMITATIONS / NOT ASSESSED` is now a
required report section.

---

## Part 2 — Why the cleanup did not hold

This is the substantive finding. The old agents were competent within their scope; the
scope was the problem.

### Gap 1 — Scope was the resources folder (Critical)

The README's prompts said `Target path: PASTE_YOUR_FIVEM_OR_RESOURCES_PATH_HERE`, and the
agents worked from there. Host persistence was one optional line ("Persistence notes — host
read-only *if authorized*"), and identity was not covered at all.

But the things that let an attacker return almost never live in `resources/`:

- a txAdmin admin account in `txData/admins.json`
- an `add_principal` / `add_ace` grant in `server.cfg`
- a stolen Cfx.re license key
- RDP or SSH credentials
- a scheduled task, service, Run key, WMI subscription or cron job
- a local account added to Administrators

**A scan of `resources/` cannot see any of these.** Cleaning under that scope removes the
payload and leaves the attacker's way in.

**Fixed:** assessment now begins at the server root and runs a mandatory host and identity
audit (Phases 5 and 6), with real tooling behind both.

### Gap 2 — Credential rotation was a reminder, not a gate (Critical)

The old remediation agent ended with "Credential reminder (always include): rotate txAdmin,
rcon, license key, DB, Discord tokens, VPS/SSH."

That is the right list in the wrong form. It appears *after* the work, framed as advice, with
nothing depending on it. An agent could complete every step, emit the reminder, and report
success with the attacker still holding a valid license key and admin password.

**Fixed:** rotation is now a numbered gate with per-item completion tracking, the server is
not to be restarted publicly until it is complete, and the verification agent fails the
whole engagement if any item is outstanding.

### Gap 3 — No identity revocation step (Critical)

Nothing in the old execution order removed an attacker's txAdmin admin, ACE grant, database
account, host account, or SSH key. The whole execution order was file operations.

**Fixed:** Step 4 of the eradication agent is identity revocation across txAdmin, server.cfg,
the database, host accounts and SSH keys.

### Gap 4 — "Clean" had no definition (High)

The old agent said "re-scan after cleanup" without defining a passing result, and told the
agent not to claim the host was clean "without post-clean verification" — without saying what
verification meant. In practice, an empty scan became the all-clear.

**Fixed:** a dedicated verification agent with four evidence-based gates. It is the only agent
permitted to issue a recovery statement, and `CANNOT VERIFY` is an explicit verdict so missing
evidence cannot quietly round up to success.

### Gap 5 — IOCs were prose, and the actual domain was missing (High)

Indicators lived in one paragraph of Markdown. `blum-panel.me` was not listed — only the
glob `*-panel.me` and `api.kercher-panel.me`. Detection therefore depended on the AI
improvising greps, differently on every run.

**Fixed:** `ioc/iocs.json` — 33 code signatures plus network, manifest, txAdmin, server.cfg,
host-persistence and database indicators, consumed by real scanners, extensible during an
engagement.

### Gap 6 — No tooling (High)

Everything was left to the model. Two runs over the same tree could reach different answers,
and multi-line loaders (fetch on one line, `eval` on the next) are easy to miss by eye.

**Fixed:** `tools/vzjrr_scan.py` (tested against a synthetic infected tree), plus PowerShell
equivalents and a Linux host audit. Whole-file regex matching catches multi-line loaders.

### Gap 7 — No re-entry-path analysis (Critical)

The single most important question after an intrusion — *how would they get back in?* — was
never asked.

**Fixed:** Phase 7 of the assessment is a mandatory twelve-row re-entry-path table, where a
path may only be marked closed with evidence. Verification Gate 4 checks it.

### Gap 8 — No guidance on when cleaning is the wrong answer (High)

The old agents assumed cleaning was always the goal. For a host where the attacker held
administrative access, cleaning cannot restore confidence.

**Fixed:** `docs/REBUILD_VS_CLEAN.md`, with rebuild triggers surfaced in both the assessment
verdict and the eradication preconditions. A repeat infection is itself a rebuild trigger.

### Gap 9 — Cleaning a running server was permitted (Medium)

Nothing required the server to be stopped first, so a live loader could rewrite files during
cleanup.

**Fixed:** stopping the server is Step 1, cutting attacker access is Step 2, and both precede
any file operation.

---

## Part 3 — What this means for the affected server

Based on the screenshots alone, before any scan:

1. **The lock message is generated by code on that server.** No third party can lock a FiveM
   server remotely. Either malicious code is still present, or the attacker still has the
   access to place it.
2. **Every credential readable from that host must be treated as stolen** — license key,
   txAdmin admins, RCON, database, Discord tokens.
3. **A second infection after a cleanup means an access path was missed, not re-opened.**
   Per `docs/REBUILD_VS_CLEAN.md`, that on its own is a rebuild trigger.
4. Start at `docs/BLUM_PANEL_PLAYBOOK.md`.

## Part 4 — Verification status of this branch's changes

Stated plainly, so nothing here is taken on trust:

| Component | Status |
|---|---|
| `tools/vzjrr_scan.py` | **Executed and tested** against a synthetic infected tree. Detected all planted indicators: padded manifest injection, lock message, panel domain, credential-theft code, JS `eval` loader, Lua `PerformHttpRequest`→`load` loader, webhook exfil, fake tooling filename, zero-byte stub, orphan manifest reference. No findings on the planted clean resource. |
| `tools/linux/vzjrr-host-audit.sh` | **Executed** end to end on Linux; `bash -n` clean. |
| `ioc/iocs.json` | Parses; all 33 signature regexes compile. |
| `tools/windows/*.ps1` | **Statically reviewed only — not executed.** No PowerShell runtime was available in the assessment environment. Verify on first run against a copy before relying on them; the Python scanner is the tested reference implementation. |
| Agent documents | Prose; correctness is a matter of review, not execution. |

---
Prepared by: vzjRR Security Assessment for FiveM
