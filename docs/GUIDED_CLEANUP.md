# Guided Cleanup — the round-by-round procedure

For cleaning a compromised FiveM/txAdmin server **with an analyst in the loop**, rather
than trusting an automated cleaner to make every judgement call on its own.

**Why guided:** the decisions that matter most are the ones a rule cannot make. *Is this
`.js` the resource's real NUI script or the loader? Is `sv_admin` an admin you created or
one they added? Was this resource always here?* Getting those wrong either breaks the
server or leaves the backdoor. A human answering them, with an analyst reading the
evidence, is why this path is slower and more reliable.

**The literal commands for every round are in [`RUNBOOK.md`](RUNBOOK.md).** This file explains
the shape of the process; the runbook is what you follow at the keyboard.

**The loop:** run a read-only command → send the output → receive exact, file-by-file
instructions → execute → re-verify. Nothing is deleted on a guess, and everything is
quarantined before it is removed.

---

## Round 0 — Containment (do this before collecting anything)

Order matters. Cut access first; leave the server running for one more step so volatile
evidence (processes, live connections) is still capturable.

1. **Restrict the management ports to your own IP** — RDP 3389, txAdmin 40120, MySQL 3306,
   and RCON if enabled. Firewall allowlist, or take them off the public interface.
2. **Snapshot the VPS**, or copy the whole server folder to external storage. You are about
   to destroy evidence; there must be a way back.
3. **Do not delete anything, reinstall anything, or restore a backup yet.**
4. **Do not visit the panel domain and do not contact the attacker.** Do not fetch any URL
   found in the malware.

## Round 1 — Collection (read-only)

Run `tools/windows/Collect-VzjrrTriage.ps1` in an **elevated** PowerShell, against the
server **root** (the folder containing `resources/`, `server.cfg` and `txData/`).

It is read-only: it stops nothing, changes nothing, deletes nothing, and contacts no
network endpoint. It writes `TRIAGE.md`, with secret values replaced by short SHA-256
fingerprints so identical values can still be matched without being disclosed.

**Read `TRIAGE.md` before sending it anywhere.** It is your data. Note that logon source
IPs are deliberately *not* redacted — identifying unfamiliar logon sources is central to
the diagnosis.

Then stop FXServer and txAdmin. From here on the server stays down until Round 5.

## Round 2 — Triage and questions

The analyst reads the collection and comes back with:

- Confirmed malicious files, with the evidence for each
- Ambiguous files needing your judgement, with the question stated plainly
- **Questions only you can answer:** which txAdmin admins are yours, which `add_principal`
  identifiers are staff, which resources you installed and from where, which logon IPs
  are yours, when you first saw the lock message

Answer these carefully. Most incomplete cleanups trace back to a guessed answer here.

## Round 3 — Cleanup, in batches

You receive exact instructions: quarantine these paths, remove these manifest lines,
delete these files, remove these admins and ACE grants, remove this persistence.

Rules that hold throughout:

- **Quarantine before delete.** Copy, with its hash recorded, to a folder outside the
  server tree. Never delete straight to the recycle bin.
- **One batch at a time**, re-collecting after each, so a mistake is visible immediately
  and reversible from quarantine.
- **Never blanket-delete `.js`.** Legitimate NUI scripts live under `html/`, `ui/`, `web/`,
  `nui/`, and some resources ship real server-side JS.
- **Replace, don't repair, untrusted resources.** If a resource came from a leak or crack
  site and is confirmed infected, replace the whole thing from an official source or
  remove it. You cannot prove you found every injection in a resource you cannot trust.

## Round 4 — Credential rotation (mandatory)

`docs/CREDENTIAL_ROTATION.md`, worked top to bottom, with the license key revoked **and
regenerated** in Keymaster.

This is the step that decides whether the attacker comes back, and no tool and no analyst
can do it for you. Rotate from a machine you trust, not from a workstation that might also
be compromised.

**Do not bring the server back publicly until this is complete.**

## Round 5 — Controlled restart

Restart with the management ports still restricted to your IP. Watch the console for
resources failing to start — that is how a cleanup that removed something legitimate shows
itself. Confirm players connect without the lock message.

## Round 6 — Verification

`agents/verification/AGENT.md` — four gates, each needing evidence. It is the only step
permitted to state that the server has recovered, and `CANNOT VERIFY` is an available
verdict so missing evidence never quietly becomes success.

## Round 7 — Watch

Daily for 7 days, weekly to 30: `admins.json` and `server.cfg` mtimes, manifest padding,
new admins, unfamiliar logons, outbound connections to panel infrastructure, any new
Defender exclusion or scheduled task.

**If an indicator returns:** stop the server, preserve evidence before touching anything,
and treat it as proof that an access path was *missed, not re-opened*. At that point the
correct response is a rebuild — see `docs/REBUILD_VS_CLEAN.md` — not a third cleaning pass.

---

## What this path cannot promise

Guided cleaning removes what the evidence reveals. If the attacker held Administrator on
the host — a Defender exclusion, a scheduled task, or a WMI subscription would each be
proof that they did — then nobody can enumerate everything they touched, and no amount of
care makes "no trace" a fact rather than a hope. If the collection shows any of those, the
honest recommendation changes to rebuild, and you should expect to hear it said plainly.

---
Prepared by: vzjRR Security Assessment for FiveM
