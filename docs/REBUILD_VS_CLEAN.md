# Rebuild or clean? — deciding honestly

Cleaning a compromised server is only trustworthy when you can enumerate everything the
attacker did. Past a certain level of access, you cannot — and continuing to clean is
just hoping.

## Rebuild the host if ANY of these is true

- [ ] Host persistence was found: scheduled task, service, Run/RunOnce key, WMI event
      subscription, cron job, systemd unit, or an unrecognised SSH key
- [ ] The attacker had Administrator / root, or an interactive RDP or SSH session
- [ ] The FXServer artifact, the txAdmin bundle, or any OS binary was modified
- [ ] Antivirus was disabled, or an exclusion was added covering the server folder
- [ ] Unauthorised remote-access software was installed (AnyDesk, RustDesk, TeamViewer, ngrok, frp)
- [ ] You cannot establish when the intrusion started
- [ ] **This is a repeat infection after a previous cleanup**
- [ ] The infected resources came from leak/crack sites and you cannot re-source clean copies

Any single box ticked means rebuild. These are not severity points to total up — each
one independently means the host's integrity cannot be established.

## Cleaning in place is defensible only when all of these hold

- [ ] The payload is confined to identifiable files inside `resources/`
- [ ] The host audit found nothing unexplained
- [ ] The intrusion window is short and fully accounted for
- [ ] Every infected resource can be replaced from an official source
- [ ] No evidence of interactive host access
- [ ] It is the first infection

## How to rebuild without carrying the infection over

1. **Provision a new host.** Do not reinstall over the old one if you can avoid it, and
   never keep the old credentials.
2. **Complete `docs/CREDENTIAL_ROTATION.md` first** — including revoking and regenerating
   the license key. A rebuilt server running the old key and old admin passwords is
   compromised on day one.
3. **Fresh FXServer artifacts** from the official Cfx.re source. Never copy the old
   artifact folder across.
4. **Fresh txAdmin data.** Create the master admin from scratch. Do not copy the old
   `admins.json`.
5. **Rebuild `server.cfg` by hand.** Do not copy the old one — copy across only the lines
   you can each justify, and re-enter secrets as new values. `add_principal` /
   `add_ace` lines get re-added one at a time, deliberately.
6. **Re-source every resource from its official origin.** For anything obtained from a
   leak site, the only safe move is not to install it. Scan everything before it lands
   on the new host:
   ```bash
   python3 tools/vzjrr_scan.py --path /staging --out /audit/staging
   ```
7. **Restore only data, never code.** Bring the database across after inspecting it for
   unknown accounts, wildcard-host grants, and admin flags on identifiers that are not
   staff. Do not restore resource folders from a backup taken after the intrusion started.
8. **Harden before going public** — `agents/hardening/AGENT.md`. Bring the server up with
   management ports restricted to your IP.
9. **Verify** — `agents/verification/AGENT.md` — before telling anyone it is recovered.
10. **Decommission the old host** once evidence has been preserved. Do not leave it
    running "just in case"; it is still an attacker foothold on your network.

## The honest cost comparison

A rebuild takes a day or two. Repeated cleaning of a host whose integrity you cannot
establish costs that much anyway across attempts — and ends with a server you still
cannot vouch for, and players who watched it get locked twice.

---
Prepared by: vzjRR Security Assessment for FiveM
