# Credential Rotation — mandatory after any confirmed FiveM compromise

**Assume every credential readable from the server is stolen**, whether or not you found
evidence of theft. The loader in this family reads config files as its first action; by
the time you see a lock message, it has had that access for as long as it has been running.

Rotation is not cleanup housekeeping. It is the step that decides whether the attacker
can come back. **Do not restart the server publicly until this table is complete.**

Work top to bottom — the order matters, because each row can be used to undo the ones
above it.

| # | Credential | Where it lives | Action | Done |
|---|---|---|---|---|
| 1 | **Cfx.re / Keymaster account** | keymaster.fivem.net | Change password, enable 2FA, review active sessions and registered servers | ☐ |
| 2 | **FiveM license key** | `sv_licenseKey` in `server.cfg` | **Revoke the old key and generate a new one** in Keymaster. Changing the config alone does nothing — the old key stays valid and attacker-usable until revoked. | ☐ |
| 3 | **Hosting / VPS provider account** | Provider panel | Change password, enable 2FA, review API tokens and SSH keys held by the provider | ☐ |
| 4 | **Host OS accounts** | Windows / Linux | New password for every account. Remove accounts you did not create. Replace SSH keys and delete every unrecognised `authorized_keys` entry. | ☐ |
| 5 | **txAdmin master admin** | `txData/admins.json` | New password; consider recreating the master account outright | ☐ |
| 6 | **Every other txAdmin admin** | `txData/admins.json` | New password each; remove anyone unrecognised; revoke all sessions | ☐ |
| 7 | **RCON password** | `rcon_password` in `server.cfg` | New long unique value. Do not expose RCON to the internet. | ☐ |
| 8 | **Database passwords** | `mysql_connection_string` | New password for every account; drop unknown accounts; remove `%` wildcard-host grants; bind MySQL to `127.0.0.1` | ☐ |
| 9 | **Discord bot token** | txAdmin config / resource configs | Regenerate in the Discord developer portal | ☐ |
| 10 | **Discord webhooks** | Resource configs, txAdmin | Delete every webhook in any config and create new ones. A stolen webhook URL needs no password to abuse. | ☐ |
| 11 | **Steam Web API key** | `steam_webApiKey` | Regenerate | ☐ |
| 12 | **Any other API keys / tokens** | Resource configs | Regenerate each; list them explicitly rather than assuming there are none | ☐ |
| 13 | **Staff credentials** | Each person | Everyone with server, panel, or Discord-admin access rotates their own credentials and scans their workstation | ☐ |
| 14 | **Shared/reused passwords elsewhere** | Anywhere the above were reused | Rotate there too. Reuse is why one stolen password becomes several compromised systems. | ☐ |

## Rules while rotating

- **New values must be unique.** Reusing a password from another system just moves the problem.
- **Rotate from a clean machine.** Changing passwords from a workstation that may itself
  be compromised hands over the new ones as you type them.
- **Rotate after eradication, not before.** New credentials set while a loader is still
  running get stolen immediately. Order: stop server → cut access → clean → rotate → restart.
- **Enable 2FA** wherever it is offered: Cfx.re, hosting provider, Discord, GitHub.
- **Record what you rotated and when.** The verification agent requires this evidence,
  and it is what tells you what remains open.

## If you cannot rotate something

Write it down as an open risk with a named owner and a date, and say so in the
verification report. An unrotated credential is an open finding — not a footnote, and
not something to quietly let slide.

---
Prepared by: vzjRR Security Assessment for FiveM
