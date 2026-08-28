# FiveM Compromise Cleanup — Step-by-Step Runbook

For a Windows FiveM/txAdmin server showing the `blum-panel.me` extortion lock.
Every command below is written to be copy-pasted. Work top to bottom; do not skip ahead.

**Legend**

- 🔵 **READ-ONLY** — changes nothing, safe to run any time
- 🟡 **CHANGES THINGS** — read the step fully before running
- 🔴 **STOP AND THINK** — a decision point or a lockout risk
- 💬 **SEND TO ANALYST** — paste this output into the chat

**Fill these in once and reuse them throughout:**

| Placeholder | Your value | How to find it (Step 1.2) |
|---|---|---|
| `<SERVER_ROOT>` | | folder containing `resources/`, `server.cfg`, `txData/` |
| `<MY_IP>` | | your own public IP, from the PC you RDP *from* |
| `<AUDIT>` | `C:\vzjrr-audit` | create it in Step 0.1 |
| `<QUARANTINE>` | `C:\vzjrr-quarantine` | created in Round 3 |

---

# ROUND 0 — Containment

**Goal:** cut the attacker's access *before* touching files. The server stays running for
now, so live processes and connections are still capturable in Round 1.

**Time:** 15–30 minutes.

## Step 0.1 — Open an elevated PowerShell and make your working folders 🟡

Log into the server over RDP. Press `Start`, type `powershell`, right-click
**Windows PowerShell** → **Run as administrator**. Then:

```powershell
New-Item -ItemType Directory -Force -Path C:\vzjrr-audit | Out-Null
New-Item -ItemType Directory -Force -Path C:\vzjrr-quarantine | Out-Null
cd C:\vzjrr-audit
whoami /groups | Select-String "S-1-5-32-544"
```

The last line should print a line containing `Administrators`. If it prints nothing, you
are not elevated — close the window and reopen it with **Run as administrator**.

## Step 0.2 — Find your own public IP 🔵

**On the computer you are sitting at** (not the server), open a browser and go to
<https://ifconfig.me> or <https://whatismyipaddress.com>. Write the IPv4 address down as
`<MY_IP>`.

🔴 **Lockout warning.** The next step restricts RDP to `<MY_IP>`. If your home connection
has a dynamic IP that changes, you will lock yourself out of your own server. Before
continuing, confirm you can reach the machine another way:

- Your VPS provider's web console / VNC / "Emergency Console" (Hetzner, OVH, Contabo,
  Vultr, DigitalOcean and most others all have one) — **log into it now and confirm it
  works**, before you change any firewall rule.
- If you have no out-of-band console, use a wider range (your ISP's `/24`, e.g.
  `203.0.113.0/24`) instead of a single IP. Still far better than open to the world.

## Step 0.3 — See what is currently exposed 🔵 💬

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter
    $af = $_ | Get-NetFirewallAddressFilter
    if ($pf.LocalPort -match '3389|40120|3306|30120|30110') {
        [pscustomobject]@{
            Rule   = $_.DisplayName
            Port   = ($pf.LocalPort -join ',')
            Remote = ($af.RemoteAddress -join ',')
        }
    }
} | Format-Table -AutoSize
```

`DefaultInboundAction` should be `Block` for the active profile. `Remote = Any` on any row
means that port is open to the entire internet right now.

## Step 0.4 — Restrict RDP to your IP 🟡 🔴

```powershell
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress "<MY_IP>"

# verify it took effect
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | ForEach-Object {
    [pscustomobject]@{ Rule = $_.DisplayName; Remote = (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',') }
} | Format-Table -AutoSize
```

**Do not close your current RDP session** until you have opened a *second* RDP connection
and confirmed it still works. Existing sessions survive the rule change; new ones are what
gets blocked if you got the IP wrong.

## Step 0.5 — Restrict txAdmin, MySQL and RCON 🟡

Windows Firewall applies **Block before Allow**, so you cannot "block everyone then allow
me." Instead: remove the broad allow rules, then add one narrow allow rule.

For each rule that Step 0.3 showed with `Remote = Any` on port 40120, 3306 or your RCON
port, scope it to your IP:

```powershell
Set-NetFirewallRule -DisplayName "<EXACT RULE NAME FROM STEP 0.3>" -RemoteAddress "<MY_IP>"
```

If there was no rule at all for 40120 (the port was reachable some other way, or via a
provider firewall), add a scoped one:

```powershell
New-NetFirewallRule -DisplayName "vzjRR-txAdmin-MyIP" -Direction Inbound -Protocol TCP `
    -LocalPort 40120 -RemoteAddress "<MY_IP>" -Action Allow
```

Also close the game port while you work — the server is coming down anyway, and this stops
players seeing the extortion message:

```powershell
New-NetFirewallRule -DisplayName "vzjRR-TEMP-Block-Game" -Direction Inbound -Protocol TCP -LocalPort 30120 -Action Block
New-NetFirewallRule -DisplayName "vzjRR-TEMP-Block-GameUDP" -Direction Inbound -Protocol UDP -LocalPort 30120 -Action Block
```

You will remove those two in Round 5.

🔴 **Check your provider's firewall too.** Many hosts (OVH, Hetzner Cloud, Vultr, AWS)
have a network-level firewall *in front of* the machine. A Windows rule does not close a
port that the provider's panel has open. Log into your provider panel and check.

## Step 0.6 — Snapshot before you change anything 🟡

You are about to destroy evidence. Take one of these, in order of preference:

1. **Provider snapshot** — your VPS panel → Snapshots / Backups → *Take snapshot now*.
   Fastest and most complete. Do this if it is available.
2. **Copy the server folder** to a second drive or external storage:

```powershell
robocopy "<SERVER_ROOT>" "E:\ir-evidence\server-data-copy" /E /COPY:DAT /R:1 /W:1 /XJ /LOG:E:\ir-evidence\copy.log
```

`/E` copies everything including empty folders. It does **not** delete anything at the
destination. Point it at a drive with enough free space.

## Step 0.7 — What NOT to do 🔴

- ❌ Do not delete anything yet
- ❌ Do not reinstall, repair, or restore a backup yet
- ❌ Do not visit `blum-panel.me`, and do not contact the attacker
- ❌ Do not open any URL you find inside the malware
- ❌ Do not pay — they hold your credentials, and payment does not change that

---

# ROUND 1 — Collection

**Goal:** capture one complete, read-only picture of the machine.
**Time:** 10–20 minutes, mostly waiting on the scan.

## Step 1.1 — Get the toolkit onto the server 🟡

In your elevated PowerShell:

```powershell
cd C:\
git clone https://github.com/vzjRR/vzjRR-fivem-security-agents.git
cd C:\vzjRR-fivem-security-agents
git checkout claude/security-review-backdoor-closure-6q1ukz
```

**No `git` on the box?** Download the single file instead:

```powershell
$u = 'https://raw.githubusercontent.com/vzjRR/vzjRR-fivem-security-agents/claude/security-review-backdoor-closure-6q1ukz/tools/windows/Collect-VzjrrTriage.ps1'
Invoke-WebRequest -Uri $u -OutFile C:\Collect-VzjrrTriage.ps1
notepad C:\Collect-VzjrrTriage.ps1
```

Skim it before running. It is read-only, but you are recovering from a supply-chain
compromise — reading what you execute is the habit that prevents the next one.

## Step 1.2 — Find your server root 🔵

```powershell
Get-ChildItem C:\ -Recurse -Depth 5 -Filter server.cfg -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
Get-ChildItem C:\ -Recurse -Depth 6 -Filter admins.json -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
```

`<SERVER_ROOT>` is the folder that contains **`server.cfg`** *and* a **`resources`**
folder. `admins.json` usually sits in `txData\` next to it — note that path too.

🔴 **This is the step your last cleanup got wrong.** If you point the tools at
`...\resources` instead of the server root, they cannot see `server.cfg`, `txData\`, or the
admin accounts — which is exactly where the attacker's way back in lives.

Confirm it looks right:

```powershell
Get-ChildItem "<SERVER_ROOT>" | Select-Object Name, Mode
```

You should see `resources` and `server.cfg` in that listing.

## Step 1.3 — Run the collector 🔵

```powershell
powershell -ExecutionPolicy Bypass -File C:\vzjRR-fivem-security-agents\tools\windows\Collect-VzjrrTriage.ps1 `
    -ServerPath "<SERVER_ROOT>" -OutDir "C:\vzjrr-audit"
```

It prints a running summary and writes `C:\vzjrr-audit\<timestamp>\TRIAGE.md`.

If it errors, **copy the full red error text** and send it — do not try to work around it.

## Step 1.4 — Read it, then send it 💬

```powershell
notepad (Get-ChildItem C:\vzjrr-audit -Recurse -Filter TRIAGE.md | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

**Secrets are redacted** — license keys, RCON and DB passwords, API keys, bot tokens and
webhook URLs are replaced with `fp:<8 hex>` fingerprints, so two identical values can still
be matched without either being disclosed. txAdmin password hashes are never printed.

**Logon source IPs are NOT redacted** — identifying an unfamiliar login source is central
to the diagnosis. Read the file. It is your data; remove anything you object to before
sending, and say what you removed.

💬 **Paste the whole of `TRIAGE.md` into the chat.**

## Step 1.5 — Now stop the server 🟡

Volatile evidence is captured, so the server comes down. It stays down until Round 5.

```powershell
Get-Process | Where-Object { $_.ProcessName -match 'FXServer|txAdmin|CitizenFX' } |
    Select-Object Id, ProcessName, Path | Format-Table -AutoSize
```

Review that list, then stop them **by Id**, one at a time:

```powershell
Stop-Process -Id <ID> -Force
```

If FXServer runs as a Windows service or scheduled task:

```powershell
Get-Service | Where-Object { $_.DisplayName -match 'FiveM|FXServer|txAdmin' }
Stop-Service -Name "<SERVICE NAME>"
Set-Service -Name "<SERVICE NAME>" -StartupType Manual   # so a reboot does not restart it mid-cleanup
```

Confirm nothing is left:

```powershell
Get-Process | Where-Object { $_.ProcessName -match 'FXServer|txAdmin|CitizenFX' }
```

No output = stopped.

---

# ROUND 2 — Triage

**Goal:** turn evidence into a decision. **Nothing is deleted in this round.**

## Step 2.1 — Answer the questions only you can answer 💬

Have these ready when you send `TRIAGE.md`. Guessed answers here are the most common
reason a cleanup comes up short:

1. **txAdmin admins** — for every name in section B1, is it yours? Name the person.
2. **`add_principal` / `add_ace` identifiers** — section B2. Which are actual staff?
3. **Resources** — which did you install, and **where did each come from**? Be honest about
   anything from a leak/crack site; it is the most likely patient zero and nobody is judging.
4. **Logon IPs** — section C10. Which are yours or your staff's?
5. **Timeline** — when did you first see the lock message? When was the previous cleanup?
6. **Defender exclusions / scheduled tasks** — sections C2 and C3. Did you create any of them?
7. **Who else has access** — RDP, txAdmin, the hosting panel, DB.

## Step 2.2 — Receive the cleanup plan

You get back: confirmed-malicious files with evidence, ambiguous files with the specific
question, and a batched, ordered plan.

## Step 2.3 — The rebuild checkpoint 🔴

If the collection shows **any** of these, the honest answer changes from *clean* to
*rebuild*, and you should expect to be told so plainly:

- A Defender exclusion covering the server folder that you did not create
- A scheduled task, service, Run key or WMI subscription you cannot account for
- Unauthorised remote-access software (AnyDesk, RustDesk, ngrok, frp)
- Unfamiliar local accounts, or unfamiliar accounts in Administrators
- Successful RDP logons from IPs that are not yours

Each of those independently means the attacker had Administrator, and past that point
nobody can enumerate everything they touched. See `docs/REBUILD_VS_CLEAN.md`.

---

# ROUND 3 — Cleanup

**Goal:** remove the payload without breaking the server.
🔴 **Only run this round against the specific paths in the plan from Round 2.**

## Step 3.1 — Quarantine first, always 🟡

Never delete a suspect file directly. First copy it to quarantine with its hash recorded —
that is your rollback and your evidence.

**Dry run** (copies, leaves the original in place):

```powershell
cd C:\vzjRR-fivem-security-agents\tools\windows

.\Move-VzjrrQuarantine.ps1 `
    -Path "<SERVER_ROOT>\resources\[core]\example\.babelrc.js" `
    -ServerRoot "<SERVER_ROOT>" `
    -QuarantineDir "C:\vzjrr-quarantine" `
    -Reason "Blum loader - MAN-001 padded manifest reference"
```

**Then, once you have checked the copy landed**, add `-Delete`:

```powershell
.\Move-VzjrrQuarantine.ps1 `
    -Path "<SERVER_ROOT>\resources\[core]\example\.babelrc.js" `
    -ServerRoot "<SERVER_ROOT>" `
    -QuarantineDir "C:\vzjrr-quarantine" `
    -Reason "Blum loader - MAN-001 padded manifest reference" `
    -Delete
```

**A batch** — put one path per line in a text file:

```powershell
Get-Content C:\vzjrr-audit\to-remove.txt | .\Move-VzjrrQuarantine.ps1 `
    -ServerRoot "<SERVER_ROOT>" -QuarantineDir "C:\vzjrr-quarantine" `
    -Reason "confirmed loaders - batch 1" -Delete
```

Every action is appended to `C:\vzjrr-quarantine\QUARANTINE_MANIFEST.csv` with the SHA-256.

**To restore something you removed by mistake:**

```powershell
Copy-Item "C:\vzjrr-quarantine\<relative path>" "<SERVER_ROOT>\<relative path>" -Force
```

## Step 3.2 — Clean the padded manifest lines 🟡

For each `MAN-001` hit, quarantine the manifest first, then edit it:

```powershell
.\Move-VzjrrQuarantine.ps1 -Path "<SERVER_ROOT>\resources\[core]\example\fxmanifest.lua" `
    -ServerRoot "<SERVER_ROOT>" -QuarantineDir "C:\vzjrr-quarantine" -Reason "infected manifest - pre-edit copy"

notepad "<SERVER_ROOT>\resources\[core]\example\fxmanifest.lua"
```

In Notepad the injected line looks blank — the payload is pushed hundreds of spaces to the
right. **Turn off word wrap** (Format → Word Wrap, unchecked), click on the line, and press
`End` to jump to the hidden content.

Delete **only** the injected directive. Keep every legitimate line. Then confirm:

```powershell
Select-String -Path "<SERVER_ROOT>\resources\[core]\example\fxmanifest.lua" -Pattern '[ \t]{60,}\S'
```

No output = the padding is gone.

## Step 3.3 — Re-scan after every batch 🔵

```powershell
powershell -ExecutionPolicy Bypass -File C:\vzjRR-fivem-security-agents\tools\windows\Collect-VzjrrTriage.ps1 `
    -ServerPath "<SERVER_ROOT>" -OutDir "C:\vzjrr-audit"
```

💬 Send the new `TRIAGE.md`. One batch at a time keeps every mistake visible and reversible.

## Step 3.4 — Rules that hold all round 🔴

- **Never blanket-delete `.js`.** Real NUI scripts live under `html\`, `ui\`, `web\`, `nui\`,
  and resources like `oxmysql` ship genuine server-side JS. Ask before deleting any JS you
  are unsure about.
- **Replace, don't repair, untrusted resources.** If a resource came from a leak or crack
  site and is confirmed infected, replace the whole folder from an official source or remove
  it. You cannot prove you found every injection in a resource you cannot trust.
- **One batch at a time**, re-scanning between each.

## Step 3.5 — Remove attacker identities 🟡

Files are only half of it. Working from the Round 2 plan:

**txAdmin admins** — quarantine `admins.json`, then edit it:

```powershell
.\Move-VzjrrQuarantine.ps1 -Path "<TXDATA>\admins.json" -ServerRoot "<SERVER_ROOT>" `
    -QuarantineDir "C:\vzjrr-quarantine" -Reason "pre-edit copy of admin store"
notepad "<TXDATA>\admins.json"
```

Delete the whole `{ ... }` object for any admin you did not recognise in Step 2.1, keeping
the JSON array valid. Verify it still parses:

```powershell
Get-Content "<TXDATA>\admins.json" -Raw | ConvertFrom-Json | Select-Object name, master
```

**server.cfg grants** — quarantine, then remove every `add_principal` / `add_ace` line for
an identifier that is not staff, and every `exec` of a cfg you did not author:

```powershell
.\Move-VzjrrQuarantine.ps1 -Path "<SERVER_ROOT>\server.cfg" -ServerRoot "<SERVER_ROOT>" `
    -QuarantineDir "C:\vzjrr-quarantine" -Reason "pre-edit copy of server.cfg"
notepad "<SERVER_ROOT>\server.cfg"
```

**Database** — from your MySQL client (HeidiSQL, phpMyAdmin, or `mysql -u root -p`):

```sql
SELECT user, host FROM mysql.user;
DROP USER 'unknown_user'@'%';
FLUSH PRIVILEGES;
```

Any account with host `%` can log in from anywhere. Remove or scope every one.

**Host accounts** — disable rather than delete, so evidence survives:

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Disable-LocalUser -Name "<UNKNOWN ACCOUNT>"
Remove-LocalGroupMember -Group "Administrators" -Member "<UNKNOWN ACCOUNT>"
```

**Host persistence** — only entries confirmed in Round 2. Export each before removing:

```powershell
Export-ScheduledTask -TaskName "<NAME>" | Out-File "C:\vzjrr-quarantine\task-<NAME>.xml"
Unregister-ScheduledTask -TaskName "<NAME>" -Confirm:$false

Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Remove-MpPreference -ExclusionPath "<PATH>"
Start-MpScan -ScanType CustomScan -ScanPath "<PATH>"   # scan what was hidden
```

---

# ROUND 4 — Credential rotation 🔴

**This is the round that decides whether they come back.** No tool can do it for you.
**Do not restart the server publicly until this table is complete.**

🔴 **Rotate from a machine you trust** — not from a workstation that might also be
compromised. If in doubt, do it from your phone.

Full detail: `docs/CREDENTIAL_ROTATION.md`. The click-paths:

| # | What | Where to go | What to do |
|---|---|---|---|
| 1 | **Cfx.re account** | <https://forum.cfx.re> → your avatar → Preferences → Security | New password, enable 2FA, review active sessions |
| 2 | **FiveM license key** | <https://keymaster.fivem.net> → your server entry | **Delete the old key and create a new one.** Editing `server.cfg` alone does nothing — the old key stays valid and usable by them until deleted. Paste the new key into `server.cfg`. |
| 3 | **VPS / hosting panel** | Your provider's website | New password, enable 2FA, review API tokens and stored SSH keys |
| 4 | **Windows accounts** | On the server: `net user <name> *` then type the new password twice | Every enabled account. Long and unique. |
| 5 | **txAdmin master** | txAdmin web UI → your account → Change Password | New password |
| 6 | **Other txAdmin admins** | txAdmin → Admin Manager | New password for each remaining admin; remove any you did not recognise |
| 7 | **RCON** | `server.cfg` → `rcon_password` | New long value, or delete the line if you do not use RCON |
| 8 | **Database** | MySQL client | `ALTER USER 'fivem'@'localhost' IDENTIFIED BY '<NEW>';` then `FLUSH PRIVILEGES;` and update `mysql_connection_string` |
| 9 | **Discord bot token** | <https://discord.com/developers/applications> → your app → Bot → **Reset Token** | Regenerate, update every config that used it |
| 10 | **Discord webhooks** | Discord → Server Settings → Integrations → Webhooks | **Delete every webhook** found in your configs and create new ones. A stolen webhook URL needs no password to abuse. |
| 11 | **Steam API key** | <https://steamcommunity.com/dev/apikey> | Revoke and regenerate; update `steam_webApiKey` |
| 12 | **Other API keys** | Each provider | Tebex, map/voice services, anything else in your configs |
| 13 | **Staff** | Each person individually | Everyone with server, panel or Discord-admin access rotates their own credentials and scans their PC |
| 14 | **Reused passwords** | Anywhere else you used any of the above | Rotate there too |

Bind MySQL to localhost while you are in there — edit `my.ini`, set
`bind-address=127.0.0.1`, restart the MySQL service.

💬 **Send the completed table with real ticks.** "Planned" is not "done", and the
verification round fails on any outstanding item.

---

# ROUND 5 — Controlled restart

## Step 5.1 — Start with the game port still closed 🟡

```powershell
Set-Service -Name "<SERVICE NAME>" -StartupType Automatic   # if you changed it in Step 1.5
```

Start FXServer/txAdmin the way you normally do. Log into txAdmin from your own IP and watch
the console.

## Step 5.2 — Watch for resources failing to start 🔵 💬

This is how a cleanup that removed something legitimate reveals itself. Any
`Failed to load resource` or `could not find script` points at a file you removed that
should have stayed — restore it from quarantine (Step 3.1) and re-check.

💬 Send any startup errors.

## Step 5.3 — Reopen the game port 🟡

Only once the console is clean:

```powershell
Remove-NetFirewallRule -DisplayName "vzjRR-TEMP-Block-Game"
Remove-NetFirewallRule -DisplayName "vzjRR-TEMP-Block-GameUDP"
```

Connect as a player. **The lock message must be gone.** If it is still there, stop the
server immediately and report it — the payload is still present.

🔴 **Leave RDP, txAdmin and MySQL restricted to your IP permanently.** Those never need to
be open to the internet. Only the game port does.

---

# ROUND 6 — Verification

## Step 6.1 — Final clean scan 🔵 💬

```powershell
powershell -ExecutionPolicy Bypass -File C:\vzjRR-fivem-security-agents\tools\windows\Collect-VzjrrTriage.ps1 `
    -ServerPath "<SERVER_ROOT>" -OutDir "C:\vzjrr-audit"
```

💬 Send it. The four gates in `agents/verification/AGENT.md` get checked against it:
payload removed, access revoked, credentials rotated, re-entry paths closed. All four must
pass — one open item means **not recovered**, and it gets said plainly.

## Step 6.2 — Record the baseline 🟡

Once verification passes:

```powershell
cd C:\vzjRR-fivem-security-agents\tools\windows
.\Watch-VzjrrChanges.ps1 -ServerRoot "<SERVER_ROOT>" `
    -BaselineFile "C:\vzjrr-audit\baseline.csv" -Mode Baseline
```

**Copy `baseline.csv` off the server** — to your PC or cloud storage. An attacker with
access to the host can edit a baseline stored on it.

---

# ROUND 7 — The watch

## Daily for 7 days 🔵

```powershell
cd C:\vzjRR-fivem-security-agents\tools\windows
.\Watch-VzjrrChanges.ps1 -ServerRoot "<SERVER_ROOT>" `
    -BaselineFile "C:\vzjrr-audit\baseline.csv" -Mode Compare
```

`No changes since baseline` = good. Anything flagged **CRITICAL** (`admins.json`,
`server.cfg`, any `fxmanifest.lua`) that you did not do yourself is an incident.

Also check weekly:

```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName
Get-LocalGroupMember -Group Administrators
```

Plus, in txAdmin: the admin list, and the login history.

## Step 7.1 — If an indicator comes back 🔴

1. Stop the server immediately
2. **Preserve evidence before touching anything** — snapshot first
3. Report it

A third infection after a completed rotation means an access path was **missed, not
re-opened**. At that point the correct response is a rebuild
(`docs/REBUILD_VS_CLEAN.md`), not another cleaning pass.

---

# Quick reference

| I want to... | Command |
|---|---|
| Collect evidence | `Collect-VzjrrTriage.ps1 -ServerPath "<SERVER_ROOT>" -OutDir "C:\vzjrr-audit"` |
| Quarantine a file | `Move-VzjrrQuarantine.ps1 -Path "<file>" -ServerRoot "<SERVER_ROOT>" -QuarantineDir "C:\vzjrr-quarantine" -Reason "why"` |
| ...and delete it | add `-Delete` |
| Restore a file | `Copy-Item "C:\vzjrr-quarantine\<rel>" "<SERVER_ROOT>\<rel>" -Force` |
| Baseline | `Watch-VzjrrChanges.ps1 -ServerRoot "<SERVER_ROOT>" -BaselineFile "C:\vzjrr-audit\baseline.csv" -Mode Baseline` |
| Check for changes | same, `-Mode Compare` |
| Find padded manifests | `Get-ChildItem "<SERVER_ROOT>" -Recurse -Include fxmanifest.lua,__resource.lua \| Select-String '[ \t]{60,}\S'` |
| Find the panel domain | `Get-ChildItem "<SERVER_ROOT>" -Recurse -File \| Select-String "blum-panel.me" -SimpleMatch` |
| Stop the server | `Get-Process \| Where-Object { $_.ProcessName -match 'FXServer\|txAdmin' } \| Stop-Process -Force` |

---
Prepared by: vzjRR Security Assessment for FiveM
