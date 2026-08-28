<#
.SYNOPSIS
    vzjRR Security Assessment for FiveM - read-only Windows host persistence & access audit.

.DESCRIPTION
    Cleaning a FiveM resource tree does not evict an attacker. Re-infection after a "successful"
    cleanup almost always comes from one of these, none of which live in resources/:

        * a local account or Administrators-group membership the attacker added
        * a scheduled task, service, Run key or WMI subscription that re-downloads the payload
        * a Windows Defender exclusion covering the server folder
        * a silently installed remote-access tool (AnyDesk / RustDesk / ngrok / frp)
        * exposed RDP with credentials the attacker already has
        * a txAdmin admin entry, a live txAdmin PIN, or a stolen Cfx.re license key

    This script inspects all of the above. It is strictly READ-ONLY: it makes no registry
    writes, kills no processes, deletes nothing and changes no configuration. It reports.

.PARAMETER ServerPath
    Optional FiveM server root, used for txAdmin / server.cfg checks.

.PARAMETER OutDir
    Report output directory. Default .\vzjrr-audit\<timestamp>.

.PARAMETER SinceDays
    Intrusion window for timeline checks. Default 45.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-VzjrrHostAudit.ps1 -ServerPath 'C:\FXServer\server-data' -OutDir 'C:\vzjrr-audit'

.NOTES
    Run in an elevated PowerShell for full coverage. Prepared by: vzjRR Security Assessment for FiveM
#>
[CmdletBinding()]
param(
    [string]$ServerPath = "",
    [string]$OutDir = "",
    [int]$SinceDays = 45
)

$ErrorActionPreference = 'SilentlyContinue'
$CREDIT = 'vzjRR Security Assessment for FiveM'
$cutoff = (Get-Date).AddDays(-$SinceDays)

if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ("vzjrr-audit\" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$findings = New-Object System.Collections.Generic.List[object]
function Add-F($id, $sev, $area, $item, $detail, $why) {
    $findings.Add([pscustomobject]@{ id = $id; severity = $sev; area = $area; item = $item; detail = $detail; why = $why })
    $c = switch ($sev) { 'critical' { 'Red' } 'high' { 'Magenta' } 'medium' { 'Yellow' } default { 'Gray' } }
    Write-Host ("[{0,-8}] {1} :: {2}" -f $sev.ToUpper(), $area, $item) -ForegroundColor $c
}
function Head($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Cyan }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "vzjRR host audit (READ-ONLY)  elevated=$isAdmin  window=${SinceDays}d" -ForegroundColor Cyan
if (-not $isAdmin) { Write-Warning "Not elevated - service, WMI, event-log and some registry checks will be incomplete." }

$susCmd = @('powershell[\s\S]{0,80}-enc', '-w\s+hidden', '-WindowStyle\s+Hidden', '-NoP\b', 'mshta',
    'certutil[\s\S]{0,40}-urlcache', 'bitsadmin', 'Invoke-WebRequest', 'Invoke-Expression', '\biex\b',
    'DownloadString', 'DownloadFile', 'curl[\s\S]{0,40}http', 'wget[\s\S]{0,40}http',
    'wscript', 'cscript', 'regsvr32[\s\S]{0,40}http', 'rundll32[\s\S]{0,40}javascript', '\.vbs\b', 'FromBase64String')
$susPath = @('\\Temp\\', '\\AppData\\', '\\ProgramData\\', '\\Users\\Public\\', '\\Downloads\\', '\\Windows\\Tasks\\', '\\PerfLogs\\')

# ------------------------------------------------------------------ 1. accounts
Head "1. Local accounts and administrators"
$admins = @()
try { $admins = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name } catch {
    $admins = (net localgroup administrators) | Where-Object { $_ -and $_ -notmatch '^(Alias|Comment|Members|---|The command)' }
}
Write-Host "Administrators group:"; $admins | ForEach-Object { Write-Host "  $_" }
Add-F 'WIN-006-INFO' 'info' 'Accounts' 'Administrators members' ($admins -join '; ') 'Review every name. Any account you did not create is standing attacker access that survives every file cleanup.'

$users = Get-LocalUser
foreach ($u in $users) {
    $flags = @()
    if ($u.Enabled -and $u.PasswordLastSet -and $u.PasswordLastSet -gt $cutoff) { $flags += "password set $($u.PasswordLastSet.ToString('yyyy-MM-dd'))" }
    if ($u.Enabled -and -not $u.PasswordRequired) { $flags += 'NO PASSWORD REQUIRED' }
    if ($u.Enabled -and $u.PasswordNeverExpires) { $flags += 'password never expires' }
    if ($flags.Count -gt 0) {
        $sev = if (-not $u.PasswordRequired) { 'critical' } else { 'high' }
        Add-F 'WIN-006' $sev 'Accounts' $u.Name ($flags -join '; ') 'Account created or credential-changed inside the intrusion window, or with a weakened password policy. Confirm you made this change; if not, it is attacker persistence.'
    }
}
$ent = $users | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, Description
$ent | Format-Table -AutoSize | Out-String | Write-Host

# ------------------------------------------------------------------ 2. Defender
Head "2. Windows Defender state and exclusions"
$mp = Get-MpPreference
if ($mp) {
    foreach ($p in @($mp.ExclusionPath)) { if ($p) { Add-F 'WIN-001' 'critical' 'Defender' "ExclusionPath: $p" $p 'An antivirus exclusion on a game server is a near-certain compromise tell: attackers add one so their payload is never scanned. Verify you created it; if not, remove it and treat the covered path as infected.' } }
    foreach ($p in @($mp.ExclusionProcess)) { if ($p) { Add-F 'WIN-001' 'critical' 'Defender' "ExclusionProcess: $p" $p 'Process-level AV exclusion.' } }
    foreach ($p in @($mp.ExclusionExtension)) { if ($p) { Add-F 'WIN-001' 'high' 'Defender' "ExclusionExtension: $p" $p 'Extension-level AV exclusion.' } }
    if ($mp.DisableRealtimeMonitoring) { Add-F 'WIN-001b' 'critical' 'Defender' 'Real-time monitoring DISABLED' 'DisableRealtimeMonitoring=True' 'Real-time protection is off. Attackers disable it during intrusion.' }
    if ($mp.DisableIOAVProtection) { Add-F 'WIN-001c' 'high' 'Defender' 'IOAV protection disabled' 'DisableIOAVProtection=True' 'Download scanning is off.' }
}
$mpst = Get-MpComputerStatus
if ($mpst) { Write-Host "AntivirusEnabled=$($mpst.AntivirusEnabled) RealTime=$($mpst.RealTimeProtectionEnabled) SigsAge=$($mpst.AntivirusSignatureAge)d" }
$threats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 25
foreach ($t in $threats) { Add-F 'WIN-001d' 'high' 'Defender' "Detection: $($t.ThreatID)" "$($t.InitialDetectionTime) resources=$([string]::Join(',', @($t.Resources)))" 'Defender previously detected something here. Read the full history - a detection that was "allowed" is an active infection.' }

# ------------------------------------------------------------------ 3. scheduled tasks
Head "3. Scheduled tasks"
$tasks = Get-ScheduledTask
Write-Host "$($tasks.Count) tasks."
foreach ($t in $tasks) {
    if ($t.TaskPath -like '\Microsoft\*') { continue }
    $acts = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    if (-not $acts) { continue }
    $hit = $false
    foreach ($rx in $susCmd) { if ($acts -match $rx) { $hit = $true; break } }
    foreach ($rx in $susPath) { if ($acts -match $rx) { $hit = $true; break } }
    $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath
    if ($hit) {
        Add-F 'WIN-002' 'critical' 'ScheduledTask' "$($t.TaskPath)$($t.TaskName)" "$acts  [author=$($t.Author) lastRun=$($info.LastRunTime)]" 'Scheduled task using download/execute or hidden-window tradecraft, or running from a user-writable directory. This is the classic mechanism that re-installs the backdoor after you clean the files.'
    }
    else {
        Write-Host ("  {0}{1}  ->  {2}" -f $t.TaskPath, $t.TaskName, $acts)
    }
}

# ------------------------------------------------------------------ 4. services
Head "4. Services"
$svcs = Get-CimInstance Win32_Service
foreach ($s in $svcs) {
    $p = $s.PathName
    if (-not $p) { continue }
    $hit = $false
    foreach ($rx in $susPath) { if ($p -match $rx) { $hit = $true; break } }
    foreach ($rx in $susCmd) { if ($p -match $rx) { $hit = $true; break } }
    if ($hit) { Add-F 'WIN-004' 'high' 'Service' $s.Name "$p  [state=$($s.State) start=$($s.StartMode) account=$($s.StartName)]" 'Service binary in a user-writable location or using download/execute tradecraft.' }
}

# ------------------------------------------------------------------ 5. autoruns
Head "5. Run keys and startup folders"
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
    if (-not (Test-Path $k)) { continue }
    $props = Get-ItemProperty -Path $k
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $v = [string]$p.Value
        $sev = 'medium'
        foreach ($rx in ($susCmd + $susPath)) { if ($v -match $rx) { $sev = 'critical'; break } }
        Add-F 'WIN-003' $sev 'Autorun' "$k :: $($p.Name)" $v 'Autorun entry. Every entry here should be software you deliberately installed.'
    }
}
foreach ($sf in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
    if (Test-Path $sf) {
        foreach ($f in (Get-ChildItem -LiteralPath $sf -File)) {
            Add-F 'WIN-008' 'high' 'Autorun' "StartupFolder: $($f.Name)" $f.FullName 'File in a Startup folder runs at logon.'
        }
    }
}

# ------------------------------------------------------------------ 6. WMI subscriptions
Head "6. WMI permanent event subscriptions"
$filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
$consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
$bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
foreach ($c in $consumers) {
    Add-F 'WIN-005' 'critical' 'WMI' "CommandLineEventConsumer: $($c.Name)" "$($c.CommandLineTemplate)" 'WMI permanent event subscription. This is fileless persistence: it survives reboots and every file-level cleanup, and is the single most commonly missed re-infection mechanism.'
}
foreach ($f in $filters) { Write-Host "  Filter: $($f.Name) -> $($f.Query)" }
Write-Host "  bindings: $($bindings.Count)"

# ------------------------------------------------------------------ 7. remote access tooling
Head "7. Remote-access tooling"
$rat = @('anydesk', 'rustdesk', 'teamviewer', 'ngrok', 'frpc', 'frps', 'supremo', 'atera', 'screenconnect', 'netsupport', 'radmin', 'ammyy', 'dwagent', 'meshagent')
$procs = Get-Process | Select-Object -ExpandProperty ProcessName -Unique
foreach ($r in $rat) {
    if ($procs -contains $r) { Add-F 'WIN-007' 'critical' 'RemoteAccess' "Process running: $r" 'live process' 'Remote-access tool running on the server. If you did not install it, the attacker has an interactive session channel that no file cleanup closes.' }
}
$instPaths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$installed = Get-ItemProperty $instPaths | Where-Object DisplayName
foreach ($i in $installed) {
    foreach ($r in $rat) {
        if ($i.DisplayName -match $r) { Add-F 'WIN-007' 'high' 'RemoteAccess' "Installed: $($i.DisplayName)" "$($i.InstallDate) $($i.InstallLocation)" 'Remote-access software installed. Confirm it is yours.' }
    }
}
foreach ($i in $installed) { if ($i.InstallDate -and $i.InstallDate -match '^\d{8}$') { $d = [datetime]::ParseExact($i.InstallDate, 'yyyyMMdd', $null); if ($d -gt $cutoff) { Write-Host "  recent install: $($i.DisplayName)  $($i.InstallDate)" } } }

# ------------------------------------------------------------------ 8. network
Head "8. Listening ports, connections, firewall, RDP"
$listen = Get-NetTCPConnection -State Listen | Sort-Object LocalPort
foreach ($l in $listen) {
    $pn = (Get-Process -Id $l.OwningProcess).ProcessName
    Write-Host ("  LISTEN {0}:{1}  {2}" -f $l.LocalAddress, $l.LocalPort, $pn)
    if ($l.LocalPort -eq 40120 -and $l.LocalAddress -in @('0.0.0.0', '::')) {
        Add-F 'TXA-006' 'high' 'Network' 'txAdmin web on 0.0.0.0:40120' "process=$pn" 'The txAdmin web panel is bound to all interfaces. If port 40120 is reachable from the internet, it is a login page for your entire server. Restrict it to a VPN, an IP allowlist, or a reverse proxy with authentication.'
    }
    if ($l.LocalPort -eq 3389 -and $l.LocalAddress -in @('0.0.0.0', '::')) {
        Add-F 'WIN-011' 'high' 'Network' 'RDP listening on all interfaces' "process=$pn" 'Internet-exposed RDP is the most common initial-access route for compromised FiveM VPS hosts. Restrict it to an IP allowlist or a VPN.'
    }
}
$estab = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' }
Write-Host "Established outbound/inbound: $($estab.Count)"
foreach ($e in ($estab | Select-Object -First 80)) {
    $pn = (Get-Process -Id $e.OwningProcess).ProcessName
    Write-Host ("  {0}:{1} <-> {2}:{3}  {4}" -f $e.LocalAddress, $e.LocalPort, $e.RemoteAddress, $e.RemotePort, $pn)
}
$fwIn = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object { $_.Group -eq $null -or $_.Group -eq '' }
foreach ($r in ($fwIn | Select-Object -First 60)) {
    $pf = $r | Get-NetFirewallPortFilter
    Add-F 'WIN-009' 'medium' 'Firewall' "Inbound allow: $($r.DisplayName)" "ports=$($pf.LocalPort) proto=$($pf.Protocol)" 'Ungrouped inbound allow rule. Attackers add these to reach their own tooling. Confirm each one is yours.'
}
$fDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
Write-Host "RDP fDenyTSConnections=$fDeny (0 = RDP enabled)"
$nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
if ($fDeny -eq 0 -and $nla -eq 0) { Add-F 'WIN-011b' 'high' 'Network' 'RDP with NLA disabled' 'UserAuthentication=0' 'Network Level Authentication is off, which removes pre-auth protection on RDP.' }

$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
foreach ($ln in (Get-Content $hosts)) {
    if ($ln -match '^\s*#' -or $ln -match '^\s*$') { continue }
    Add-F 'WIN-010' 'medium' 'Hosts' $ln.Trim() $ln.Trim() 'Non-default hosts file entry - can redirect updates, license checks or block security tooling.'
}

# ------------------------------------------------------------------ 9. logon events
Head "9. Recent successful logons (4624) and account changes"
if ($isAdmin) {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $cutoff } -MaxEvents 400
    $byUser = $ev | ForEach-Object {
        $x = [xml]$_.ToXml()
        [pscustomobject]@{
            User = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            Type = ($x.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
            IP   = ($x.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
        }
    } | Where-Object { $_.User -and $_.User -notmatch '\$$' -and $_.Type -in @('3', '7', '10') -and $_.IP -and $_.IP -ne '-' -and $_.IP -notmatch '^(127\.|::1)' }
    $grp = $byUser | Group-Object User, IP | Sort-Object Count -Descending
    foreach ($g in ($grp | Select-Object -First 40)) {
        Write-Host ("  {0,-40} x{1}" -f $g.Name, $g.Count)
        Add-F 'WIN-LOGON' 'info' 'Logon' $g.Name "count=$($g.Count)" 'Remote/network logon source. Any source IP that is not yours is confirmed unauthorised access - and means credentials, not just files, must be rotated.'
    }
    $fail = (Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $cutoff } -MaxEvents 2000).Count
    Write-Host "Failed logons (4625) in window: $fail"
    if ($fail -gt 500) { Add-F 'WIN-BRUTE' 'high' 'Logon' 'High failed-logon volume' "$fail failures in $SinceDays days" 'Sustained credential brute-forcing against this host. Management ports are exposed to the internet.' }
    foreach ($id in @(4720, 4722, 4728, 4732, 4738, 4724)) {
        $e2 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $id; StartTime = $cutoff } -MaxEvents 50
        foreach ($e in $e2) {
            Add-F 'WIN-ACCTCHG' 'high' 'Logon' "Event $id at $($e.TimeCreated)" (($e.Message -split "`n" | Select-Object -First 6) -join ' ') 'Account created, enabled, password-reset, or added to a privileged group inside the intrusion window.'
        }
    }
}
else { Write-Warning "Skipping Security event log (needs elevation)." }

# ------------------------------------------------------------------ 10. txAdmin / server config
Head "10. txAdmin and server configuration"
if ($ServerPath -and (Test-Path $ServerPath)) {
    $root = (Resolve-Path $ServerPath).Path
    $adminFiles = @(Get-ChildItem -Path $root -Recurse -File -Filter 'admins.json' -ErrorAction SilentlyContinue)
    # also look one level up - txData often sits beside server-data
    $adminFiles += @(Get-ChildItem -Path (Split-Path $root -Parent) -Recurse -Depth 3 -File -Filter 'admins.json' -ErrorAction SilentlyContinue)
    $adminFiles = $adminFiles | Sort-Object FullName -Unique
    foreach ($af in $adminFiles) {
        Add-F 'TXA-001' 'critical' 'txAdmin' "admins.json: $($af.FullName)" "modified=$($af.LastWriteTime)" 'REVIEW EVERY ENTRY BY HAND. An attacker-added admin here is standing access to your whole server and is completely unaffected by cleaning resource files. This is the number one cause of re-infection after a "successful" cleanup.'
        try {
            $j = Get-Content -LiteralPath $af.FullName -Raw | ConvertFrom-Json
            foreach ($a in $j) {
                $isMaster = $a.master -eq $true
                Write-Host ("  admin: {0}  master={1}  providers={2}" -f $a.name, $isMaster, (($a.providers.PSObject.Properties.Name) -join ','))
                if ($isMaster) { Add-F 'TXA-002' 'high' 'txAdmin' "master admin: $($a.name)" 'master=true' 'Master admin account. There should be exactly one and it should be yours.' }
            }
        }
        catch { Write-Warning "  could not parse $($af.FullName)" }
        if ($af.LastWriteTime -gt $cutoff) { Add-F 'TXA-003' 'critical' 'txAdmin' 'admins.json modified in intrusion window' "$($af.LastWriteTime)" 'The admin list changed recently. If that was not you, an attacker account was added.' }
    }

    $cfgs = @(Get-ChildItem -Path $root -Recurse -File -Filter '*.cfg' -ErrorAction SilentlyContinue | Select-Object -First 60)
    foreach ($c in $cfgs) {
        $ls = Get-Content -LiteralPath $c.FullName
        for ($i = 0; $i -lt $ls.Count; $i++) {
            $ln = $ls[$i].Trim()
            if ($ln -match '^\s*#' -or $ln -eq '') { continue }
            if ($ln -match '^\s*add_(principal|ace)\s') { Add-F 'CFG-002' 'critical' 'ServerCfg' "$($c.Name):$($i+1)" $ln 'ACE/principal grant. Every identifier here has elevated in-game and console rights. One line you do not recognise is a permanent backdoor.' }
            elseif ($ln -match '^\s*exec\s') { Add-F 'CFG-001' 'high' 'ServerCfg' "$($c.Name):$($i+1)" $ln 'exec of another config file. Attackers chain a small extra cfg here so their changes survive edits to the main config. Open the referenced file.' }
            elseif ($ln -match '^\s*(rcon_password)\s') { Add-F 'CFG-004' 'high' 'ServerCfg' "$($c.Name):$($i+1)" 'rcon_password <redacted>' 'RCON password present. Assume it is stolen and rotate it. Never expose RCON to the internet.' }
            elseif ($ln -match 'sv_licenseKey|steam_webApiKey|mysql_connection_string|discord.*token') { Add-F 'CFG-006' 'critical' 'ServerCfg' "$($c.Name):$($i+1)" '<secret redacted>' 'A secret is stored here in plaintext. The attacker read this file. Treat this credential as compromised and rotate it - the FiveM license key must be revoked and regenerated in Keymaster.' }
            elseif ($ln -match '[a-z0-9_-]{2,30}-panel\.(me|xyz|cc|su|ru|top)') { Add-F 'CFG-IOC' 'critical' 'ServerCfg' "$($c.Name):$($i+1)" $ln 'Panel C2 domain referenced directly in server configuration.' }
        }
    }
}
else { Write-Warning "No -ServerPath given - skipping txAdmin/server.cfg checks. Re-run with -ServerPath for full coverage." }

# ------------------------------------------------------------------ report
Head "Report"
$crit = @($findings | Where-Object severity -eq 'critical')
$high = @($findings | Where-Object severity -eq 'high')
$med = @($findings | Where-Object severity -eq 'medium')

$verdict = if ($crit.Count -gt 0) { 'HOST PERSISTENCE / STANDING ACCESS INDICATORS PRESENT - assume the attacker can return' }
elseif ($high.Count -gt 0) { 'REVIEW REQUIRED - high-severity host findings' }
else { 'No host persistence indicators detected in the checks performed (not a proof of cleanliness)' }

[pscustomobject]@{
    credit = $CREDIT; scanned_utc = (Get-Date).ToUniversalTime().ToString('o')
    host_name = $env:COMPUTERNAME; elevated = $isAdmin; window_days = $SinceDays
    server_path = $ServerPath
    counts = @{ critical = $crit.Count; high = $high.Count; medium = $med.Count }
    verdict = $verdict; findings = $findings
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutDir 'host-audit.json') -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Windows Host Persistence & Access Audit")
[void]$md.AppendLine("")
[void]$md.AppendLine("- **Host:** $env:COMPUTERNAME")
[void]$md.AppendLine("- **Scanned (UTC):** $((Get-Date).ToUniversalTime().ToString('u'))")
[void]$md.AppendLine("- **Elevated:** $isAdmin (non-elevated runs are incomplete)")
[void]$md.AppendLine("- **Findings:** $($crit.Count) critical / $($high.Count) high / $($med.Count) medium")
[void]$md.AppendLine("- **Verdict:** $verdict")
[void]$md.AppendLine("")
[void]$md.AppendLine("> Any confirmed critical finding in this report means file cleanup alone will not recover the server. Close the access path and rotate the credentials, or the intrusion repeats.")
[void]$md.AppendLine("")
foreach ($sev in @('critical', 'high', 'medium', 'info')) {
    $set = @($findings | Where-Object severity -eq $sev)
    if ($set.Count -eq 0) { continue }
    [void]$md.AppendLine("## " + $sev.ToUpper() + " ($($set.Count))")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("| ID | Area | Item | Detail | Why it matters |")
    [void]$md.AppendLine("|---|---|---|---|---|")
    foreach ($x in $set) {
        $d = ([string]$x.detail -replace '\|', '\|') -replace '[\r\n]', ' '
        if ($d.Length -gt 300) { $d = $d.Substring(0, 300) + ' ...' }
        $it = ([string]$x.item -replace '\|', '\|') -replace '[\r\n]', ' '
        [void]$md.AppendLine("| $($x.id) | $($x.area) | ``$it`` | $d | $($x.why -replace '\|','\|') |")
    }
    [void]$md.AppendLine("")
}
[void]$md.AppendLine("---")
[void]$md.AppendLine("Prepared by: $CREDIT")
$md.ToString() | Set-Content -LiteralPath (Join-Path $OutDir 'host-audit.md') -Encoding UTF8

Write-Host ""
Write-Host "VERDICT: $verdict" -ForegroundColor $(if ($crit.Count) { 'Red' } elseif ($high.Count) { 'Magenta' } else { 'Green' })
Write-Host "Report: $(Join-Path $OutDir 'host-audit.md')"
Write-Host "Prepared by: $CREDIT"
exit $(if ($crit.Count -gt 0) { 2 } elseif ($high.Count -gt 0) { 1 } else { 0 })
