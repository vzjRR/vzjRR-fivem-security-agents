<#
.SYNOPSIS
    vzjRR Security Assessment for FiveM - read-only triage collector for guided cleanup.

.DESCRIPTION
    Gathers, in ONE pass, everything needed to plan a cleanup of a FiveM/txAdmin server
    compromised by the blum-panel / Kercher family - and produces a compact report that is
    safe to paste into a chat with whoever is helping you.

    STRICTLY READ-ONLY. It does not stop services, change settings, delete files, edit the
    registry, or contact any network endpoint. It reads and reports.

    SECRETS ARE REDACTED. License keys, RCON and database passwords, API keys, bot tokens,
    webhook URLs and txAdmin password hashes are replaced with a short SHA-256 fingerprint,
    so you can still tell two values apart without disclosing either. Read TRIAGE.md before
    sending it anywhere - it is your data and your call.

    NOTE: the report DOES contain source IP addresses from logon history, because identifying
    unfamiliar logon sources is central to the diagnosis. Strip them yourself if you object.

.PARAMETER ServerPath
    FiveM server ROOT - the folder containing resources/, server.cfg and txData/.
    Not resources/ on its own: that scope is what lets an intrusion survive a cleanup.

.PARAMETER OutDir
    Where to write the report. Must be OUTSIDE the server tree. Default .\vzjrr-triage\<timestamp>.

.PARAMETER SinceDays
    Intrusion window for timeline and log checks. Default 60.

.PARAMETER Full
    Skip output truncation. Produces a much larger file for local review; the default
    truncated form is the one meant for pasting.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Collect-VzjrrTriage.ps1 -ServerPath 'C:\FXServer\server-data'

.NOTES
    Run in an ELEVATED PowerShell for full coverage.
    Prepared by: vzjRR Security Assessment for FiveM
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerPath,
    [string]$OutDir = "",
    [int]$SinceDays = 60,
    [switch]$Full
)

$ErrorActionPreference = 'SilentlyContinue'
$CREDIT = 'vzjRR Security Assessment for FiveM'
$cutoff = (Get-Date).AddDays(-$SinceDays)

# ------------------------------------------------------------------ setup
if (-not (Test-Path -LiteralPath $ServerPath)) { throw "ServerPath not found: $ServerPath" }
$ServerPath = (Resolve-Path -LiteralPath $ServerPath).Path
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ("vzjrr-triage\" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
if ($OutDir.ToLower().StartsWith($ServerPath.ToLower())) {
    throw "OutDir must be OUTSIDE the server tree. Evidence written inside a compromised tree is not evidence."
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$REPORT = Join-Path $OutDir 'TRIAGE.md'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$script:Out = New-Object System.Text.StringBuilder
function W($t) { [void]$script:Out.AppendLine($t) }
function Sec($t) { W ""; W "## $t"; W ""; Write-Host "  $t" -ForegroundColor Cyan }
function Code($lines, $cap) {
    if (-not $Full -and $cap -gt 0) {
        $arr = @($lines)
        if ($arr.Count -gt $cap) {
            $lines = @($arr[0..($cap - 1)]) + "... [$($arr.Count - $cap) more lines omitted - see raw output with -Full]"
        }
    }
    W '```'
    foreach ($l in @($lines)) { if ($null -ne $l) { W ([string]$l) } }
    if (@($lines).Count -eq 0) { W '(none)' }
    W '```'
}

# ------------------------------------------------------------------ redaction
function Fingerprint($v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return 'empty' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$v))
    return (($b[0..3] | ForEach-Object { $_.ToString('x2') }) -join '')
}
# Redacts secret VALUES while keeping the surrounding line readable.
# Two passes (quoted then unquoted) - a single pattern misses quoted values containing
# spaces, e.g. rcon_password "S3cr3t P4ss". Verified against a leak-test corpus.
$script:SecretKeys = 'sv_licenseKey|rcon_password|mysql_connection_string|steam_webApiKey|sv_tebexSecret|discord[A-Za-z_]*[Tt]oken|[A-Za-z_]*api[_-]?key|[A-Za-z_]*secret|[A-Za-z_]*password|[A-Za-z_]*token'
function Redact([string]$line) {
    if ([string]::IsNullOrEmpty($line)) { return $line }
    $t = $line
    # 1. quoted values (may contain spaces)
    $t = [regex]::Replace($t, "(?i)\b($script:SecretKeys)\b(\s*[:=]?\s*)([`"'])([^`"']*)\3",
        { param($m) "$($m.Groups[1].Value)$($m.Groups[2].Value)<REDACTED fp:$(Fingerprint $m.Groups[4].Value)>" })
    # 2. unquoted values; the guards stop it re-redacting a value pass 1 already replaced,
    #    and stop a bare '=' or ':' separator being treated as the value
    $t = [regex]::Replace($t, "(?i)\b($script:SecretKeys)\b(\s*[:=]?\s*)(?!<REDACTED)([^\s`"'<=:]\S*)",
        { param($m) "$($m.Groups[1].Value)$($m.Groups[2].Value)<REDACTED fp:$(Fingerprint $m.Groups[3].Value)>" })
    # 3. Discord webhooks - keep the host, drop id/token
    $t = [regex]::Replace($t, '(?i)(https?://[a-z.]*discord(?:app)?\.com/api/(?:v\d+/)?webhooks/)\S+',
        { param($m) "$($m.Groups[1].Value)<REDACTED fp:$(Fingerprint $m.Value)>" })
    # 4. bare cfxk_ license keys anywhere, as a backstop
    $t = [regex]::Replace($t, '(?i)\bcfxk_\S+', { param($m) "<REDACTED-LICENSE fp:$(Fingerprint $m.Value)>" })
    return $t
}

Write-Host "$CREDIT" -ForegroundColor Cyan
Write-Host "Read-only triage collection. Elevated=$isAdmin. Window=${SinceDays}d." -ForegroundColor Cyan
if (-not $isAdmin) { Write-Warning "NOT ELEVATED - accounts, services, WMI, Defender and event-log sections will be incomplete. Re-run as Administrator." }

W "# FiveM Compromise Triage"
W ""
W "- **Host:** $env:COMPUTERNAME"
W "- **Collected (UTC):** $((Get-Date).ToUniversalTime().ToString('u'))"
W "- **Server root:** ``$ServerPath``"
W "- **Elevated:** $isAdmin"
W "- **Window:** last $SinceDays days"
W ""
W "> Read-only collection. Secret VALUES are redacted and shown as ``fp:<8 hex>`` fingerprints,"
W "> so identical values can be matched without disclosing them. Logon source IPs are NOT"
W "> redacted - they are central to the diagnosis."

# ================================================================== A. RESOURCE TREE
$SIGS = @(
    @('LOCK-MSG', 'critical', 'Server is locked by|Purchase whitelist|Connections? to server is restricted'),
    @('PANEL-C2', 'critical', 'blum-panel|kercher-panel|[a-z0-9_-]{2,30}-panel\.(me|xyz|cc|su|ru|top|store|online|site)'),
    @('LOADER-MARK', 'critical', 'helpEmptyCode|onServerResourceFail|RESOURCE_EXCLUDE|JohnsUrUncle|BLUM_TXADMIN_THEFT_PAYLOAD|txadmin:js_create'),
    @('RCE-DYNAMIC', 'critical', 'loadstring\s*\(|\bload\s*\(\s*(Base64|base64|Decode|decode)|\beval\s*\(|new\s+Function\s*\('),
    @('RCE-SHELL', 'critical', 'os\.execute\s*\(|io\.popen\s*\(|require\s*\(\s*[''"]child_process'),
    @('CRED-THEFT', 'critical', 'admins\.json|sv_licenseKey|rcon_password|mysql_connection_string|steam_webApiKey|txData'),
    @('EXFIL', 'high', 'discord(app)?\.com/api/(v[0-9]+/)?webhooks/|pastebin\.com/raw|hastebin|transfer\.sh|gofile\.io|anonfiles|ngrok'),
    @('FAKE-TOOLING', 'critical', 'sv_init\.mjs|\.babelrc\.js|babel_config\.js|\.yarn\.js|node_modules[\\/]internal'),
    @('DEFER-LOCK', 'high', 'deferrals\.(done|update)\s*\('),
    @('OBFUSC', 'medium', 'String\.fromCharCode\s*\(\s*\d{2,3}(\s*,\s*\d{2,3}){10,}|_0x[a-f0-9]{4,6}|\\27Lua')
)

Sec "A1. Resource tree - IOC hits"
$exts = @('.lua', '.js', '.mjs', '.cjs', '.cfg', '.json')
$allFiles = @(Get-ChildItem -LiteralPath $ServerPath -Recurse -File -Force | Where-Object {
        $_.Extension.ToLower() -in $exts -and $_.Length -lt 12MB -and $_.FullName -notmatch '\\(cache|logs|\.git)\\'
    })
W "Scanned **$($allFiles.Count)** script/config files under the server root."
W ""

$hits = New-Object System.Collections.Generic.List[object]
foreach ($f in $allFiles) {
    $rel = $f.FullName.Substring($ServerPath.Length).TrimStart('\')
    $lines = [System.IO.File]::ReadAllLines($f.FullName)
    if (-not $lines) { continue }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($s in $SIGS) {
            if ($lines[$i] -match $s[2]) {
                $ev = (Redact $lines[$i]).Trim()
                if ($ev.Length -gt 180) { $ev = $ev.Substring(0, 180) + ' ...' }
                $hits.Add([pscustomobject]@{ Sev = $s[1]; Id = $s[0]; File = $rel; Line = $i + 1; Text = $ev })
            }
        }
    }
}
foreach ($sev in @('critical', 'high', 'medium')) {
    $set = @($hits | Where-Object Sev -eq $sev)
    if ($set.Count -eq 0) { continue }
    W "### $($sev.ToUpper()) ($($set.Count))"
    Code (@($set | ForEach-Object { "{0,-13} {1}:{2}`n              {3}" -f $_.Id, $_.File, $_.Line, $_.Text })) 120
}
if ($hits.Count -eq 0) { W "_No IOC hits in the resource tree._" }
Write-Host "    $($hits.Count) IOC hits" -ForegroundColor $(if ($hits.Count) { 'Red' } else { 'Green' })

Sec "A2. Manifest injections (whitespace padding + orphan references)"
$manifests = @(Get-ChildItem -LiteralPath $ServerPath -Recurse -File -Force -Include fxmanifest.lua, __resource.lua)
$manOut = @()
foreach ($m in $manifests) {
    $rel = $m.FullName.Substring($ServerPath.Length).TrimStart('\')
    $lines = [System.IO.File]::ReadAllLines($m.FullName)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '[ \t]{60,}\S') {
            $manOut += "PADDED   $rel`:$($i+1)  ->  $((Redact $lines[$i]).Trim())"
        }
        if ($lines[$i] -match "['`"]([A-Za-z0-9_\-./\\@\[\]]+\.(lua|js|mjs))['`"]") {
            $r = $Matches[1]
            if ($r -notmatch '[\*\?]' -and $r -notmatch '^https?:') {
                if (-not (Test-Path -LiteralPath (Join-Path $m.Directory.FullName ($r -replace '/', '\')))) {
                    $manOut += "ORPHAN   $rel`:$($i+1)  ->  references missing file '$r'"
                }
            }
        }
    }
}
W "**$($manifests.Count)** manifests examined."
Code $manOut 80
Write-Host "    $($manOut.Count) manifest issues" -ForegroundColor $(if ($manOut.Count) { 'Red' } else { 'Green' })

Sec "A3. Zero-byte script stubs and recently modified scripts"
Code (@(Get-ChildItem -LiteralPath $ServerPath -Recurse -File -Force -Include *.lua, *.js, *.mjs |
        Where-Object Length -eq 0 | ForEach-Object { "0-BYTE  " + $_.FullName.Substring($ServerPath.Length).TrimStart('\') })) 40
W ""
W "Script/config files modified in the last $SinceDays days (newest first):"
Code (@(Get-ChildItem -LiteralPath $ServerPath -Recurse -File -Force -Include *.lua, *.js, *.mjs, *.cfg, *.json |
        Where-Object { $_.LastWriteTime -gt $cutoff } | Sort-Object LastWriteTime -Descending |
        ForEach-Object { "{0}  {1}" -f $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.FullName.Substring($ServerPath.Length).TrimStart('\') })) 60

Sec "A4. Resource inventory"
$resRoot = Join-Path $ServerPath 'resources'
if (Test-Path $resRoot) {
    Code (@(Get-ChildItem -LiteralPath $resRoot -Recurse -File -Force -Include fxmanifest.lua, __resource.lua |
            ForEach-Object { $_.Directory.FullName.Substring($ServerPath.Length).TrimStart('\') } | Sort-Object)) 200
}
else { W "_No resources/ folder at the server root - confirm ServerPath is the server ROOT._" }

# ================================================================== B. txADMIN / CONFIG
Sec "B1. txAdmin admins (names only - password hashes are never output)"
$adminFiles = @()
$adminFiles += @(Get-ChildItem -LiteralPath $ServerPath -Recurse -File -Filter 'admins.json' -Force)
$parent = Split-Path $ServerPath -Parent
if ($parent) { $adminFiles += @(Get-ChildItem -LiteralPath $parent -Recurse -Depth 4 -File -Filter 'admins.json' -Force) }
$adminFiles = @($adminFiles | Sort-Object FullName -Unique)
$adminOut = @()
foreach ($af in $adminFiles) {
    $adminOut += "FILE: $($af.FullName)   (modified $($af.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"
    try {
        foreach ($a in (Get-Content -LiteralPath $af.FullName -Raw | ConvertFrom-Json)) {
            $prov = ($a.providers.PSObject.Properties.Name) -join ','
            $adminOut += ("  admin='{0}'  master={1}  providers=[{2}]  perms=[{3}]" -f `
                    $a.name, ($a.master -eq $true), $prov, (@($a.permissions) -join ','))
        }
    }
    catch { $adminOut += "  <could not parse this file>" }
}
Code $adminOut 60
W ""
W "**Action for you:** name every admin above. Any account you do not personally recognise is"
W "standing attacker access, and it is unaffected by cleaning resource files."

Sec "B2. server.cfg - access control and secrets (values redacted)"
$cfgOut = @()
foreach ($c in @(Get-ChildItem -LiteralPath $ServerPath -Recurse -File -Filter '*.cfg' -Force | Select-Object -First 40)) {
    $rel = $c.FullName.Substring($ServerPath.Length).TrimStart('\')
    $ls = Get-Content -LiteralPath $c.FullName
    for ($i = 0; $i -lt $ls.Count; $i++) {
        $ln = $ls[$i].Trim()
        if ($ln -match '^\s*#' -or $ln -eq '') { continue }
        if ($ln -match '^\s*(add_principal|add_ace|add_auth|exec|ensure|start|sv_licenseKey|rcon_password|set\s+mysql|sv_master|sv_endpoint|steam_webApiKey)') {
            $cfgOut += "$rel`:$($i+1)  $(Redact $ln)"
        }
    }
}
Code $cfgOut 150
W ""
W "**Action for you:** every ``add_principal`` / ``add_ace`` identifier, every ``exec``, and every"
W "``ensure`` must be one you recognise. One line you cannot account for is a permanent backdoor."

# ================================================================== C. HOST
Sec "C1. Local accounts and Administrators"
Code (@(net localgroup administrators 2>$null)) 30
Code (@(Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon |
        Format-Table -AutoSize | Out-String -Width 160) -split "`n" | Where-Object { $_.Trim() }) 40

Sec "C2. Windows Defender - exclusions, state, detections"
$mp = Get-MpPreference
$defOut = @()
foreach ($p in @($mp.ExclusionPath)) { if ($p) { $defOut += "EXCLUSION-PATH   $p" } }
foreach ($p in @($mp.ExclusionProcess)) { if ($p) { $defOut += "EXCLUSION-PROC   $p" } }
foreach ($p in @($mp.ExclusionExtension)) { if ($p) { $defOut += "EXCLUSION-EXT    $p" } }
if ($mp.DisableRealtimeMonitoring) { $defOut += "REALTIME MONITORING IS DISABLED" }
$st = Get-MpComputerStatus
if ($st) { $defOut += "AV=$($st.AntivirusEnabled) RealTime=$($st.RealTimeProtectionEnabled) SigAge=$($st.AntivirusSignatureAge)d" }
foreach ($t in @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20)) {
    $defOut += "DETECTION  $($t.InitialDetectionTime)  $($t.ThreatID)  $(@($t.Resources) -join ';')"
}
Code $defOut 50
W ""
W "> An antivirus exclusion covering the server folder is a near-certain compromise tell:"
W "> attackers add one so the payload is never scanned. If you did not create it, the covered"
W "> path should be treated as infected."

Sec "C3. Scheduled tasks (non-Microsoft)"
Code (@(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
            $a = (@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ')
            if ($a.Trim()) { "{0}{1}`n     author={2}  ->  {3}" -f $_.TaskPath, $_.TaskName, $_.Author, (Redact $a) }
        })) 60

Sec "C4. Services with binaries in user-writable paths"
Code (@(Get-CimInstance Win32_Service | Where-Object {
            $_.PathName -match '\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Downloads\\|\\PerfLogs\\'
        } | ForEach-Object { "{0}  state={1} start={2}`n     {3}" -f $_.Name, $_.State, $_.StartMode, $_.PathName })) 40

Sec "C5. Autoruns - Run keys and Startup folders"
$runOut = @()
foreach ($k in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
    if (-not (Test-Path $k)) { continue }
    foreach ($p in (Get-ItemProperty -Path $k).PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $runOut += "$k :: $($p.Name) = $(Redact ([string]$p.Value))"
    }
}
foreach ($sf in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
    foreach ($f in @(Get-ChildItem -LiteralPath $sf -File)) { $runOut += "STARTUP-FOLDER :: $($f.FullName)" }
}
Code $runOut 50

Sec "C6. WMI permanent event subscriptions (fileless persistence)"
Code (@(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
        ForEach-Object { "CONSUMER  $($_.Name)  ->  $(Redact $_.CommandLineTemplate)" })) 30
W ""
W "> WMI subscriptions survive reboots and every file-level cleanup. This is the most"
W "> commonly missed re-infection mechanism."

Sec "C7. Remote-access tooling"
$rat = 'anydesk|rustdesk|teamviewer|ngrok|frpc|frps|supremo|atera|screenconnect|netsupport|radmin|ammyy|dwagent|meshagent'
$ratOut = @()
$ratOut += @(Get-Process | Where-Object ProcessName -match $rat | ForEach-Object { "RUNNING    $($_.ProcessName)  ($($_.Path))" })
$ratOut += @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName -match $rat } | ForEach-Object { "INSTALLED  $($_.DisplayName)  installed=$($_.InstallDate)" })
Code $ratOut 30

Sec "C8. Network - listeners, established connections, firewall, RDP"
Code (@(Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
            "LISTEN  {0,-16}:{1,-6}  {2}" -f $_.LocalAddress, $_.LocalPort, (Get-Process -Id $_.OwningProcess).ProcessName
        })) 50
W ""
Code (@(Get-NetTCPConnection -State Established |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } | ForEach-Object {
            "ESTAB   {0}:{1} <-> {2}:{3}  {4}" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, (Get-Process -Id $_.OwningProcess).ProcessName
        })) 60
W ""
Code (@(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
        Where-Object { [string]::IsNullOrEmpty($_.Group) } | Select-Object -First 50 | ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter
            "FW-IN   {0}  ports={1} proto={2}" -f $_.DisplayName, $pf.LocalPort, $pf.Protocol
        })) 50
W ""
$fDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
Code @("RDP enabled (fDenyTSConnections=0 means enabled): $fDeny", "RDP NLA (UserAuthentication=1 means on): $nla") 0

Sec "C9. Hosts file (non-default entries)"
Code (@(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*(#|$)' })) 20

Sec "C10. Logon history and account changes"
if ($isAdmin) {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4624; StartTime = $cutoff } -MaxEvents 600)
    $rows = $ev | ForEach-Object {
        $x = [xml]$_.ToXml()
        [pscustomobject]@{
            User = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            Type = ($x.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
            IP   = ($x.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
        }
    } | Where-Object { $_.User -and $_.User -notmatch '\$$' -and $_.Type -in @('3', '7', '10') -and $_.IP -and $_.IP -ne '-' -and $_.IP -notmatch '^(127\.|::1)' }
    Code (@($rows | Group-Object User, IP | Sort-Object Count -Descending |
            ForEach-Object { "{0,-6} x  {1}" -f $_.Count, $_.Name })) 50
    W ""
    W "Failed logons (4625) in window: **$(@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$cutoff} -MaxEvents 5000).Count)**"
    W ""
    W "Account changes (created/enabled/password-reset/added-to-group):"
    Code (@(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4720, 4722, 4724, 4728, 4732, 4738; StartTime = $cutoff } -MaxEvents 60 |
            ForEach-Object { "{0}  EventID={1}  {2}" -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $_.Id, (($_.Message -split "`r?`n" | Where-Object { $_ -match 'Account Name|Group Name' }) -join ' / ') })) 50
}
else { W "_Skipped - requires an elevated PowerShell. Re-run as Administrator for this section._" }

# ------------------------------------------------------------------ finish
W ""
W "---"
W "Prepared by: $CREDIT"

$script:Out.ToString() | Set-Content -LiteralPath $REPORT -Encoding UTF8

$critCount = @($hits | Where-Object Sev -eq 'critical').Count
Write-Host ""
Write-Host "Collection complete." -ForegroundColor Green
Write-Host "  IOC hits (critical): $critCount"
Write-Host "  Manifest issues    : $($manOut.Count)"
Write-Host "  Report             : $REPORT"
Write-Host ""
Write-Host "Review TRIAGE.md yourself before sending it anywhere. Secret values are redacted;" -ForegroundColor Yellow
Write-Host "logon source IPs are not." -ForegroundColor Yellow
Write-Host "Prepared by: $CREDIT"
