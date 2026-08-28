<#
.SYNOPSIS
    vzjRR Security Assessment for FiveM - read-only resource / manifest scanner (Windows).

.DESCRIPTION
    Scans a FiveM server tree for the Blum / Kercher / generic "-panel" backdoor family:
    whitespace-padded fxmanifest injections, hidden loader scripts, remote-code-execution
    patterns, credential-theft code and extortion lock strings.

    This script NEVER writes to, modifies, executes or deletes anything inside the target
    tree. It only reads. All output goes to -OutDir, which must be outside the target.

.PARAMETER Path
    Root of the server tree to scan. Point this at the SERVER ROOT (the folder containing
    resources/, server.cfg and txData/), not just resources/ - scoping to resources/ alone
    is how re-entry paths get missed.

.PARAMETER OutDir
    Where to write the report. Defaults to .\vzjrr-audit\<timestamp> in the current directory.

.PARAMETER IocPath
    Path to ioc/iocs.json. Defaults to the repo copy relative to this script.

.PARAMETER SinceDays
    Also flag files modified within this many days (intrusion-window triage). Default 30.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-VzjrrResourceScan.ps1 -Path 'C:\FXServer\server-data' -OutDir 'C:\vzjrr-audit'

.NOTES
    Prepared by: vzjRR Security Assessment for FiveM
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$OutDir = "",
    [string]$IocPath = "",
    [int]$SinceDays = 30,
    [int]$MaxFileSizeMB = 12
)

$ErrorActionPreference = 'Continue'
$CREDIT = 'vzjRR Security Assessment for FiveM'

function Write-Head($t) { Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Cyan }
function Write-Hit($sev, $msg) {
    $c = switch ($sev) { 'critical' { 'Red' } 'high' { 'Magenta' } 'medium' { 'Yellow' } default { 'Gray' } }
    Write-Host ("[{0,-8}] {1}" -f $sev.ToUpper(), $msg) -ForegroundColor $c
}

# ---------------------------------------------------------------- setup
$Path = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ("vzjrr-audit\" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
if ($OutDir.ToLower().StartsWith($Path.ToLower())) {
    throw "OutDir must be OUTSIDE the target tree. Evidence written inside a compromised tree is not evidence."
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $IocPath) {
    $candidate = Join-Path $PSScriptRoot '..\..\ioc\iocs.json'
    if (Test-Path $candidate) { $IocPath = (Resolve-Path $candidate).Path }
}

$sigs = @()
$critNames = @(); $highNames = @(); $netPatterns = @()
if ($IocPath -and (Test-Path $IocPath)) {
    $ioc = Get-Content -LiteralPath $IocPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($s in $ioc.code_signatures) { $sigs += [pscustomobject]@{ id = $s.id; sev = $s.severity; rx = $s.pattern; why = $s.why } }
    $critNames = @($ioc.suspicious_filenames.critical)
    $highNames = @($ioc.suspicious_filenames.high)
    foreach ($d in $ioc.network_indicators.domains_exact) { $netPatterns += [pscustomobject]@{ id = 'NET-DOMAIN'; sev = 'critical'; rx = [regex]::Escape($d); why = "Known malicious panel/C2 host: $d" } }
    foreach ($p in $ioc.network_indicators.domain_patterns) { $netPatterns += [pscustomobject]@{ id = 'NET-PANEL'; sev = 'critical'; rx = $p; why = 'Matches the *-panel C2 naming pattern.' } }
    foreach ($p in $ioc.network_indicators.exfil_patterns) { $netPatterns += [pscustomobject]@{ id = 'NET-EXFIL'; sev = 'high'; rx = $p; why = 'Discord webhook - common exfiltration channel.' } }
    foreach ($p in $ioc.network_indicators.payload_host_patterns) { $netPatterns += [pscustomobject]@{ id = 'NET-PAYLOAD'; sev = 'high'; rx = $p; why = 'Known payload-hosting endpoint.' } }
    $sigs += $netPatterns
    Write-Host "Loaded $($sigs.Count) detection patterns from $IocPath" -ForegroundColor Green
}
else {
    Write-Warning "iocs.json not found - falling back to the built-in core set (reduced coverage)."
    $fallback = @(
        @('SIG-LOCK-001', 'critical', 'Server is locked by', 'Extortion lock message.'),
        @('NET-PANEL', 'critical', '[a-z0-9_-]{2,30}-panel\.(me|xyz|cc|su|ru|top|store|shop|online|site)', 'Panel C2 host.'),
        @('SIG-BLUM-002', 'critical', 'helpEmptyCode', 'Known loader function.'),
        @('SIG-BLUM-003', 'critical', 'onServerResourceFail', 'Known loader hook.'),
        @('SIG-BLUM-004', 'critical', 'RESOURCE_EXCLUDE', 'Loader self-exclusion list.'),
        @('SIG-BLUM-005', 'critical', 'JohnsUrUncle', 'Known family string.'),
        @('SIG-LUA-001', 'critical', 'PerformHttpRequest[\s\S]{0,400}?(load|loadstring)\s*\(', 'Remote code execution loader.'),
        @('SIG-JS-001', 'critical', 'eval\s*\([\s\S]{0,200}?Buffer\.from\s*\([^)]*base64', 'Executes base64-decoded code.'),
        @('SIG-THEFT-001', 'critical', 'admins\.json', 'txAdmin credential store access.'),
        @('SIG-THEFT-002', 'critical', 'sv_licenseKey', 'License key harvesting.'),
        @('NET-EXFIL', 'high', 'discord(app)?\.com/api/webhooks/', 'Discord webhook exfiltration.')
    )
    foreach ($f in $fallback) { $sigs += [pscustomobject]@{ id = $f[0]; sev = $f[1]; rx = $f[2]; why = $f[3] } }
    $critNames = @('sv_init.mjs', 'sv_init.js', 'blum.js', 'kercher.js', 'panel.js')
    $highNames = @('.babelrc.js', 'babel_config.js', 'crypto.js', '.yarn.js')
}

$textExt = @('.lua', '.js', '.mjs', '.cjs', '.json', '.cfg', '.txt', '.md', '.yml', '.yaml', '.ts', '.html', '.css', '.sql', '.bat', '.ps1', '.sh', '.env', '.ini', '.conf')
$findings = New-Object System.Collections.Generic.List[object]
$cutoff = (Get-Date).AddDays(-$SinceDays)

function Add-Finding($id, $sev, $file, $line, $evidence, $why) {
    $findings.Add([pscustomobject]@{
            id = $id; severity = $sev; file = $file; line = $line
            evidence = $evidence; why = $why
        })
}

function Get-Sha256($f) {
    try { (Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'unavailable' }
}

# ---------------------------------------------------------------- enumerate
Write-Head "Scope"
Write-Host "Target : $Path"
Write-Host "Output : $OutDir"
Write-Host "Credit : $CREDIT"

Write-Head "Enumerating files"
$all = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)

# Never scan the toolkit's own tree: its IOC set and docs contain every pattern by
# definition, and would otherwise produce a false COMPROMISED verdict when the toolkit
# is cloned inside the server folder being scanned.
$toolkitRoots = @($all | Where-Object { $_.Name -eq '.vzjrr-toolkit-root' } | ForEach-Object { $_.Directory.FullName })
if ($toolkitRoots.Count -gt 0) {
    foreach ($tr in $toolkitRoots) { Write-Host "  (excluded toolkit tree: $tr)" -ForegroundColor DarkGray }
    $all = @($all | Where-Object { $f = $_.FullName; -not ($toolkitRoots | Where-Object { $f.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }) })
}
Write-Host "$($all.Count) files found."

$maxBytes = $MaxFileSizeMB * 1MB
$scanned = 0

# ---------------------------------------------------------------- content scan
Write-Head "Content signature scan"
foreach ($f in $all) {
    $rel = $f.FullName.Substring($Path.Length).TrimStart('\')
    $ext = $f.Extension.ToLower()

    # Suspicious filename check (runs on every file, regardless of type)
    if ($critNames -contains $f.Name) {
        Add-Finding 'FILE-CRIT' 'critical' $rel 0 $f.Name 'Filename matches a known loader drop point for this malware family.'
        Write-Hit 'critical' "$rel  (known loader filename)"
    }
    elseif ($highNames -contains $f.Name) {
        Add-Finding 'FILE-HIGH' 'high' $rel 0 $f.Name 'Fake build-tooling filename used to disguise a loader inside a FiveM resource.'
        Write-Hit 'high' "$rel  (fake tooling filename)"
    }

    # Zero-byte script stubs
    if ($f.Length -eq 0 -and ($ext -in @('.js', '.mjs', '.lua'))) {
        Add-Finding 'FILE-STUB' 'medium' $rel 0 '0 bytes' 'Zero-byte script - typically a loader that wiped itself after execution, or a placeholder left by an incomplete cleanup.'
    }

    if ($ext -notin $textExt) { continue }
    if ($f.Length -gt $maxBytes) { continue }

    try { $lines = [System.IO.File]::ReadAllLines($f.FullName) } catch { continue }
    $scanned++

    # Match against the whole file body rather than line by line: several loader
    # signatures deliberately span multiple lines (fetch on one line, eval on the
    # next). Line numbers are recovered from the match offset.
    $body = [string]::Join("`n", $lines)
    $starts = New-Object 'System.Int32[]' ($lines.Count + 1)
    $acc = 0
    for ($i = 0; $i -lt $lines.Count; $i++) { $starts[$i] = $acc; $acc += $lines[$i].Length + 1 }
    $starts[$lines.Count] = $acc

    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($s in $sigs) {
        $ms = [regex]::Matches($body, $s.rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $ms) {
            # binary search for the line containing this offset
            $lo = 0; $hi = $lines.Count - 1
            while ($lo -lt $hi) {
                $mid = [int](($lo + $hi + 1) / 2)
                if ($starts[$mid] -le $m.Index) { $lo = $mid } else { $hi = $mid - 1 }
            }
            $lineNo = $lo + 1
            $key = "$($s.id)|$lineNo"
            if (-not $seen.Add($key)) { continue }
            $ev = if ($lo -lt $lines.Count) { $lines[$lo].Trim() } else { $m.Value }
            if ($m.Value -match "`n") { $ev = ($m.Value -replace '\s+', ' ').Trim() }
            if ($ev.Length -gt 240) { $ev = $ev.Substring(0, 240) + ' ...[truncated]' }
            Add-Finding $s.id $s.sev $rel $lineNo $ev $s.why
            Write-Hit $s.sev "$rel`:$lineNo  $($s.id)"
        }
    }
}
Write-Host "$scanned text files scanned."

# ---------------------------------------------------------------- manifest audit
Write-Head "Manifest injection audit"
$manifests = @($all | Where-Object { $_.Name -in @('fxmanifest.lua', '__resource.lua') })
Write-Host "$($manifests.Count) manifests found."

foreach ($m in $manifests) {
    $rel = $m.FullName.Substring($Path.Length).TrimStart('\')
    $resDir = $m.Directory.FullName
    try { $lines = [System.IO.File]::ReadAllLines($m.FullName) } catch { continue }

    $blankRun = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]

        # MAN-001: whitespace-padded hidden directive
        if ($ln -match '^\s*$') { $blankRun++ } else {
            if ($blankRun -ge 20) {
                Add-Finding 'MAN-005' 'high' $rel ($i + 1) "$blankRun blank lines then: $($ln.Trim())" 'Content hidden behind a large blank gap so it scrolls out of the editor view.'
                Write-Hit 'high' "$rel`:$($i+1)  MAN-005 hidden after $blankRun blank lines"
            }
            $blankRun = 0
        }

        if ($ln -match '[ \t]{60,}') {
            $trimmed = $ln.Trim()
            if ($trimmed.Length -gt 0) {
                $ev = $trimmed; if ($ev.Length -gt 200) { $ev = $ev.Substring(0, 200) + ' ...' }
                Add-Finding 'MAN-001' 'critical' $rel ($i + 1) "PADDED: $ev" 'Whitespace-padded manifest line - the signature Blum/Kercher injection. The padding pushes the malicious directive beyond the editor viewport.'
                Write-Hit 'critical' "$rel`:$($i+1)  MAN-001 WHITESPACE-PADDED INJECTION"
            }
        }

        # MAN-003: fake tooling references
        foreach ($n in @('sv_init.mjs', 'sv_init.js', '.babelrc.js', 'babel_config.js', 'babel.config.js', 'crypto.js', '.yarn.js', 'node_modules/internal', 'webpack.config.js')) {
            if ($ln -like "*$n*") {
                Add-Finding 'MAN-003' 'critical' $rel ($i + 1) $ln.Trim() "Manifest references '$n' - a fake build-tooling path used as a loader entry point."
                Write-Hit 'critical' "$rel`:$($i+1)  MAN-003 references $n"
            }
        }

        # MAN-006: referenced script missing from disk
        if ($ln -match "['\`"]([A-Za-z0-9_\-./\\@\[\]]+\.(lua|js|mjs))['\`"]") {
            $refRaw = $Matches[1]
            if ($refRaw -notmatch '[\*\?]' -and $refRaw -notmatch '^https?:') {
                $refPath = Join-Path $resDir ($refRaw -replace '/', '\')
                if (-not (Test-Path -LiteralPath $refPath)) {
                    Add-Finding 'MAN-006' 'high' $rel ($i + 1) $refRaw "Manifest loads '$refRaw' but that file does not exist. Either a loader deleted itself after running, or a previous cleanup removed the file and left the reference - both mean this resource's history needs review."
                    Write-Hit 'high' "$rel`:$($i+1)  MAN-006 missing file $refRaw"
                }
            }
        }
    }

    # MAN-002: JS server_script inside an otherwise pure-Lua resource
    $body = ($lines -join "`n")
    if ($body -match "server_scripts?\s*[\{\(']?[^\n]*\.(js|mjs)") {
        $luaCount = @(Get-ChildItem -LiteralPath $resDir -Recurse -File -Filter *.lua -ErrorAction SilentlyContinue).Count
        $jsTop = @(Get-ChildItem -LiteralPath $resDir -File -Filter *.js -ErrorAction SilentlyContinue).Count
        if ($luaCount -gt 0 -and $jsTop -gt 0) {
            Add-Finding 'MAN-002' 'high' $rel 0 'server_script -> .js/.mjs in a Lua resource' 'A Lua resource that also loads a server-side JS file. Legitimate for a few known resources (oxmysql, screenshot-basic); a strong injection signal for everything else.'
            Write-Hit 'high' "$rel  MAN-002 server-side JS in a Lua resource"
        }
    }
}

# ---------------------------------------------------------------- timeline
Write-Head "Recently modified files (last $SinceDays days)"
$recent = @($all | Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Extension.ToLower() -in @('.lua', '.js', '.mjs', '.cfg', '.json') } | Sort-Object LastWriteTime -Descending)
Write-Host "$($recent.Count) script/config files modified in the window."
foreach ($r in ($recent | Select-Object -First 60)) {
    $rel = $r.FullName.Substring($Path.Length).TrimStart('\')
    Write-Host ("  {0}  {1}" -f $r.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $rel)
}

# ---------------------------------------------------------------- hash the hits
Write-Head "Hashing flagged files"
$hitFiles = $findings | Select-Object -ExpandProperty file -Unique
$hashes = @{}
foreach ($h in $hitFiles) {
    $full = Join-Path $Path $h
    if (Test-Path -LiteralPath $full -PathType Leaf) { $hashes[$h] = Get-Sha256 $full }
}
Write-Host "$($hashes.Count) files hashed."

# ---------------------------------------------------------------- report
Write-Head "Report"
$crit = @($findings | Where-Object severity -eq 'critical')
$high = @($findings | Where-Object severity -eq 'high')
$med = @($findings | Where-Object severity -eq 'medium')

$verdict = if ($crit.Count -gt 0) { 'COMPROMISED - critical indicators present' }
elseif ($high.Count -gt 0) { 'SUSPECTED COMPROMISE - high-severity indicators need manual confirmation' }
elseif ($med.Count -gt 0) { 'INCONCLUSIVE - medium indicators only' }
else { 'NO RESOURCE-TREE INDICATORS FOUND (this does NOT mean the host is clean - run the host audit)' }

$jsonOut = [pscustomobject]@{
    credit         = $CREDIT
    scanned_utc    = (Get-Date).ToUniversalTime().ToString('o')
    target         = $Path
    files_total    = $all.Count
    files_scanned  = $scanned
    manifests      = $manifests.Count
    counts         = @{ critical = $crit.Count; high = $high.Count; medium = $med.Count }
    verdict        = $verdict
    findings       = $findings
    hashes         = $hashes
    recent_changes = @($recent | Select-Object -First 200 | ForEach-Object { @{ file = $_.FullName.Substring($Path.Length).TrimStart('\'); mtime = $_.LastWriteTime.ToString('o') } })
}
$jsonPath = Join-Path $OutDir 'resource-scan.json'
$jsonOut | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# FiveM Resource Scan Report")
[void]$md.AppendLine("")
[void]$md.AppendLine("- **Target:** ``$Path``")
[void]$md.AppendLine("- **Scanned (UTC):** $((Get-Date).ToUniversalTime().ToString('u'))")
[void]$md.AppendLine("- **Files:** $($all.Count) total, $scanned text files scanned, $($manifests.Count) manifests")
[void]$md.AppendLine("- **Findings:** $($crit.Count) critical / $($high.Count) high / $($med.Count) medium")
[void]$md.AppendLine("- **Verdict:** $verdict")
[void]$md.AppendLine("")
[void]$md.AppendLine("> A clean resource scan does not mean a clean server. Host persistence, txAdmin admin accounts and stolen credentials survive file cleanup. Run ``Invoke-VzjrrHostAudit.ps1`` and complete the credential rotation before declaring recovery.")
[void]$md.AppendLine("")
foreach ($sev in @('critical', 'high', 'medium')) {
    $set = @($findings | Where-Object severity -eq $sev)
    if ($set.Count -eq 0) { continue }
    [void]$md.AppendLine("## " + $sev.ToUpper() + " ($($set.Count))")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("| ID | File | Line | Evidence | Why it matters |")
    [void]$md.AppendLine("|---|---|---|---|---|")
    foreach ($x in $set) {
        $e = ($x.evidence -replace '\|', '\|') -replace '[\r\n]', ' '
        $w = ($x.why -replace '\|', '\|')
        [void]$md.AppendLine("| $($x.id) | ``$($x.file)`` | $($x.line) | ``$e`` | $w |")
    }
    [void]$md.AppendLine("")
}
if ($hashes.Count -gt 0) {
    [void]$md.AppendLine("## SHA-256 of flagged files")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("| File | SHA-256 |")
    [void]$md.AppendLine("|---|---|")
    foreach ($k in ($hashes.Keys | Sort-Object)) { [void]$md.AppendLine("| ``$k`` | ``$($hashes[$k])`` |") }
    [void]$md.AppendLine("")
}
[void]$md.AppendLine("---")
[void]$md.AppendLine("Prepared by: $CREDIT")
$mdPath = Join-Path $OutDir 'resource-scan.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host ""
Write-Host "VERDICT: $verdict" -ForegroundColor $(if ($crit.Count) { 'Red' } elseif ($high.Count) { 'Magenta' } else { 'Green' })
Write-Host "Report : $mdPath"
Write-Host "JSON   : $jsonPath"
Write-Host "Prepared by: $CREDIT"

exit $(if ($crit.Count -gt 0) { 2 } elseif ($high.Count -gt 0) { 1 } else { 0 })
