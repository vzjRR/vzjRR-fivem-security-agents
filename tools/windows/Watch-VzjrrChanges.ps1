<#
.SYNOPSIS
    vzjRR Security Assessment for FiveM - file change detection for the post-cleanup watch.

.DESCRIPTION
    Records a SHA-256 baseline of every script and config file under the server root, then
    diffs against it on demand. Read-only in both modes.

    After a cleanup, this is what turns "I hope they're gone" into "nothing has changed
    since Tuesday." Three files matter most and change rarely - admins.json, server.cfg and
    any fxmanifest.lua - so any change to them is reported as CRITICAL.

.PARAMETER ServerRoot
    Server root - the folder containing resources/, server.cfg and txData/.

.PARAMETER BaselineFile
    Where the baseline CSV lives. Keep it OUTSIDE the server tree, ideally off the host.

.PARAMETER Mode
    Baseline = record current state. Compare = diff current state against the baseline.

.EXAMPLE
    # Right after verification passes
    .\Watch-VzjrrChanges.ps1 -ServerRoot 'C:\FXServer\server-data' -BaselineFile 'C:\vzjrr-audit\baseline.csv' -Mode Baseline

.EXAMPLE
    # Daily for 7 days, then weekly
    .\Watch-VzjrrChanges.ps1 -ServerRoot 'C:\FXServer\server-data' -BaselineFile 'C:\vzjrr-audit\baseline.csv' -Mode Compare

.NOTES
    Exit codes: 0 = no changes, 1 = changes found, 2 = critical-file changes found.
    Prepared by: vzjRR Security Assessment for FiveM
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerRoot,
    [Parameter(Mandatory = $true)][string]$BaselineFile,
    [Parameter(Mandatory = $true)][ValidateSet('Baseline', 'Compare')][string]$Mode
)

$ErrorActionPreference = 'Stop'
$CREDIT = 'vzjRR Security Assessment for FiveM'
$ServerRoot = (Resolve-Path -LiteralPath $ServerRoot).Path.TrimEnd('\')

$exts = @('.lua', '.js', '.mjs', '.cjs', '.cfg', '.json')
function Test-Critical($rel) {
    return ($rel -match '(^|\\)(admins\.json|server\.cfg|fxmanifest\.lua|__resource\.lua)$')
}

Write-Host "$CREDIT - change watch ($Mode)" -ForegroundColor Cyan
Write-Host "  Server root : $ServerRoot"
Write-Host "  Baseline    : $BaselineFile"

Write-Host "  Hashing ..." -ForegroundColor DarkGray
$current = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $ServerRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension.ToLower() -in $exts -and $_.FullName -notmatch '\\(cache|logs|\.git)\\' })) {
    $rel = $f.FullName.Substring($ServerRoot.Length).TrimStart('\')
    try { $current[$rel] = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch { }
}
Write-Host "  $($current.Count) files hashed."

if ($Mode -eq 'Baseline') {
    $dir = Split-Path $BaselineFile -Parent
    if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $current.GetEnumerator() | Sort-Object Name |
        ForEach-Object { [pscustomobject]@{ RelativePath = $_.Key; Sha256 = $_.Value } } |
        Export-Csv -LiteralPath $BaselineFile -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "Baseline written: $BaselineFile" -ForegroundColor Green
    Write-Host "Keep a copy OFF this host - an attacker with access edits local baselines." -ForegroundColor Yellow
    Write-Host "Prepared by: $CREDIT"
    exit 0
}

if (-not (Test-Path -LiteralPath $BaselineFile)) { throw "Baseline not found: $BaselineFile. Run -Mode Baseline first." }
$base = @{}
foreach ($r in (Import-Csv -LiteralPath $BaselineFile)) { $base[$r.RelativePath] = $r.Sha256 }
Write-Host "  $($base.Count) files in baseline."

$added = @(); $changed = @(); $removed = @()
foreach ($k in $current.Keys) {
    if (-not $base.ContainsKey($k)) { $added += $k }
    elseif ($base[$k] -ne $current[$k]) { $changed += $k }
}
foreach ($k in $base.Keys) { if (-not $current.ContainsKey($k)) { $removed += $k } }

$critical = @(@($added + $changed + $removed) | Where-Object { Test-Critical $_ })

Write-Host ""
if ($critical.Count -gt 0) {
    Write-Host "CRITICAL-FILE CHANGES ($($critical.Count))" -ForegroundColor Red
    foreach ($c in $critical) { Write-Host "  !! $c" -ForegroundColor Red }
    Write-Host ""
    Write-Host "  admins.json, server.cfg and fxmanifest.lua change rarely. If you did not make" -ForegroundColor Red
    Write-Host "  this change, stop the server and preserve evidence BEFORE touching anything." -ForegroundColor Red
    Write-Host ""
}
foreach ($set in @(@{N = 'ADDED'; V = $added; C = 'Yellow' }, @{N = 'CHANGED'; V = $changed; C = 'Yellow' }, @{N = 'REMOVED'; V = $removed; C = 'DarkGray' })) {
    if ($set.V.Count -eq 0) { continue }
    Write-Host "$($set.N) ($($set.V.Count))" -ForegroundColor $set.C
    foreach ($x in ($set.V | Sort-Object | Select-Object -First 60)) { Write-Host "  $x" }
    if ($set.V.Count -gt 60) { Write-Host "  ... $($set.V.Count - 60) more" }
    Write-Host ""
}

if ($added.Count + $changed.Count + $removed.Count -eq 0) {
    Write-Host "No changes since baseline." -ForegroundColor Green
}
Write-Host "Prepared by: $CREDIT"

if ($critical.Count -gt 0) { exit 2 }
if ($added.Count + $changed.Count + $removed.Count -gt 0) { exit 1 }
exit 0
