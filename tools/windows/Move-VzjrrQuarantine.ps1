<#
.SYNOPSIS
    vzjRR Security Assessment for FiveM - safe quarantine helper.

.DESCRIPTION
    Copies a suspect file to a quarantine folder OUTSIDE the server tree, records its
    SHA-256 and the reason, verifies the copy matches the original, and only then - and
    only with -Delete - removes the original.

    Never delete a suspect file directly. If a cleanup goes wrong, quarantine is how you
    put it back, and the hash log is your evidence of what was there.

.PARAMETER Path
    File(s) to quarantine. Accepts pipeline input, wildcards, and multiple paths.

.PARAMETER ServerRoot
    Server root, used to preserve the relative path inside quarantine.

.PARAMETER QuarantineDir
    Quarantine folder. Must be OUTSIDE ServerRoot. Reused across batches so one incident
    keeps one manifest.

.PARAMETER Reason
    Short note recorded in the manifest, e.g. "MAN-001 padded manifest injection".

.PARAMETER Delete
    Remove the original after the copy is verified. Without this, the file is only copied
    (a dry run you can inspect first).

.EXAMPLE
    # Dry run - copy to quarantine, leave the original in place
    .\Move-VzjrrQuarantine.ps1 -Path 'C:\FXServer\server-data\resources\[core]\mycore\.babelrc.js' `
        -ServerRoot 'C:\FXServer\server-data' -QuarantineDir 'C:\vzjrr-quarantine' -Reason 'Blum loader'

.EXAMPLE
    # Same, then remove the original
    .\Move-VzjrrQuarantine.ps1 -Path '...\.babelrc.js' -ServerRoot 'C:\FXServer\server-data' `
        -QuarantineDir 'C:\vzjrr-quarantine' -Reason 'Blum loader' -Delete

.EXAMPLE
    # Batch from a file listing one path per line
    Get-Content C:\to-remove.txt | .\Move-VzjrrQuarantine.ps1 -ServerRoot 'C:\FXServer\server-data' `
        -QuarantineDir 'C:\vzjrr-quarantine' -Reason 'confirmed loader' -Delete

.NOTES
    Prepared by: vzjRR Security Assessment for FiveM
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)][string[]]$Path,
    [Parameter(Mandatory = $true)][string]$ServerRoot,
    [Parameter(Mandatory = $true)][string]$QuarantineDir,
    [string]$Reason = 'unspecified',
    [switch]$Delete
)

begin {
    $ErrorActionPreference = 'Stop'
    $CREDIT = 'vzjRR Security Assessment for FiveM'

    $ServerRoot = (Resolve-Path -LiteralPath $ServerRoot).Path.TrimEnd('\')
    if ($QuarantineDir.ToLower().StartsWith($ServerRoot.ToLower())) {
        throw "QuarantineDir must be OUTSIDE ServerRoot. Quarantine inside a compromised tree is not quarantine."
    }
    New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null
    $manifest = Join-Path $QuarantineDir 'QUARANTINE_MANIFEST.csv'
    if (-not (Test-Path $manifest)) {
        'TimestampUtc,Action,RelativePath,Sha256,SizeBytes,Reason,QuarantineCopy' |
            Set-Content -LiteralPath $manifest -Encoding UTF8
    }
    $ok = 0; $failed = 0; $deleted = 0
    Write-Host "$CREDIT - quarantine" -ForegroundColor Cyan
    Write-Host "  Server root : $ServerRoot"
    Write-Host "  Quarantine  : $QuarantineDir"
    Write-Host "  Delete mode : $($Delete.IsPresent)" -ForegroundColor $(if ($Delete) { 'Yellow' } else { 'Green' })
}

process {
    foreach ($p in $Path) {
        foreach ($item in @(Get-Item -Path $p -Force -ErrorAction SilentlyContinue)) {
            if (-not $item -or $item.PSIsContainer) {
                Write-Warning "Skipping (not a file): $p"
                $failed++
                continue
            }
            $full = $item.FullName
            if (-not $full.ToLower().StartsWith($ServerRoot.ToLower())) {
                Write-Warning "Skipping (outside ServerRoot): $full"
                $failed++
                continue
            }

            $rel = $full.Substring($ServerRoot.Length).TrimStart('\')
            $dest = Join-Path $QuarantineDir $rel
            $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash

            if ($PSCmdlet.ShouldProcess($rel, 'quarantine')) {
                New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
                # If this path was quarantined before, keep both copies rather than overwrite.
                if (Test-Path -LiteralPath $dest) {
                    $dest = "$dest.$((Get-Date).ToString('HHmmss'))"
                }
                Copy-Item -LiteralPath $full -Destination $dest -Force

                $copyHash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
                if ($copyHash -ne $hash) {
                    Write-Host "  [FAIL] copy hash mismatch, original left in place: $rel" -ForegroundColor Red
                    $failed++
                    continue
                }

                $action = 'COPIED'
                if ($Delete) {
                    Remove-Item -LiteralPath $full -Force
                    if (Test-Path -LiteralPath $full) {
                        Write-Host "  [FAIL] could not delete: $rel" -ForegroundColor Red
                        $failed++
                        continue
                    }
                    $action = 'QUARANTINED+DELETED'
                    $deleted++
                }

                $row = '{0},{1},"{2}",{3},{4},"{5}","{6}"' -f `
                    (Get-Date).ToUniversalTime().ToString('o'), $action, $rel, $hash,
                    $item.Length, ($Reason -replace '"', "'"), ($dest -replace '"', "'")
                Add-Content -LiteralPath $manifest -Value $row -Encoding UTF8

                $col = if ($Delete) { 'Yellow' } else { 'Green' }
                Write-Host "  [$action] $rel" -ForegroundColor $col
                Write-Host "      sha256 $hash" -ForegroundColor DarkGray
                $ok++
            }
        }
    }
}

end {
    Write-Host ""
    Write-Host "Quarantined: $ok   Deleted: $deleted   Failed/skipped: $failed"
    Write-Host "Manifest   : $manifest"
    Write-Host ""
    Write-Host "To restore a file:" -ForegroundColor Cyan
    Write-Host "  Copy-Item '<quarantine copy>' '<original path>' -Force"
    Write-Host "Prepared by: $CREDIT"
}
