# One-shot orchestrator for the RQ2 injection dataset.
#
# Boots the ETW-TI capture chain once, then runs N iterations of each specified
# manifest under Run-PPLExperiment.ps1. Prints a summary at the end so you can
# tell at a glance which runs produced data.
#
# Usage (default: 5 runs each of the three injection techniques):
#   .\experiments\Run-RQ2Dataset.ps1
#
# Custom:
#   .\experiments\Run-RQ2Dataset.ps1 -RunsPerManifest 10 `
#       -Manifests basic-loadlibrary,basic-threadhijack

[CmdletBinding()]
param(
    [int]$RunsPerManifest = 5,
    [string[]]$Manifests  = @('basic-loadlibrary', 'basic-threadhijack', 'basic-manualmap'),
    [int]$InterRunSleepSeconds = 3,
    [switch]$SkipBootstrap
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot            = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$bootstrapScript     = Join-Path $PSScriptRoot 'Bootstrap-ETWTI.ps1'
$runScript           = Join-Path $PSScriptRoot 'Run-PPLExperiment.ps1'
$manifestsDir        = Join-Path $PSScriptRoot 'manifests'
$runsDir             = Join-Path $PSScriptRoot 'runs'

if (-not $SkipBootstrap) {
    Write-Host ''
    & $bootstrapScript
}

$campaign = @()
$startedAt = Get-Date

foreach ($m in $Manifests) {
    $manifestPath = Join-Path $manifestsDir "$m.json"
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Write-Warning "Manifest not found: $manifestPath - skipping"
        continue
    }

    for ($i = 1; $i -le $RunsPerManifest; $i++) {
        Write-Host ''
        Write-Host ("=== {0}  run {1}/{2} ===" -f $m, $i, $RunsPerManifest) -ForegroundColor Cyan
        $entry = [pscustomobject]@{
            manifest = $m
            iteration = $i
            status   = 'unknown'
            runDir   = $null
            error    = $null
        }
        try {
            & $runScript -ManifestPath $manifestPath
            # The most recently created run dir belonging to this manifest is ours.
            $entry.runDir = (Get-ChildItem $runsDir -Directory |
                             Where-Object { $_.Name -like "*-$m+ppl" } |
                             Sort-Object LastWriteTime -Descending |
                             Select-Object -First 1).FullName
            $entry.status = 'completed'
        }
        catch {
            $entry.status = 'failed'
            $entry.error  = $_.Exception.Message
            Write-Warning "Run failed: $($_.Exception.Message)"
        }
        $campaign += $entry
        Start-Sleep -Seconds $InterRunSleepSeconds
    }
}

$elapsed = (Get-Date) - $startedAt

Write-Host ''
Write-Host '=== Campaign summary ===' -ForegroundColor Cyan
$campaign | Format-Table manifest, iteration, status, runDir -AutoSize

$byStatus = $campaign | Group-Object status
Write-Host ('Total runs: {0}   elapsed: {1:hh\:mm\:ss}' -f $campaign.Count, $elapsed)
foreach ($g in $byStatus) {
    Write-Host ('  {0}: {1}' -f $g.Name, $g.Count)
}

# Save the campaign log so it's easy to reference later.
$campaignLog = Join-Path $runsDir ("campaign-" + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.json')
$campaign | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $campaignLog -Encoding utf8
Write-Host ("Campaign log: {0}" -f $campaignLog)
