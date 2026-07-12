# One-shot orchestrator for the RQ2 injection dataset.
#
# Boots the ETW-TI capture chain once, then runs N iterations of each specified
# manifest under Run-PPLExperiment.ps1. Prints a summary at the end so you can
# tell at a glance which runs produced data.
#
# Execution order is RANDOMIZED across manifests by default so any environmental
# drift is spread across techniques rather than biasing a single block. Pass
# -NoShuffle to run techniques in the order they appear in -Manifests.
#
# Usage (default: 10 runs each of baseline + four attack techniques, shuffled):
#   .\experiments\Run-RQ2Dataset.ps1
#
# Custom:
#   .\experiments\Run-RQ2Dataset.ps1 -RunsPerManifest 5 `
#       -Manifests basic-loadlibrary,basic-threadhijack

[CmdletBinding()]
param(
    [int]$RunsPerManifest = 10,
    [string[]]$Manifests  = @(
        'baseline',
        'basic-loadlibrary',
        'basic-threadhijack',
        'basic-manualmap',
        'basic-patch-data'
    ),
    [int]$InterRunSleepSeconds = 3,
    [switch]$SkipBootstrap,
    [switch]$NoShuffle
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

# Build the schedule of (manifest, iteration) jobs. We resolve manifest paths
# upfront so a missing file is caught before any run starts.
$schedule = @()
foreach ($m in $Manifests) {
    $manifestPath = Join-Path $manifestsDir "$m.json"
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Write-Warning "Manifest not found: $manifestPath - skipping"
        continue
    }
    for ($i = 1; $i -le $RunsPerManifest; $i++) {
        $schedule += [pscustomobject]@{
            manifest     = $m
            iteration    = $i
            manifestPath = $manifestPath
        }
    }
}

# Randomize execution order (unless -NoShuffle). Get-Random -Count N returns N
# random elements without repetition; when N == Count, that's a full shuffle.
if (-not $NoShuffle -and $schedule.Count -gt 1) {
    $schedule = @($schedule | Get-Random -Count $schedule.Count)
    Write-Host ("Randomized execution order across {0} runs" -f $schedule.Count) -ForegroundColor Yellow
}

$runIdx = 0
foreach ($job in $schedule) {
    $runIdx++
    Write-Host ''
    Write-Host ("=== [{0}/{1}] {2}  iteration {3}/{4} ===" -f $runIdx, $schedule.Count, $job.manifest, $job.iteration, $RunsPerManifest) -ForegroundColor Cyan
    $entry = [pscustomobject]@{
        order     = $runIdx
        manifest  = $job.manifest
        iteration = $job.iteration
        status    = 'unknown'
        runDir    = $null
        error     = $null
    }
    try {
        & $runScript -ManifestPath $job.manifestPath
        # The most recently created run dir belonging to this manifest is ours.
        $entry.runDir = (Get-ChildItem $runsDir -Directory |
                         Where-Object { $_.Name -like "*-$($job.manifest)-ppl" } |
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

$elapsed = (Get-Date) - $startedAt

Write-Host ''
Write-Host '=== Campaign summary ===' -ForegroundColor Cyan
$campaign | Format-Table order, manifest, iteration, status, runDir -AutoSize

$byStatus = $campaign | Group-Object status
Write-Host ('Total runs: {0}   elapsed: {1:hh\:mm\:ss}' -f $campaign.Count, $elapsed)
foreach ($g in $byStatus) {
    Write-Host ('  {0}: {1}' -f $g.Name, $g.Count)
}

Write-Host ''
Write-Host '=== Per-manifest breakdown ===' -ForegroundColor Cyan
$campaign | Group-Object manifest | Sort-Object Name | ForEach-Object {
    $ok   = ($_.Group | Where-Object status -eq 'completed').Count
    $fail = ($_.Group | Where-Object status -eq 'failed').Count
    Write-Host ('  {0,-22} completed: {1,3}   failed: {2}' -f $_.Name, $ok, $fail)
}

# Save the campaign log so it's easy to reference later.
$campaignLog = Join-Path $runsDir ("campaign-" + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.json')
$campaign | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $campaignLog -Encoding utf8
Write-Host ("Campaign log: {0}" -f $campaignLog)
