# Orchestrator for the RQ3 evasion dataset.
#
# Boots the ETW-TI capture chain once, then runs N iterations of every
# manifest that ends in "_<tag>" for each tag in -EvasionTags. Prints a
# summary at the end.
#
# The RQ3 story is provider-degradation resilience: baseline captures run
# under Run-RQ2Dataset.ps1 (all three providers subscribed); this runner
# handles the evasion siblings. Additional evasion strategies added later
# just need a new manifest suffix (e.g. "_direct_syscall") and a matching
# generator script; the runner discovers them automatically via the
# -EvasionTags parameter.
#
# Execution order is RANDOMIZED across (manifest, iteration) pairs by
# default so environmental drift is spread evenly across techniques and
# tags rather than biasing a single block. Pass -NoShuffle to run in file
# order.
#
# Usage (default: 3 runs each of every _ti_only manifest, shuffled):
#   .\experiments\Run-RQ3Dataset.ps1
#
# Custom (multi-tag sweep, once we add another evasion technique):
#   .\experiments\Run-RQ3Dataset.ps1 -EvasionTags ti_only,direct_syscall
#
# Explicit manifest list (subset run):
#   .\experiments\Run-RQ3Dataset.ps1 -Manifests basic-loadlibrary_ti_only,apc_classic_ti_only

[CmdletBinding()]
param(
    [int]$RunsPerManifest = 3,
    [string[]]$EvasionTags = @('ti_only'),
    [string[]]$Manifests   = @(),
    [int]$InterRunSleepSeconds = 3,
    [switch]$SkipBootstrap,
    [switch]$NoShuffle
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot        = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$bootstrapScript = Join-Path $PSScriptRoot 'Bootstrap-ETWTI.ps1'
$runScript       = Join-Path $PSScriptRoot 'Run-PPLExperiment.ps1'
$manifestsDir    = Join-Path $PSScriptRoot 'manifests'
$runsDir         = Join-Path $PSScriptRoot 'runs'

# ---------------------------------------------------------------------------
# Resolve manifest list.
# ---------------------------------------------------------------------------
# If -Manifests was passed, use it verbatim (advanced/one-off runs).
# Otherwise glob every "<baseline>_<tag>.json" for each tag in -EvasionTags.
# The glob is what lets a new evasion technique join the sweep with zero
# runner changes: `generate-<newtag>-manifests.py`, then rerun this script
# with `-EvasionTags ti_only,<newtag>`.
if ($Manifests.Count -eq 0) {
    $discovered = @()
    foreach ($tag in $EvasionTags) {
        $matches = Get-ChildItem -LiteralPath $manifestsDir -Filter "*_$tag.json" -File
        if (-not $matches) {
            Write-Warning "No manifests matched *_$tag.json - skipping tag '$tag'"
            continue
        }
        foreach ($f in $matches) {
            # Strip .json for downstream naming, matching RQ2's convention.
            $discovered += ($f.BaseName)
        }
    }
    if ($discovered.Count -eq 0) {
        throw "No RQ3 manifests discovered for tags: $($EvasionTags -join ', ')"
    }
    $Manifests = $discovered
    Write-Host ("Discovered {0} RQ3 manifests across tags: {1}" -f `
        $Manifests.Count, ($EvasionTags -join ', ')) -ForegroundColor Yellow
}

if (-not $SkipBootstrap) {
    Write-Host ''
    & $bootstrapScript
}

# ---------------------------------------------------------------------------
# Build (manifest, iteration) schedule and optionally shuffle.
# ---------------------------------------------------------------------------
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

if (-not $NoShuffle -and $schedule.Count -gt 1) {
    $schedule = @($schedule | Get-Random -Count $schedule.Count)
    Write-Host ("Randomized execution order across {0} runs" -f $schedule.Count) -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Run each scheduled job. Same error-handling shape as Run-RQ2Dataset.ps1.
# ---------------------------------------------------------------------------
$campaign  = @()
$startedAt = Get-Date
$runIdx    = 0
foreach ($job in $schedule) {
    $runIdx++
    Write-Host ''
    Write-Host ("=== [{0}/{1}] {2}  iteration {3}/{4} ===" -f `
        $runIdx, $schedule.Count, $job.manifest, $job.iteration, $RunsPerManifest) `
        -ForegroundColor Cyan
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

# ---------------------------------------------------------------------------
# Summary + log.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '=== RQ3 campaign summary ===' -ForegroundColor Cyan
$campaign | Format-Table order, manifest, iteration, status, runDir -AutoSize

$byStatus = $campaign | Group-Object status
Write-Host ('Total runs: {0}   elapsed: {1:hh\:mm\:ss}' -f $campaign.Count, $elapsed)
foreach ($g in $byStatus) {
    Write-Host ('  {0}: {1}' -f $g.Name, $g.Count)
}

Write-Host ''
Write-Host '=== Per-manifest breakdown ===' -ForegroundColor Cyan
$campaign | Group-Object manifest | Sort-Object Name | ForEach-Object {
    $ok   = @($_.Group | Where-Object { $_.status -eq 'completed' }).Count
    $fail = @($_.Group | Where-Object { $_.status -eq 'failed' }).Count
    Write-Host ('  {0,-42} completed: {1,3}   failed: {2}' -f $_.Name, $ok, $fail)
}

$campaignLog = Join-Path $runsDir ("campaign-rq3-" + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.json')
$campaign | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $campaignLog -Encoding utf8
Write-Host ("Campaign log: {0}" -f $campaignLog)
