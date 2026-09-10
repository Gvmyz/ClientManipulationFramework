# Serial execution only: PPLRunner and the ETW session are machine-wide.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Plan,
    [switch]$PreflightOnly,
    [switch]$Resume,
    [switch]$SkipBootstrap,
    [switch]$AllowManualTools,
    [ValidateRange(0,60)] [int]$InterRunSleepSeconds = 3
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Campaign-Helpers.ps1')
$repo = Split-Path $PSScriptRoot -Parent
$planPath = (Resolve-Path -LiteralPath $Plan).Path
$p = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
foreach ($job in $p.runs) {
    if ((Get-FileHash -LiteralPath $job.manifest -Algorithm SHA256).Hash -ne $job.manifest_sha256) { throw "Frozen manifest changed: $($job.manifest)" }
    $m = Get-Content -LiteralPath $job.manifest -Raw | ConvertFrom-Json
    if (-not $AllowManualTools) { Assert-AutomatableManifest $m }
    $paths = @($m.target.executable)
    if ($m.PSObject.Properties['manipulation'] -and $m.manipulation) {
        $paths += $m.manipulation.executable
        foreach ($match in [regex]::Matches($m.manipulation.commandLineTemplate, '\{repoRoot\}[^"\s]+\.dll')) { $paths += $match.Value.Replace('{repoRoot}',$repo) }
    }
    if ($m.metadata.PSObject.Properties['extra'] -and $m.metadata.extra.PSObject.Properties['payload_path'] -and $m.metadata.extra.payload_path) { $paths += $m.metadata.extra.payload_path }
    foreach ($path in $paths) {
        $resolved = if ([IO.Path]::IsPathRooted($path)) { $path } else { Join-Path $repo $path }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Required binary missing: $resolved" }
    }
}
Write-Host "Manifest/binary preflight passed for $($p.runs.Count) scheduled attempts."
if ($PreflightOnly) { return }
$lockPath = Join-Path $PSScriptRoot 'campaigns\active-capture.lock'
New-Item -ItemType Directory -Path (Split-Path $lockPath) -Force | Out-Null
try { $lock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
catch { throw 'Another automated campaign holds the capture lock. Run campaigns serially.' }
$journalPath = Join-Path (Split-Path $planPath) 'attempts.json'
$entries = @()
try {
    if (Test-Path -LiteralPath $journalPath) {
        if (-not $Resume) { throw 'Campaign already started. Use -Resume to continue pending entries; attempted entries are never silently rerun.' }
        $entries = @(Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json)
    }
    function Save-Journal { ConvertTo-Json -InputObject @($entries) -Depth 12 | Set-Content -LiteralPath $journalPath -Encoding UTF8 }
    if (-not $SkipBootstrap) { & (Join-Path $PSScriptRoot 'Bootstrap-ETWTI.ps1') }
    foreach ($job in $p.runs) {
        if (@($entries | Where-Object order -eq $job.order).Count) { continue }
        $entry = [pscustomobject]@{order=$job.order; name=$job.name; repetition=$job.repetition; startedAt=(Get-Date).ToString('o'); status='started'; runDirectory=$null; effect_verified=$null; error=$null}
        $entries += $entry
        Save-Journal
        Write-Host "[$($job.order)/$($p.runs.Count)] $($job.name) repetition $($job.repetition)"
        try {
            $runParams = @{ManifestPath=$job.manifest; RunsRoot=$p.runsRoot; Phase=$p.phase; PassThru=$true}
            if (-not $AllowManualTools) { $runParams.NonInteractive=$true }
            $r = & (Join-Path $PSScriptRoot 'Run-PPLExperiment.ps1') @runParams
            $entry.runDirectory = $r.runDirectory
            $entry.effect_verified = $r.outcome.effect_verified
            $entry.status = if ($r.outcome.effect_verified -eq $true) { 'effect_verified' } else { 'effect_failed_or_unverified' }
            if ($r.outcome.target_survived -ne $true) { $entry.status = 'target_did_not_survive' }
            if ($r.captureQuality.decoder_version -ne 2 -or $r.captureQuality.provider_startup_verified -ne $true -or $r.captureQuality.vm_logging_opt_in_verified -ne $true -or $r.captureQuality.event_loss_observed -ne $false -or $r.captureQuality.consumer_shutdown_clean -ne $true -or $r.captureQuality.decode_health_verified -ne $true) {
                $entry.status = 'capture_quality_failed'
                $entry.error = 'Capture quality is unverified/failed. Inspect capture-quality.json and install both rebuilt signed capture binaries.'
            }
        } catch {
            $entry.status='capture_failed'; $entry.error=$_.Exception.Message
            if ($_.Exception.Data.Contains('RunDirectory')) { $entry.runDirectory=$_.Exception.Data['RunDirectory'] }
            Write-Warning $entry.error
        }
        Save-Journal
        if ($entry.status -ne 'effect_verified') { throw "Campaign paused after $($entry.status). Inspect its evidence, then use -Resume for the remaining schedule." }
        if ($InterRunSleepSeconds) { Start-Sleep -Seconds $InterRunSleepSeconds }
    }
    $entries | Group-Object status | Select-Object Name,Count | Format-Table -AutoSize
    Write-Host "Run data: $($p.runsRoot)"
    Write-Host "Journal: $journalPath"
} finally { $lock.Dispose() }
