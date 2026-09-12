# Serial execution only: PPLRunner and the ETW session are machine-wide.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Plan,
    [switch]$PreflightOnly,
    [switch]$Resume,
    # Explicit recovery: rerun this schedule order and everything after it.
    [ValidateRange(1,2147483647)] [int]$StartAt = 1,
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
$explicitStart = $PSBoundParameters.ContainsKey('StartAt')
if ($explicitStart -and -not $Resume) { throw '-StartAt requires -Resume. It explicitly restarts the schedule at the supplied order.' }
$jobsByOrder = @{}
foreach ($job in $p.runs) {
    $order = 0
    if (-not [int]::TryParse([string]$job.order, [ref]$order) -or $order -lt 1 -or $jobsByOrder.ContainsKey($order)) {
        throw 'The plan must contain unique positive integer order values.'
    }
    $jobsByOrder[$order] = $job
}
if ($explicitStart -and -not $jobsByOrder.ContainsKey($StartAt)) { throw "StartAt $StartAt is not a scheduled order in this plan." }
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
$journalPath = Join-Path (Split-Path $planPath) 'attempts.json'
$entries = New-Object 'System.Collections.Generic.List[object]'

function Add-JournalEntry($Value) {
    # Windows PowerShell 5.1 does not enumerate ConvertFrom-Json arrays in
    # a pipeline. Repeated use of @(... | ConvertFrom-Json) used to nest
    # the journal, making the order-property check miss every old attempt.
    if ($Value -is [array]) {
        foreach ($item in $Value) { Add-JournalEntry $item }
        return
    }
    if ($null -eq $Value) { throw 'The journal contains a null entry.' }
    if (-not $Value.PSObject.Properties['order']) {
        # Recover the value/Count wrapper written by the old 5.1 reader.
        if ($Value.PSObject.Properties['value'] -and $Value.value -is [array] -and $Value.PSObject.Properties['Count'] -and $Value.Count -eq $Value.value.Count) {
            foreach ($item in $Value.value) { Add-JournalEntry $item }
            return
        }
        throw 'A journal entry has no order.'
    }
    $order = 0
    if ($Value.order -is [array] -or -not [int]::TryParse([string]$Value.order, [ref]$order) -or -not $jobsByOrder.ContainsKey($order)) {
        throw 'A journal entry has an invalid or unknown order.'
    }
    $job = $jobsByOrder[$order]
    if (($Value.PSObject.Properties['name'] -and $Value.name -ne $job.name) -or
        ($Value.PSObject.Properties['repetition'] -and $Value.repetition -ne $job.repetition)) {
        throw "Journal order $order does not match the frozen plan."
    }
    [void]$entries.Add($Value)
}

function Save-Journal {
    # Finish writing beside the journal before replacing it. Disk-full or
    # interrupted writes must not truncate the last committed checkpoint.
    $temporary = $journalPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = ConvertTo-Json -InputObject $entries.ToArray() -Depth 12
        [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $journalPath) {
            [IO.File]::Replace($temporary, $journalPath, ($journalPath + '.bak'), $true)
        } else {
            [IO.File]::Move($temporary, $journalPath)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) }
    }
}

$lockPath = Join-Path $PSScriptRoot 'campaigns\active-capture.lock'
$lock = $null
if (-not $PreflightOnly) {
    New-Item -ItemType Directory -Path (Split-Path $lockPath) -Force | Out-Null
    try { $lock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
    catch { throw 'Another automated campaign holds the capture lock. Run campaigns serially.' }
}
try {
    if (Test-Path -LiteralPath $journalPath) {
        if (-not $Resume -and -not $PreflightOnly) { throw 'Campaign already started. Use -Resume to continue pending entries; attempted entries are never silently rerun.' }
        try {
            $raw = Get-Content -LiteralPath $journalPath -Raw
            if ([string]::IsNullOrWhiteSpace($raw)) { throw 'The journal is empty.' }
            $decoded = $raw | ConvertFrom-Json
            # Assignment first, then foreach: portable to PowerShell 5.1/7.
            if ($null -eq $decoded -and $raw -notmatch '^\s*\[\s*\]\s*$') { throw 'The journal contains no attempt array.' }
            foreach ($item in $decoded) { Add-JournalEntry $item }
        } catch {
            if (-not $explicitStart) { throw "Cannot resume from '$journalPath': $($_.Exception.Message) Restore a valid journal, or specify -Resume -StartAt <order> for explicit recovery." }
            $entries.Clear()
            Write-Warning "Journal could not be read: $($_.Exception.Message) Explicit recovery will archive it and record earlier orders as skipped, without claiming verified results."
        }
    } elseif ($Resume -and -not $explicitStart) {
        throw "No journal found at '$journalPath'. Use -Resume -StartAt <order> to recover from a known schedule position."
    }

    if ($explicitStart) {
        $prior = @($entries | Where-Object { [int]$_.order -lt $StartAt })
        $entries.Clear()
        foreach ($entry in $prior) { [void]$entries.Add($entry) }
        $recorded = @{}
        foreach ($entry in $entries) { $recorded[[int]$entry.order] = $true }
        foreach ($job in $p.runs) {
            if ([int]$job.order -ge $StartAt -or $recorded.ContainsKey([int]$job.order)) { continue }
            [void]$entries.Add([pscustomobject]@{
                order=$job.order; name=$job.name; repetition=$job.repetition
                startedAt=$null; status='skipped_before_start'; runDirectory=$null
                effect_verified=$null; skippedAt=(Get-Date).ToString('o')
                error="Skipped by operator via -StartAt $StartAt; earlier run evidence was not reconstructed."
            })
        }
    }
    $recorded = @{}
    foreach ($entry in $entries) { $recorded[[int]$entry.order] = $true }
    $pending = @($p.runs | Where-Object { -not $recorded.ContainsKey([int]$_.order) } | Sort-Object { [int]$_.order })
    if ($pending.Count) {
        Write-Host "Next scheduled attempt: $($pending[0].order)/$($p.runs.Count) ($($pending.Count) remaining)."
    } else { Write-Host 'No pending attempts remain in this campaign.' }
    if ($PreflightOnly) { return }
    if ($explicitStart) {
        if (Test-Path -LiteralPath $journalPath) {
            $archive = Join-Path (Split-Path $journalPath) ("attempts.before-start-{0}.{1}.{2}.json" -f $StartAt,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'),[guid]::NewGuid().ToString('N'))
            Copy-Item -LiteralPath $journalPath -Destination $archive
            Write-Host "Previous journal archived: $archive"
        }
        Save-Journal
        Write-Host "Explicit restart at order $StartAt; previous attempts at or after it will be rerun."
    }
    if (-not $pending.Count) { return }
    if (-not $SkipBootstrap) { & (Join-Path $PSScriptRoot 'Bootstrap-ETWTI.ps1') }
    foreach ($job in $pending) {
        $entry = [pscustomobject]@{order=$job.order; name=$job.name; repetition=$job.repetition; startedAt=(Get-Date).ToString('o'); status='started'; runDirectory=$null; effect_verified=$null; error=$null}
        [void]$entries.Add($entry)
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
        if ($entry.status -ne 'effect_verified') { throw "Campaign paused after $($entry.status) at order $($job.order). Inspect its evidence and resolve the failure. Use -Resume -StartAt $($job.order) to retry from this order; plain -Resume skips this recorded attempt and continues with the remaining schedule." }
        if ($InterRunSleepSeconds) { Start-Sleep -Seconds $InterRunSleepSeconds }
    }
    $entries | Group-Object status | Select-Object Name,Count | Format-Table -AutoSize
    Write-Host "Run data: $($p.runsRoot)"
    Write-Host "Journal: $journalPath"
} finally { if ($lock) { $lock.Dispose() } }
