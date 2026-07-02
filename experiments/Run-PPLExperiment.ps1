# Execute one experiment run under the PPL/ETW-TI capture flow.
#
# This is the ELAM/PPL sibling of Run-Experiment.ps1. Instead of launching
# Telemetry.exe as a normal child process it drives PPLRunner: writes
# C:\elam\runner.cfg with the desired Telemetry command line, starts the
# protected service, waits for the ProcessEnableReadWriteVmLogging opt-in to
# succeed, runs the manipulation, then signals shutdown via C:\elam\stop.flag.
#
# The output layout matches Run-Experiment.ps1 exactly so analysis/loader.py
# reads both without special-casing:
#   experiments/runs/<run_id>/
#     manifest.json     — same schema as the direct-launch runner
#     telemetry.jsonl   — copy of C:\elam\ti_test.json for this run
#     telemetry.log     — copy of C:\elam\ti_test.json.log (diag output)
#     pplrunner.log     — copy of C:\elam\pplrunner.log (service log)
#     target-info.json  — optional sidecar written by the target itself

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    # Machine-wide PPL layout. Overridable if the lab paths ever move.
    [string]$TelemetryPPLBinary = 'C:\elam\bin\Telemetry.exe',
    [string]$ElamWorkDir        = 'C:\elam',

    # runner.cfg is read by PPLRunner at service-start; we rewrite it per run
    # because it embeds the target PID.
    [string]$RunnerCfgPath      = 'C:\elam\runner.cfg',

    # Files written by the PPL child; we copy them into the run directory
    # after the capture stops.
    [string]$SessionName        = 'TISession',

    # Optional: extend timings from the manifest (defaults come from manifest.timings).
    [int]$ExtraCooldownSeconds  = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---- Small helpers (kept minimal; mirror Run-Experiment.ps1 style) ----

function Resolve-RepoPath {
    param([string]$PathValue)
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return (Resolve-Path -LiteralPath $PathValue).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path $script:RepoRoot $PathValue)).Path
}

function Resolve-OptionalPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return $null }
    return Resolve-RepoPath -PathValue $PathValue
}

function Quote-Argument {
    param([string]$Argument)
    if ($Argument.Length -eq 0) { return '""' }
    if ($Argument -match '[\s"]') { return '"' + ($Argument -replace '"', '\"') + '"' }
    return $Argument
}

function Resolve-Template {
    param([string]$Template, [hashtable]$Tokens)
    $result = $Template
    foreach ($entry in $Tokens.GetEnumerator()) {
        $result = $result.Replace($entry.Key, [string]$entry.Value)
    }
    return $result
}

function Wait-ForLogLine {
    param(
        [string]$Path,
        [string]$Pattern,
        [int]$TimeoutSeconds = 15
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) {
            if (Select-String -Path $Path -Pattern $Pattern -Quiet -ErrorAction SilentlyContinue) {
                return $true
            }
        }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Wait-ForService {
    param([string]$Name, [string]$DesiredStatus, [int]$TimeoutSeconds = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq $DesiredStatus) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

# ---- Load manifest, prepare run directory ----

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceManifestPath = Resolve-RepoPath -PathValue $ManifestPath
$manifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json

$experimentName = if ($manifest.name) { [string]$manifest.name } else { 'experiment' }
$timestamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$runId          = "$timestamp-$experimentName+ppl"
$runDirectory   = Join-Path $script:RepoRoot (Join-Path 'experiments\runs' $runId)
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null

# Where our final artefacts land
$telemetryOutputPath = Join-Path $runDirectory 'telemetry.jsonl'
$telemetryLogPath    = Join-Path $runDirectory 'telemetry.log'
$pplrunnerLogPath    = Join-Path $runDirectory 'pplrunner.log'
$finalManifestPath   = Join-Path $runDirectory 'manifest.json'

# Where the PPL child writes during the run (read from runner.cfg)
$pplTelemetryJson    = Join-Path $ElamWorkDir 'ti_test.json'
$pplTelemetryLog     = "$pplTelemetryJson.log"
$pplRunnerLogSource  = Join-Path $ElamWorkDir 'pplrunner.log'
$pplStopFlag         = Join-Path $ElamWorkDir 'stop.flag'

# ---- Resolve target / manipulation exes (same rules as Run-Experiment.ps1) ----

$resolvedTargetExecutable       = Resolve-OptionalPath $manifest.target.executable
$resolvedTargetWorkingDirectory = Resolve-OptionalPath $manifest.target.workingDirectory
if (-not $resolvedTargetWorkingDirectory) {
    $resolvedTargetWorkingDirectory = Split-Path -Parent $resolvedTargetExecutable
}

$resolvedManipulationExecutable       = Resolve-OptionalPath $manifest.manipulation.executable
$resolvedManipulationWorkingDirectory = Resolve-OptionalPath $manifest.manipulation.workingDirectory
if (-not $resolvedManipulationWorkingDirectory) {
    $resolvedManipulationWorkingDirectory = Split-Path -Parent $resolvedManipulationExecutable
}

# ---- Build the manifest skeleton (matches Run-Experiment.ps1 schema) ----

$startedAt = Get-Date
$result = [ordered]@{
    schemaVersion      = 1
    sourceManifestPath = $sourceManifestPath
    runId              = $runId
    experiment         = $manifest
    resolved           = [ordered]@{
        target        = [ordered]@{
            executable       = $resolvedTargetExecutable
            workingDirectory = $resolvedTargetWorkingDirectory
            arguments        = [string]$manifest.target.arguments
        }
        telemetry     = [ordered]@{
            executable       = $TelemetryPPLBinary  # runs as PPL child, not repo-relative
            workingDirectory = $ElamWorkDir
        }
        manipulation  = [ordered]@{
            executable          = $resolvedManipulationExecutable
            workingDirectory    = $resolvedManipulationWorkingDirectory
            commandLineTemplate = [string]$manifest.manipulation.commandLineTemplate
        }
    }
    output             = [ordered]@{
        directory = $runDirectory
        telemetry = $telemetryOutputPath
        manifest  = $finalManifestPath
    }
    execution          = [ordered]@{
        startedAt        = $startedAt.ToString('o')
        warmupSeconds    = [int]$manifest.timings.warmupSeconds
        cooldownSeconds  = [int]$manifest.timings.cooldownSeconds + $ExtraCooldownSeconds
        mode             = 'ppl'
        sessionName      = $SessionName
        vmLoggingPid     = $null
        commands         = [ordered]@{
            target       = $null
            telemetry    = $null   # runner.cfg contents, filled in below
            manipulation = $null
        }
        targetPid            = $null
        pplrunnerPid         = $null
        telemetryPid         = $null   # from pplrunner.log if we can grep it
        manipulationPid      = $null
        targetExitCode       = $null
        manipulationExitCode = $null
        status               = 'running'
        finishedAt           = $null
    }
}

function Write-FinalManifest {
    param([string]$Status)
    $result.execution.status     = $Status
    $result.execution.finishedAt = (Get-Date).ToString('o')
    $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $finalManifestPath -Encoding utf8
}

# ---- Sanity checks before we touch anything ----

if (-not (Test-Path -LiteralPath $TelemetryPPLBinary)) {
    throw "Signed telemetry binary missing: $TelemetryPPLBinary  (run Bootstrap-ETWTI first, or re-sign+copy)"
}
if (-not (Get-Service -Name 'PPLRunner' -ErrorAction SilentlyContinue)) {
    throw 'PPLRunner service is not installed. Run Bootstrap-ETWTI.ps1 first.'
}
$currentSvcStatus = (Get-Service PPLRunner).Status
if ($currentSvcStatus -ne 'Stopped') {
    Write-Host "PPLRunner is currently $currentSvcStatus - stopping cleanly before starting fresh capture" -ForegroundColor Yellow
    New-Item -ItemType File -Force -Path $pplStopFlag | Out-Null
    if (-not (Wait-ForService -Name 'PPLRunner' -DesiredStatus 'Stopped' -TimeoutSeconds 10)) {
        throw 'PPLRunner did not stop within 10s. Investigate manually before rerunning.'
    }
}

$targetProcess       = $null
$manipulationProcess = $null

try {
    # ---- 1. Start the target ----
    $targetParams = @{
        FilePath         = $resolvedTargetExecutable
        WorkingDirectory = $resolvedTargetWorkingDirectory
        PassThru         = $true
    }
    # Start-Process rejects an empty -ArgumentList; only add it when present.
    if (-not [string]::IsNullOrWhiteSpace([string]$manifest.target.arguments)) {
        $targetParams.ArgumentList = [string]$manifest.target.arguments
    }
    $targetProcess = Start-Process @targetParams
    $result.execution.targetPid    = $targetProcess.Id
    $result.execution.commands.target = ('{0} {1}' -f (Quote-Argument $resolvedTargetExecutable), [string]$manifest.target.arguments).Trim()

    # ---- 2. Wait for the target-info sidecar (same convention as Run-Experiment.ps1) ----
    $tokens = @{
        '{targetPid}'       = $targetProcess.Id
        '{runId}'           = $runId
        '{runDirectory}'    = $runDirectory
        '{telemetryOutput}' = $telemetryOutputPath
        '{repoRoot}'        = $script:RepoRoot
    }
    $targetInfoPath = Join-Path $resolvedTargetWorkingDirectory "target-info-$($targetProcess.Id).json"
    for ($i = 0; $i -lt 20; $i++) {
        if (Test-Path -LiteralPath $targetInfoPath) {
            try {
                $targetInfo = Get-Content -LiteralPath $targetInfoPath -Raw | ConvertFrom-Json
                foreach ($prop in $targetInfo.PSObject.Properties) {
                    $tokens["{targetInfo.$($prop.Name)}"] = [string]$prop.Value
                }
                Move-Item -LiteralPath $targetInfoPath -Destination (Join-Path $runDirectory 'target-info.json') -Force
                break
            } catch {
                Start-Sleep -Milliseconds 100
            }
        } else {
            Start-Sleep -Milliseconds 100
        }
    }

    # ---- 3. Build the runner.cfg command line ----
    $telemetryArgs = New-Object 'System.Collections.Generic.List[string]'
    $telemetryArgs.Add($TelemetryPPLBinary)

    # Providers: from manifest (new schema) or single guid (legacy)
    if ($manifest.PSObject.Properties['providers'] -and $manifest.providers) {
        foreach ($entry in $manifest.providers) {
            $guid = [string]$entry.guid
            $name = if ($entry.PSObject.Properties['name']) { [string]$entry.name } else { '' }
            $spec = if ([string]::IsNullOrWhiteSpace($name)) { $guid } else { "${guid}:${name}" }
            $telemetryArgs.Add('--provider'); $telemetryArgs.Add($spec)
        }
    } elseif ($manifest.PSObject.Properties['providerGuid']) {
        $telemetryArgs.Add('--provider'); $telemetryArgs.Add([string]$manifest.providerGuid)
    } else {
        throw "Manifest declares neither 'providers' nor 'providerGuid'."
    }

    $telemetryArgs.Add('--output');  $telemetryArgs.Add($pplTelemetryJson)
    $telemetryArgs.Add('--session'); $telemetryArgs.Add($SessionName)
    $telemetryArgs.Add('--enable-vm-logging-pid'); $telemetryArgs.Add([string]$targetProcess.Id)
    $telemetryArgs.Add('--run-id');  $telemetryArgs.Add($runId)

    if ($manifest.metadata.label)     { $telemetryArgs.Add('--label');     $telemetryArgs.Add([string]$manifest.metadata.label) }
    if ($manifest.metadata.technique) { $telemetryArgs.Add('--technique'); $telemetryArgs.Add([string]$manifest.metadata.technique) }
    if ($manifest.metadata.target)    { $telemetryArgs.Add('--target');    $telemetryArgs.Add([string]$manifest.metadata.target) }
    if ($manifest.metadata.extra) {
        foreach ($entry in $manifest.metadata.extra.PSObject.Properties) {
            $telemetryArgs.Add('--meta'); $telemetryArgs.Add(($entry.Name + '=' + [string]$entry.Value))
        }
    }

    # runner.cfg is a single line; PPLRunner passes it verbatim to CreateProcessW.
    $runnerCfgLine = ($telemetryArgs | ForEach-Object { Quote-Argument $_ }) -join ' '
    $result.execution.commands.telemetry = $runnerCfgLine
    $result.execution.vmLoggingPid       = $targetProcess.Id

    # Clean prior-run artefacts and write the fresh cfg.
    Remove-Item $pplTelemetryJson, $pplTelemetryLog, $pplRunnerLogSource, $pplStopFlag -ErrorAction SilentlyContinue
    # Write UTF-8 WITHOUT a BOM: PS 5.1's `-Encoding utf8` emits a BOM, and
    # PPLRunner feeds runner.cfg's bytes verbatim to CreateProcessW. A leading
    # BOM lands in front of the exe path, so CreateProcess fails with
    # ERROR_FILE_NOT_FOUND (2) and Telemetry never launches.
    [System.IO.File]::WriteAllText($RunnerCfgPath, $runnerCfgLine, (New-Object System.Text.UTF8Encoding($false)))

    # ---- 4. Start the protected capture ----
    $scOut = & sc.exe start PPLRunner
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe start PPLRunner failed:`n$scOut"
    }
    if (-not (Wait-ForService -Name 'PPLRunner' -DesiredStatus 'Running' -TimeoutSeconds 10)) {
        throw 'PPLRunner did not reach Running within 10s.'
    }
    $svc = Get-Service PPLRunner
    # SCM doesn't expose the child PID here, but pplrunner.log has "child launched pid N"

    # ---- 5. Wait for opt-in to succeed — deterministic "ready" signal ----
    if (-not (Wait-ForLogLine -Path $pplTelemetryLog `
                              -Pattern 'vm-logging.*status=0x00000000' `
                              -TimeoutSeconds 15)) {
        throw "Telemetry never confirmed vm-logging opt-in. Check $pplTelemetryLog."
    }
    Start-Sleep -Seconds ([int]$manifest.timings.warmupSeconds)

    # ---- 6. Run the manipulation ----
    $manipulationCommandLine = Resolve-Template `
        -Template ([string]$manifest.manipulation.commandLineTemplate) `
        -Tokens $tokens
    $result.execution.commands.manipulation = ('{0} {1}' -f (Quote-Argument $resolvedManipulationExecutable), $manipulationCommandLine).Trim()

    $manipulationParams = @{
        FilePath         = $resolvedManipulationExecutable
        WorkingDirectory = $resolvedManipulationWorkingDirectory
        PassThru         = $true
        Wait             = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($manipulationCommandLine)) {
        $manipulationParams.ArgumentList = $manipulationCommandLine
    }
    $manipulationProcess = Start-Process @manipulationParams
    $result.execution.manipulationPid      = $manipulationProcess.Id
    $result.execution.manipulationExitCode = $manipulationProcess.ExitCode

    # ---- 7. Cooldown so ETW flushes, then request graceful shutdown ----
    Start-Sleep -Seconds $result.execution.cooldownSeconds

    New-Item -ItemType File -Force -Path $pplStopFlag | Out-Null
    if (-not (Wait-ForService -Name 'PPLRunner' -DesiredStatus 'Stopped' -TimeoutSeconds 20)) {
        throw "PPLRunner did not stop within 20s. Capture may be truncated."
    }

    # ---- 8. Copy artefacts into the run directory ----
    if (Test-Path -LiteralPath $pplTelemetryJson) {
        Copy-Item -LiteralPath $pplTelemetryJson -Destination $telemetryOutputPath -Force
    } else {
        Write-Warning "No ti_test.json produced - capture is empty."
    }
    if (Test-Path -LiteralPath $pplTelemetryLog)    { Copy-Item -LiteralPath $pplTelemetryLog    -Destination $telemetryLogPath -Force }
    if (Test-Path -LiteralPath $pplRunnerLogSource) { Copy-Item -LiteralPath $pplRunnerLogSource -Destination $pplrunnerLogPath -Force }

    # Extract the PPL child PID from the log for the manifest (optional but nice).
    if (Test-Path -LiteralPath $pplrunnerLogPath) {
        $line = Select-String -Path $pplrunnerLogPath -Pattern 'child launched pid (\d+)' | Select-Object -First 1
        if ($line) { $result.execution.telemetryPid = [int]$line.Matches[0].Groups[1].Value }
    }

    # ---- 9. Stop the target if still alive ----
    if ($targetProcess -and -not $targetProcess.HasExited) {
        Stop-Process -Id $targetProcess.Id -Force
    }
    if ($targetProcess) { $result.execution.targetExitCode = $targetProcess.ExitCode }

    Write-FinalManifest -Status 'completed'
    Write-Host ("Run OK: {0}" -f $runDirectory) -ForegroundColor Green
}
catch {
    # Best-effort cleanup
    New-Item -ItemType File -Force -Path $pplStopFlag -ErrorAction SilentlyContinue | Out-Null
    Wait-ForService -Name 'PPLRunner' -DesiredStatus 'Stopped' -TimeoutSeconds 10 | Out-Null
    if ($targetProcess -and -not $targetProcess.HasExited) {
        Stop-Process -Id $targetProcess.Id -Force -ErrorAction SilentlyContinue
    }
    $result.execution.error = $_.Exception.Message
    Write-FinalManifest -Status 'failed'
    throw
}
