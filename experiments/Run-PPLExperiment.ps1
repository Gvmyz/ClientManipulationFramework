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
    [int]$ExtraCooldownSeconds  = 0,

    # Keep pilot, final and previous datasets separate. Relative to repo root.
    [string]$RunsRoot = 'experiments\runs',
    [ValidateSet('Pilot','Final')] [string]$Phase,
    # Optional override for a manually launched tool installed elsewhere (e.g. CE).
    [string]$ExternalToolPath = '',
    [switch]$NonInteractive,
    [switch]$PassThru,
    [ValidateRange(1,3600)] [int]$ManipulationTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Capture-Helpers.ps1')
. (Join-Path $PSScriptRoot 'Campaign-Helpers.ps1')

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
Assert-SupportedManifest $manifest
if ($NonInteractive) { Assert-AutomatableManifest $manifest }
if (-not $manifest.metadata.PSObject.Properties['extra'] -or $null -eq $manifest.metadata.extra) {
    $manifest.metadata | Add-Member -NotePropertyName extra -NotePropertyValue ([pscustomobject]@{}) -Force
}
if ($Phase) {
    if (-not $PSBoundParameters.ContainsKey('RunsRoot')) { $RunsRoot = 'experiments\campaigns\manual-' + $Phase.ToLowerInvariant() + '\runs' }
    if (-not $manifest.metadata.PSObject.Properties['extra']) { $manifest.metadata | Add-Member -NotePropertyName extra -NotePropertyValue ([pscustomobject]@{}) }
    $manifest.metadata.extra | Add-Member -NotePropertyName phase -NotePropertyValue $Phase.ToLowerInvariant() -Force
}

$experimentName = if ($manifest.name) { [string]$manifest.name } else { 'experiment' }
$timestamp      = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
$runId          = "$timestamp-$experimentName-ppl"
$resolvedRunsRoot = if ([IO.Path]::IsPathRooted($RunsRoot)) { $RunsRoot } else { Join-Path $script:RepoRoot $RunsRoot }
$runDirectory   = Join-Path $resolvedRunsRoot $runId

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

# If the manifest omits the manipulation section, we assume an EXTERNAL attacker
# is going to drive the injection (e.g. an interactive Metasploit migrate). In
# that mode we still do target + telemetry setup, but instead of Start-Process'ing
# our own attacker we display the target PID and wait for the operator to press
# Enter when they're done. Enables tier-1 red-team-tool validation.
$externalManipulation = -not ($manifest.PSObject.Properties['manipulation'] -and $manifest.manipulation)

if (-not $externalManipulation) {
    $resolvedManipulationExecutable       = Resolve-OptionalPath $manifest.manipulation.executable
    $resolvedManipulationWorkingDirectory = Resolve-OptionalPath $manifest.manipulation.workingDirectory
    if (-not $resolvedManipulationWorkingDirectory) {
        $resolvedManipulationWorkingDirectory = Split-Path -Parent $resolvedManipulationExecutable
    }
} else {
    $resolvedManipulationExecutable       = $null
    $resolvedManipulationWorkingDirectory = $null
}

# ---- Build the manifest skeleton (matches Run-Experiment.ps1 schema) ----

$startedAt = Get-Date
$result = [ordered]@{
    schemaVersion      = 2
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
            commandLineTemplate = if ($externalManipulation) { '<external>' } else { [string]$manifest.manipulation.commandLineTemplate }
            external            = $externalManipulation
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
        manipulationStartedAt = $null
        manipulationFinishedAt = $null
        operatorWindowStartedAt = $null
        operatorWindowFinishedAt = $null
        targetExitCode       = $null
        manipulationExitCode = $null
        status               = 'running'
        finishedAt           = $null
    }
}

function Write-FinalManifest {
    param([string]$Status)
    $result.execution.status     = $Status
    $result.execution.finishedAt = if ($Status -eq 'running') { $null } else { (Get-Date).ToString('o') }
    $result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $finalManifestPath -Encoding utf8
}

# ---- Sanity checks before we touch anything ----

if (-not (Test-Path -LiteralPath $TelemetryPPLBinary)) {
    throw "Signed telemetry binary missing: $TelemetryPPLBinary  (run Bootstrap-ETWTI first, or re-sign+copy)"
}
if (-not (Get-Service -Name 'PPLRunner' -ErrorAction SilentlyContinue)) {
    throw 'PPLRunner service is not installed. Run Bootstrap-ETWTI.ps1 first.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this capture from PowerShell opened as Administrator.'
}

# Record actual lab inputs automatically; source manifest templates stay unchanged.
$extra = $manifest.metadata.extra
$artifactSpecs = @(@('target',$resolvedTargetExecutable), @('telemetry',$TelemetryPPLBinary), @('source_manifest',$sourceManifestPath))
if ($externalManipulation) {
    $toolPath = $ExternalToolPath
    if (-not $toolPath -and $extra.PSObject.Properties['attacker_executable']) { $toolPath = [string]$extra.attacker_executable }
    if ($toolPath) { $artifactSpecs += ,@('tool',$toolPath) }
    if ($extra.PSObject.Properties['payload_path']) { $artifactSpecs += ,@('payload',[string]$extra.payload_path) }
} else {
    $artifactSpecs += ,@('tool',$resolvedManipulationExecutable)
    $payloadCommand = ([string]$manifest.manipulation.commandLineTemplate).Replace('{repoRoot}', $script:RepoRoot)
    if ($payloadCommand -match '(?:^|\s)--dll\s+(?:"([^"]+)"|(\S+))') {
        $payloadPath = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
        $artifactSpecs += ,@('payload',$payloadPath)
    }
}
$artifacts = @()
foreach ($spec in $artifactSpecs) {
    $artifact = Get-CaptureArtifact -Role $spec[0] -Path $spec[1] -RepoRoot $script:RepoRoot
    $artifacts += $artifact
    if ($artifact.status -eq 'recorded') {
        $key = switch ($artifact.role) { 'target' {'target_sha256'} 'tool' {'sha256'} 'payload' {'payload_sha256'} default {$null} }
        if ($key) { $extra | Add-Member -NotePropertyName $key -NotePropertyValue $artifact.sha256 -Force }
    } elseif ($artifact.role -in @('tool','payload')) { Write-Warning "Cannot record $($artifact.role) hash: $($artifact.path) ($($artifact.status)). Use -ExternalToolPath for a different tool location." }
}
$result['provenance'] = [ordered]@{ recordedAt=(Get-Date).ToString('o'); osVersion=[Environment]::OSVersion.VersionString; artifacts=$artifacts }
$currentSvcStatus = (Get-Service PPLRunner).Status
if ($currentSvcStatus -ne 'Stopped') {
    throw "PPLRunner is currently $currentSvcStatus. Finish the active capture before starting another; this runner will not interrupt it."
}

$targetProcess       = $null
$manipulationProcess = $null
$capturePrepared = $false
New-Item -ItemType Directory -Path $runDirectory | Out-Null
Write-FinalManifest -Status 'running'

try {
    # ---- 1. Start the target ----
    $targetParams = @{
        FilePath         = $resolvedTargetExecutable
        WorkingDirectory = $resolvedTargetWorkingDirectory
        PassThru         = $true
        WindowStyle      = $(if ($NonInteractive) { 'Hidden' } else { 'Normal' })
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
    $requestedProviderGuids = @()

    # Providers: from manifest (new schema) or single guid (legacy)
    if ($manifest.PSObject.Properties['providers'] -and $manifest.providers) {
        foreach ($entry in $manifest.providers) {
            $guid = [string]$entry.guid
            $requestedProviderGuids += $guid
            $name = if ($entry.PSObject.Properties['name']) { [string]$entry.name } else { '' }
            $spec = if ([string]::IsNullOrWhiteSpace($name)) { $guid } else { "${guid}:${name}" }
            $telemetryArgs.Add('--provider'); $telemetryArgs.Add($spec)
        }
    } elseif ($manifest.PSObject.Properties['providerGuid']) {
        $requestedProviderGuids += [string]$manifest.providerGuid
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
        foreach ($argument in (Get-CompactTelemetryMetadata $manifest.metadata.extra)) { $telemetryArgs.Add($argument) }
    }

    # runner.cfg is a single line; PPLRunner passes it verbatim to CreateProcessW.
    $runnerCfgLine = ($telemetryArgs | ForEach-Object { Quote-Argument $_ }) -join ' '
    Assert-PPLCommandLength $runnerCfgLine
    $result.execution.commands.telemetry = $runnerCfgLine
    $result.execution.vmLoggingPid       = $targetProcess.Id

    # Clean prior-run artefacts and write the fresh cfg.
    foreach ($oldArtifact in @($pplTelemetryJson, $pplTelemetryLog, $pplRunnerLogSource, $pplStopFlag)) {
        if (Test-Path -LiteralPath $oldArtifact) { Remove-Item -LiteralPath $oldArtifact -ErrorAction Stop }
    }
    $capturePrepared = $true
    # Write UTF-8 WITHOUT a BOM: PS 5.1's `-Encoding utf8` emits a BOM, and
    # PPLRunner feeds runner.cfg's bytes verbatim to CreateProcessW. A leading
    # BOM lands in front of the exe path, so CreateProcess fails with
    # ERROR_FILE_NOT_FOUND (2) and Telemetry never launches.
    [System.IO.File]::WriteAllText($RunnerCfgPath, $runnerCfgLine, (New-Object System.Text.UTF8Encoding($false)))
    Copy-Item -LiteralPath $RunnerCfgPath -Destination (Join-Path $runDirectory 'runner.cfg')

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
    # This snapshot makes existing modules explicit instead of classifying
    # pre-capture module addresses as orphan threads.
    try {
        $moduleSnapshot = @($targetProcess.Modules | ForEach-Object { [ordered]@{ base=('0x{0:X}' -f $_.BaseAddress.ToInt64()); size=$_.ModuleMemorySize; path=$_.FileName } })
        [ordered]@{ targetPid=$targetProcess.Id; recordedAt=(Get-Date).ToString('o'); modules=$moduleSnapshot } |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runDirectory 'target-modules-before.json') -Encoding UTF8
    } catch { Write-Warning "Initial module snapshot unavailable: $($_.Exception.Message)" }

    # ---- 6. Run the manipulation ----
    if ($externalManipulation) {
        # No manipulation section → two sub-modes:
        #   observationSeconds set  → BASELINE: observe the target for a fixed window (no attacker)
        #   observationSeconds unset → EXTERNAL ATTACKER: pause for operator (Meterpreter, Sliver, ...)
        $observationSeconds = 0
        if ($manifest.timings.PSObject.Properties['observationSeconds']) {
            $observationSeconds = [int]$manifest.timings.observationSeconds
        }

        if ($observationSeconds -gt 0) {
            $result.execution.manipulationStartedAt = (Get-Date).ToString('o')
            # Baseline observation window — no attacker, just watch the target
            # for a fixed duration. Used for `baseline_*` manifests.
            Write-Host ''
            Write-Host '================================================================' -ForegroundColor Cyan
            Write-Host ('  BASELINE OBSERVATION MODE') -ForegroundColor Yellow
            Write-Host ('  Target PID: {0}' -f $targetProcess.Id) -ForegroundColor Yellow
            Write-Host ('  Observing for {0} seconds...' -f $observationSeconds)
            Write-Host '================================================================' -ForegroundColor Cyan
            Start-Sleep -Seconds $observationSeconds
            $result.execution.manipulationFinishedAt = (Get-Date).ToString('o')
            $result.execution.commands.manipulation = ('<baseline observation {0}s>' -f $observationSeconds)
            $result.execution.manipulationExitCode  = 0
        } else {
            # External-attacker mode: display the target PID and wait for the
            # operator to drive the injection out-of-band (Metasploit, Sliver, etc.)
            # and press Enter.
            Write-Host ''
            Write-Host '================================================================' -ForegroundColor Cyan
            Write-Host ('  EXTERNAL ATTACKER MODE') -ForegroundColor Yellow
            Write-Host ('  Target PID: {0}' -f $targetProcess.Id) -ForegroundColor Yellow
            Write-Host ''
            $operatorInstructions = $null
            if ($manifest.PSObject.Properties['metadata'] -and $manifest.metadata -and
                $manifest.metadata.PSObject.Properties['extra'] -and $manifest.metadata.extra -and
                $manifest.metadata.extra.PSObject.Properties['operator_commands']) {
                $operatorInstructions = [string]$manifest.metadata.extra.operator_commands
            }
            if ($operatorInstructions) {
                Write-Host $operatorInstructions -ForegroundColor Green
            } else {
                Write-Host '  Perform the external action described by this manifest.'
            }
            Write-Host '  Complete the prescribed observation, then press Enter for cooldown.'
            Write-Host '  Record actual attachment/activation times and independent success evidence.'
            Write-Host '================================================================' -ForegroundColor Cyan
            Write-Host ''
            $result.execution.operatorWindowStartedAt = (Get-Date).ToString('o')
            $toolPidText = Read-Host 'Tool PID(s), comma-separated; leave blank if unknown (keep tool open now)'
            $toolPids = @()
            $identities = @()
            foreach ($part in ($toolPidText -split ',')) {
                $parsedPid = 0
                if (-not [int]::TryParse($part.Trim(), [ref]$parsedPid) -or $parsedPid -le 0) { continue }
                $toolProcess = Get-Process -Id $parsedPid -ErrorAction Stop
                $toolPids += $parsedPid
                $identities += [ordered]@{ pid=$parsedPid; path=$toolProcess.Path; startedAt=$toolProcess.StartTime.ToString('o'); sha256=(Get-FileHash -LiteralPath $toolProcess.Path -Algorithm SHA256).Hash }
            }
            [void](Read-Host 'Press Enter immediately BEFORE performing the action (read-only controls: before attaching)')
            $result.execution.manipulationStartedAt = (Get-Date).ToString('o')
            $answer = Read-Host 'After the prescribed observation: S=effect verified, F=failed, U=unknown'
            $result.execution.manipulationFinishedAt = (Get-Date).ToString('o')
            $evidence = Read-Host 'Brief independent evidence (marker/value/feature and target PID), or reason unknown/failed'
            $effect = if ($answer -match '^[sS]$') { $true } elseif ($answer -match '^[fF]$') { $false } else { $null }
            if ($effect -eq $true -and [string]::IsNullOrWhiteSpace($evidence)) { $effect = $null }
            $result['outcome'] = [ordered]@{ effect_verified=$effect; effect_evidence=@($evidence | Where-Object { $_ }); tool_pids=$toolPids; tool_identities=$identities; timing=@{ action_started_at=$result.execution.manipulationStartedAt; observation_ended_at=$result.execution.manipulationFinishedAt; time_basis='Operator marked immediately before action; not an exact API timestamp.' } }
            $result.execution.operatorWindowFinishedAt = (Get-Date).ToString('o')
            $result.execution.commands.manipulation = '<external attacker>'
            # The runner did not execute the tool and cannot know its exit code.
            $result.execution.manipulationExitCode  = $null
        }
    } else {
        $manipulationCommandLine = Resolve-Template `
            -Template ([string]$manifest.manipulation.commandLineTemplate) `
            -Tokens $tokens
        if ($manipulationCommandLine -match '\{[^}]+\}') { throw "Unresolved target-info token in command: $manipulationCommandLine" }
        $result.execution.commands.manipulation = ('{0} {1}' -f (Quote-Argument $resolvedManipulationExecutable), $manipulationCommandLine).Trim()

        # Persist the attacker's console output — without redirection Start-Process
        # opens a transient window that closes on exit, which is why hook-inline
        # etc. seemed to "flash and disappear." These two files live next to
        # telemetry.jsonl so post-mortem analysis (or the analysis pipeline itself)
        # can correlate ETW events with what the attacker actually printed.
        $manipulationStdoutPath = Join-Path $runDirectory 'manipulation.stdout.log'
        $manipulationStderrPath = Join-Path $runDirectory 'manipulation.stderr.log'

        $manipulationParams = @{
            FilePath               = $resolvedManipulationExecutable
            WorkingDirectory       = $resolvedManipulationWorkingDirectory
            PassThru               = $true
            WindowStyle            = 'Hidden'
            RedirectStandardOutput = $manipulationStdoutPath
            RedirectStandardError  = $manipulationStderrPath
        }
        if (-not [string]::IsNullOrWhiteSpace($manipulationCommandLine)) {
            $manipulationParams.ArgumentList = $manipulationCommandLine
        }
        $result.execution.manipulationStartedAt = (Get-Date).ToString('o')
        $manipulationProcess = Start-Process @manipulationParams
        $result.execution.manipulationPid      = $manipulationProcess.Id
        if (-not $manipulationProcess.WaitForExit($ManipulationTimeoutSeconds * 1000)) {
            Stop-Process -Id $manipulationProcess.Id -Force
            throw "Manipulation exceeded $ManipulationTimeoutSeconds seconds; attempt retained as failed."
        }
        $manipulationProcess.Refresh()
        $result.execution.manipulationFinishedAt = (Get-Date).ToString('o')
        $result.execution.manipulationExitCode = $manipulationProcess.ExitCode
        $probePath = Join-Path $resolvedManipulationWorkingDirectory ("usermode-hooks-{0}-{1}.log" -f $targetProcess.Id, $manipulationProcess.Id)
        if (Test-Path -LiteralPath $probePath) { Copy-Item -LiteralPath $probePath -Destination (Join-Path $runDirectory 'usermode-hooks.log') }
    }

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
        throw 'No telemetry file was produced. A missing file is a capture failure; an existing empty file is evaluated using capture health.'
    }
    if (Test-Path -LiteralPath $pplTelemetryLog)    { Copy-Item -LiteralPath $pplTelemetryLog    -Destination $telemetryLogPath -Force }
    if (Test-Path -LiteralPath $pplRunnerLogSource) { Copy-Item -LiteralPath $pplRunnerLogSource -Destination $pplrunnerLogPath -Force }
    $telemetryText = if (Test-Path -LiteralPath $telemetryLogPath) { Get-Content -LiteralPath $telemetryLogPath -Raw } else { '' }
    $runnerText = if (Test-Path -LiteralPath $pplrunnerLogPath) { Get-Content -LiteralPath $pplrunnerLogPath -Raw } else { '' }
    $result['captureQuality'] = Get-CaptureQuality -TelemetryLog $telemetryText -RunnerLog $runnerText -ProviderGuids $requestedProviderGuids
    $result.captureQuality | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory 'capture-quality.json') -Encoding UTF8
    $targetProcess.Refresh()
    $targetSurvived = -not $targetProcess.HasExited
    if (-not $result.Contains('outcome')) {
        $stdout = if (Test-Path -LiteralPath (Join-Path $runDirectory 'manipulation.stdout.log')) { Get-Content -LiteralPath (Join-Path $runDirectory 'manipulation.stdout.log') -Raw } else { '' }
        $isBaseline = $manifest.metadata.label -in @('benign','baseline') -or $manifest.metadata.technique -eq 'none'
        $attachMarker = $false
        if ($result.execution.commands.manipulation -match '(?i)TestDll\.dll' -and $targetSurvived) { $attachMarker = Test-PayloadAttachMarker -TargetPid $targetProcess.Id -TimeoutSeconds 2 }
        $result['outcome'] = Get-AutomaticOutcome -Command $result.execution.commands.manipulation -ExitCode $result.execution.manipulationExitCode -TargetSurvived $targetSurvived -Baseline $isBaseline -Stdout $stdout -AttachMarkerObserved $attachMarker
    }
    $result.outcome['target_survived'] = $targetSurvived
    if ($externalManipulation -and $extra.PSObject.Properties['payload_path'] -and $extra.payload_path -match '(?i)TestDll\.dll$' -and $targetSurvived) {
        $markerObserved = Test-PayloadAttachMarker -TargetPid $targetProcess.Id -TimeoutSeconds 2
        $result.outcome['payload_attach_marker_observed'] = $markerObserved
        if ($markerObserved -and $result.outcome.effect_verified -ne $false) {
            $result.outcome['effect_verified'] = $true
            $result.outcome['effect_evidence'] = @($result.outcome.effect_evidence) + "Target-specific TestDll attach marker observed for PID $($targetProcess.Id)."
        }
    }
    if ($externalManipulation -and $observationSeconds -le 0) {
        $result.outcome | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDirectory 'operator-record.json') -Encoding UTF8
    }

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
    Write-Host ("Capture finished: {0}; verified effect: {1}" -f $runDirectory, $result.outcome.effect_verified) -ForegroundColor Green
    if ($PassThru) { Write-Output ([pscustomobject]@{ runDirectory=$runDirectory; manifest=$finalManifestPath; outcome=$result.outcome; captureQuality=$result.captureQuality }) }
}
catch {
    $_.Exception.Data['RunDirectory'] = $runDirectory
    $failureMessage = $_.Exception.Message
    # Best-effort cleanup
    New-Item -ItemType File -Force -Path $pplStopFlag -ErrorAction SilentlyContinue | Out-Null
    Wait-ForService -Name 'PPLRunner' -DesiredStatus 'Stopped' -TimeoutSeconds 10 | Out-Null
    if ($targetProcess -and -not $targetProcess.HasExited) {
        Stop-Process -Id $targetProcess.Id -Force -ErrorAction SilentlyContinue
    }
    # Preserve startup evidence as well as successful captures.
    foreach ($pair in @(@($pplTelemetryJson,$telemetryOutputPath), @($pplTelemetryLog,$telemetryLogPath), @($pplRunnerLogSource,$pplrunnerLogPath))) {
        if ($capturePrepared -and (Test-Path -LiteralPath $pair[0])) { Copy-Item -LiteralPath $pair[0] -Destination $pair[1] -Force -ErrorAction SilentlyContinue }
    }
    & sc.exe queryex PPLRunner 2>&1 | Out-File -LiteralPath (Join-Path $runDirectory 'service-status.txt')
    foreach ($log in @($pplrunnerLogPath,$telemetryLogPath)) {
        if (Test-Path -LiteralPath $log) { Write-Host "Diagnostic log: $log"; Get-Content -LiteralPath $log -Tail 12 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ } }
    }
    Write-Host "Failed-run evidence: $runDirectory" -ForegroundColor Yellow
    $result.execution['error'] = $failureMessage
    Write-FinalManifest -Status 'failed'
    throw
}
