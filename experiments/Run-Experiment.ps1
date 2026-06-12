[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$ManifestPath,

	# Capture manipulation stdout/stderr to files, leave the target alive, and
	# open a summary window after the run instead of tearing everything down.
	[switch]$KeepWindowsOpen
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Quote-Argument {
	param([Parameter(Mandatory = $true)][string]$Argument)

	if ($Argument.Length -eq 0) {
		return '""'
	}

	if ($Argument -match '[\s"]') {
		return '"' + ($Argument -replace '"', '\"') + '"'
	}

	return $Argument
}

function Join-CommandLine {
	param([Parameter(Mandatory = $true)][string[]]$Arguments)

	return ($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' '
}

function Resolve-RepoPath {
	param([Parameter(Mandatory = $true)][string]$PathValue)

	if ([System.IO.Path]::IsPathRooted($PathValue)) {
		return (Resolve-Path -LiteralPath $PathValue).Path
	}

	$combined = Join-Path -Path $script:RepoRoot -ChildPath $PathValue
	return (Resolve-Path -LiteralPath $combined).Path
}

function Resolve-OptionalPath {
	param([string]$PathValue)

	if ([string]::IsNullOrWhiteSpace($PathValue)) {
		return $null
	}

	return Resolve-RepoPath -PathValue $PathValue
}

function New-CommandLine {
	param(
		[Parameter(Mandatory = $true)][string]$Executable,
		[string]$Arguments = ''
	)

	if ([string]::IsNullOrWhiteSpace($Arguments)) {
		return Quote-Argument -Argument $Executable
	}

	return (Quote-Argument -Argument $Executable) + ' ' + $Arguments
}

function Resolve-Template {
	param(
		[Parameter(Mandatory = $true)][string]$Template,
		[Parameter(Mandatory = $true)][hashtable]$Tokens
	)

	$result = $Template
	foreach ($entry in $Tokens.GetEnumerator()) {
		$result = $result.Replace($entry.Key, [string]$entry.Value)
	}
	return $result
}

function Add-Flag {
	param(
		# AllowEmptyCollection: PowerShell rejects empty collections on mandatory
		# parameters by default. We legitimately call this with a fresh empty list.
		[Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Arguments,
		[Parameter(Mandatory = $true)][string]$Name,
		[Parameter(Mandatory = $true)][object]$Value
	)

	$Arguments.Add($Name)
	$Arguments.Add([string]$Value)
}

function Start-ManagedProcess {
	param(
		[Parameter(Mandatory = $true)][string]$Executable,
		[Parameter(Mandatory = $true)][string]$WorkingDirectory,
		[string]$Arguments = '',
		[switch]$Hidden
	)

	$parameters = @{
		FilePath = $Executable
		WorkingDirectory = $WorkingDirectory
		PassThru = $true
	}

	if (-not [string]::IsNullOrWhiteSpace($Arguments)) {
		$parameters.ArgumentList = $Arguments
	}

	if ($Hidden) {
		$parameters.WindowStyle = 'Hidden'
	}

	return Start-Process @parameters
}

# ---- Manifest load + run-directory setup ----

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceManifestPath = Resolve-RepoPath -PathValue $ManifestPath
$manifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json

# Build a unique run id: <timestamp>-<experimentName>, or the manifest's runId if set.
$experimentName = if ($manifest.name) { [string]$manifest.name } else { 'experiment' }
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$runIdProperty = $manifest.PSObject.Properties['runId']
$runId = if ($runIdProperty -and $runIdProperty.Value) {
	[string]$runIdProperty.Value
} else {
	"$timestamp-$experimentName"
}
$runDirectory = Join-Path -Path $script:RepoRoot -ChildPath (Join-Path 'experiments\runs' $runId)
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null

$telemetryOutputPath = Join-Path $runDirectory 'telemetry.jsonl'
$finalManifestPath = Join-Path $runDirectory 'manifest.json'

# Resolve the three executable paths (target, telemetry, manipulation) against the repo.
$resolvedTargetExecutable = Resolve-OptionalPath $manifest.target.executable
$resolvedTargetWorkingDirectory = Resolve-OptionalPath $manifest.target.workingDirectory
if (-not $resolvedTargetWorkingDirectory) {
	$resolvedTargetWorkingDirectory = Split-Path -Path $resolvedTargetExecutable -Parent
}

$resolvedTelemetryExecutable = Resolve-OptionalPath $manifest.telemetry.executable
$resolvedTelemetryWorkingDirectory = Resolve-OptionalPath $manifest.telemetry.workingDirectory
if (-not $resolvedTelemetryWorkingDirectory) {
	$resolvedTelemetryWorkingDirectory = Split-Path -Path $resolvedTelemetryExecutable -Parent
}

$resolvedManipulationExecutable = Resolve-OptionalPath $manifest.manipulation.executable
$resolvedManipulationWorkingDirectory = Resolve-OptionalPath $manifest.manipulation.workingDirectory
if (-not $resolvedManipulationWorkingDirectory) {
	$resolvedManipulationWorkingDirectory = Split-Path -Path $resolvedManipulationExecutable -Parent
}

# ---- Final manifest skeleton (filled in as the run progresses, written to disk at the end) ----

$startedAt = Get-Date
$targetProcess = $null
$telemetryProcess = $null
$manipulationProcess = $null
$result = [ordered]@{
	schemaVersion = 1
	sourceManifestPath = $sourceManifestPath
	runId = $runId
	experiment = $manifest
	resolved = [ordered]@{
		target = [ordered]@{
			executable = $resolvedTargetExecutable
			workingDirectory = $resolvedTargetWorkingDirectory
			arguments = [string]$manifest.target.arguments
		}
		telemetry = [ordered]@{
			executable = $resolvedTelemetryExecutable
			workingDirectory = $resolvedTelemetryWorkingDirectory
		}
		manipulation = [ordered]@{
			executable = $resolvedManipulationExecutable
			workingDirectory = $resolvedManipulationWorkingDirectory
			commandLineTemplate = [string]$manifest.manipulation.commandLineTemplate
		}
	}
	output = [ordered]@{
		directory = $runDirectory
		telemetry = $telemetryOutputPath
		manifest = $finalManifestPath
	}
	execution = [ordered]@{
		startedAt = $startedAt.ToString('o')
		warmupSeconds = [int]$manifest.timings.warmupSeconds
		cooldownSeconds = [int]$manifest.timings.cooldownSeconds
		commands = [ordered]@{
			target = $null
			telemetry = $null
			manipulation = $null
		}
		targetPid = $null
		telemetryPid = $null
		manipulationPid = $null
		targetExitCode = $null
		manipulationExitCode = $null
		status = 'running'
		finishedAt = $null
	}
}

function Write-FinalManifest {
	param([Parameter(Mandatory = $true)][string]$Status)

	$result.execution.status = $Status
	$result.execution.finishedAt = (Get-Date).ToString('o')
	$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $finalManifestPath -Encoding utf8
}

try {
	# ---- 1. Start the target process ----
	$targetProcess = Start-ManagedProcess -Executable $resolvedTargetExecutable -WorkingDirectory $resolvedTargetWorkingDirectory -Arguments ([string]$manifest.target.arguments)
	$result.execution.targetPid = $targetProcess.Id
	$result.execution.commands.target = New-CommandLine -Executable $resolvedTargetExecutable -Arguments ([string]$manifest.target.arguments)

	# ---- 2. Build the telemetry command line ----
	# Manifest declares providers as either `providerGuid: "{...}"` (single,
	# legacy) or `providers: [ { guid, name }, ... ]`. The latter wins.
	$telemetryArguments = New-Object 'System.Collections.Generic.List[string]'

	$providersProperty = $manifest.PSObject.Properties['providers']
	if ($providersProperty -and $providersProperty.Value) {
		foreach ($entry in $providersProperty.Value) {
			$guid = [string]$entry.guid
			$nameProperty = $entry.PSObject.Properties['name']
			$name = if ($nameProperty) { [string]$nameProperty.Value } else { '' }
			$spec = if ([string]::IsNullOrWhiteSpace($name)) { $guid } else { "${guid}:${name}" }
			Add-Flag -Arguments $telemetryArguments -Name '--provider' -Value $spec
		}
	} elseif ($manifest.PSObject.Properties['providerGuid']) {
		$telemetryArguments.Add([string]$manifest.providerGuid)
	} else {
		throw "Manifest must declare either 'providerGuid' or 'providers'."
	}

	Add-Flag -Arguments $telemetryArguments -Name '--output' -Value $telemetryOutputPath
	Add-Flag -Arguments $telemetryArguments -Name '--session' -Value ([string]$manifest.sessionName)

	# Filter telemetry to the launched target process
	Add-Flag -Arguments $telemetryArguments -Name '--pid' -Value $targetProcess.Id

	$telemetryFilterPidProperty = $manifest.telemetry.PSObject.Properties['filterPid']

	if ($telemetryFilterPidProperty -and $telemetryFilterPidProperty.Value) {
		Add-Flag -Arguments $telemetryArguments -Name '--pid' -Value $telemetryFilterPidProperty.Value
	}

	$telemetryFilterNameProperty = $manifest.telemetry.PSObject.Properties['filterName']

	if ($telemetryFilterNameProperty -and $telemetryFilterNameProperty.Value) {
		Add-Flag -Arguments $telemetryArguments -Name '--name' -Value $telemetryFilterNameProperty.Value
	}

	$metadataRunIdProperty = $manifest.metadata.PSObject.Properties['runId']

	if ($metadataRunIdProperty -and $metadataRunIdProperty.Value) {
		Add-Flag -Arguments $telemetryArguments -Name '--run-id' -Value $metadataRunIdProperty.Value
	} else {
		Add-Flag -Arguments $telemetryArguments -Name '--run-id' -Value $runId
	}

	if ($manifest.metadata.label) {
		Add-Flag -Arguments $telemetryArguments -Name '--label' -Value $manifest.metadata.label
	}

	if ($manifest.metadata.technique) {
		Add-Flag -Arguments $telemetryArguments -Name '--technique' -Value $manifest.metadata.technique
	}

	if ($manifest.metadata.target) {
		Add-Flag -Arguments $telemetryArguments -Name '--target' -Value $manifest.metadata.target
	}

	if ($manifest.metadata.extra) {
		foreach ($entry in $manifest.metadata.extra.PSObject.Properties) {
			Add-Flag -Arguments $telemetryArguments -Name '--meta' -Value ($entry.Name + '=' + [string]$entry.Value)
		}
	}

	# ---- 3. Start telemetry and let it warm up ----
	$telemetryProcess = Start-ManagedProcess -Executable $resolvedTelemetryExecutable -WorkingDirectory $resolvedTelemetryWorkingDirectory -Arguments (Join-CommandLine $telemetryArguments.ToArray())
	$result.execution.telemetryPid = $telemetryProcess.Id
	$result.execution.commands.telemetry = New-CommandLine -Executable $resolvedTelemetryExecutable -Arguments (Join-CommandLine $telemetryArguments.ToArray())

	Start-Sleep -Seconds ([int]$manifest.timings.warmupSeconds)
	Write-Host "Telemetry command:"
	Write-Host $resolvedTelemetryExecutable
	Write-Host (Join-CommandLine $telemetryArguments.ToArray())

	# ---- 4. Build the manipulation command line (token substitution + sidecar) ----
	# If the target wrote target-info-<pid>.json in its working dir, every
	# top-level key becomes a {targetInfo.<key>} token for the manipulation
	# template (used e.g. by memorypatch for the address of the target variable).
	$tokens = @{
		'{targetPid}' = $targetProcess.Id
		'{runId}' = $runId
		'{runDirectory}' = $runDirectory
		'{telemetryOutput}' = $telemetryOutputPath
	}

	$targetInfoPath = Join-Path $resolvedTargetWorkingDirectory "target-info-$($targetProcess.Id).json"
	$targetInfo = $null
	# Try for ~2s before giving up; the sidecar normally appears within ms.
	for ($i = 0; $i -lt 20; $i++) {
		if (Test-Path -LiteralPath $targetInfoPath) {
			try {
				$targetInfo = Get-Content -LiteralPath $targetInfoPath -Raw | ConvertFrom-Json
				break
			} catch {
				Start-Sleep -Milliseconds 100
			}
		} else {
			Start-Sleep -Milliseconds 100
		}
	}
	if ($targetInfo) {
		foreach ($prop in $targetInfo.PSObject.Properties) {
			$tokens["{targetInfo.$($prop.Name)}"] = [string]$prop.Value
		}
	}

	# Move the sidecar into the run directory so it's part of the run artifacts.
	if (Test-Path -LiteralPath $targetInfoPath) {
		Move-Item -LiteralPath $targetInfoPath -Destination (Join-Path $runDirectory 'target-info.json') -Force
	}

	$manipulationTemplate = [string]$manifest.manipulation.commandLineTemplate
	$manipulationCommandLine = Resolve-Template -Template $manipulationTemplate -Tokens $tokens

	Write-Host "Manipulation command:"
	Write-Host $resolvedManipulationExecutable
	Write-Host $manipulationCommandLine

	# ---- 5. Run the manipulation tool ----
	$manipulationOutputPath = Join-Path $runDirectory 'manipulation-output.txt'

	if ($KeepWindowsOpen) {
		# Use ProcessStartInfo directly: Start-Process -RedirectStandardOutput
		# -PassThru returns a Process whose ExitCode is sometimes null after
		# WaitForExit because the handle is released early. We need the exit
		# code for empty-trace techniques like memorypatch.
		$psi = New-Object System.Diagnostics.ProcessStartInfo
		$psi.FileName = $resolvedManipulationExecutable
		$psi.Arguments = $manipulationCommandLine
		$psi.WorkingDirectory = $resolvedManipulationWorkingDirectory
		$psi.RedirectStandardOutput = $true
		$psi.RedirectStandardError = $true
		$psi.UseShellExecute = $false
		$psi.CreateNoWindow = $true
		$manipulationProcess = [System.Diagnostics.Process]::Start($psi)
		# Drain both streams before WaitForExit or a full buffer deadlocks us.
		$stdout = $manipulationProcess.StandardOutput.ReadToEnd()
		$stderr = $manipulationProcess.StandardError.ReadToEnd()
		$manipulationProcess.WaitForExit()
		Set-Content -LiteralPath $manipulationOutputPath -Value $stdout -Encoding utf8
		Set-Content -LiteralPath "$runDirectory\manipulation-error.txt" -Value $stderr -Encoding utf8
	} else {
		$manipulationProcess = Start-ManagedProcess `
			-Executable $resolvedManipulationExecutable `
			-WorkingDirectory $resolvedManipulationWorkingDirectory `
			-Arguments $manipulationCommandLine
		$manipulationProcess.WaitForExit()
	}

	$result.execution.manipulationPid = $manipulationProcess.Id
	$result.execution.commands.manipulation = New-CommandLine -Executable $resolvedManipulationExecutable -Arguments $manipulationCommandLine
	$result.execution.manipulationExitCode = $manipulationProcess.ExitCode

	# ---- 6. Cool-down so telemetry flushes, then stop telemetry ----
	Start-Sleep -Seconds ([int]$manifest.timings.cooldownSeconds)

	if ($telemetryProcess -and -not $telemetryProcess.HasExited) {
		Stop-Process -Id $telemetryProcess.Id -Force
	}

	# ---- 7. Tear-down (or, with -KeepWindowsOpen, leave target alive for inspection) ----
	if ($KeepWindowsOpen) {
		Write-Host ""
		Write-Host "Target left running (PID $($targetProcess.Id)) - close its window manually." -ForegroundColor Yellow

		# Show the captured output in a persistent window
		if (Test-Path -LiteralPath $manipulationOutputPath) {
			$exitCode = $manipulationProcess.ExitCode
			$batchPath = Join-Path $runDirectory 'show-results.cmd'
			$batchLines = @(
				'@echo off',
				'echo === Manipulation Output ===',
				'echo.',
				('type "' + $manipulationOutputPath + '"'),
				'echo.',
				('echo === Exit Code: ' + $exitCode + ' ==='),
				'echo.',
				'pause'
			)
			Set-Content -LiteralPath $batchPath -Value $batchLines -Encoding Ascii
			Start-Process -FilePath 'cmd.exe' -ArgumentList ('/k "' + $batchPath + '"')
		}
	} else {
		if ($targetProcess -and -not $targetProcess.HasExited) {
			Stop-Process -Id $targetProcess.Id -Force
		}
	}

	# ---- 8. Persist the final manifest ----
	Write-FinalManifest -Status 'completed'

	if ($KeepWindowsOpen) {
		Write-Host ""
		Write-Host "Run complete. Manifest written to: $finalManifestPath" -ForegroundColor Green
		Read-Host "Press Enter to close this runner window"
	}
}
catch {
	# Best-effort cleanup of any process we started, then re-throw so the user sees the error.
	if ($telemetryProcess -and -not $telemetryProcess.HasExited) {
		Stop-Process -Id $telemetryProcess.Id -Force -ErrorAction SilentlyContinue
	}

	if ($targetProcess -and -not $targetProcess.HasExited) {
		Stop-Process -Id $targetProcess.Id -Force -ErrorAction SilentlyContinue
	}

	$result.execution.status = 'failed'
	$result.execution.error = $_.Exception.Message
	Write-FinalManifest -Status 'failed'
	throw
}
