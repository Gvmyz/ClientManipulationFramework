[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$ManifestPath
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
		[Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$Arguments,
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

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceManifestPath = Resolve-RepoPath -PathValue $ManifestPath
$manifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json

$experimentName = if ($manifest.name) { [string]$manifest.name } else { 'experiment' }
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

$runIdProperty = $manifest.PSObject.Properties['runId']
$runId = if ($runIdProperty -and $runIdProperty.Value) {
	[string]$runIdProperty.Value
} else {
	"$timestamp-$experimentName"
}
# $runId = if ($manifest.runId) { [string]$manifest.runId } else { "$timestamp-$experimentName" }
$runDirectory = Join-Path -Path $script:RepoRoot -ChildPath (Join-Path 'experiments\runs' $runId)
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null

$telemetryOutputPath = Join-Path $runDirectory 'telemetry.jsonl'
$finalManifestPath = Join-Path $runDirectory 'manifest.json'

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
	$targetProcess = Start-ManagedProcess -Executable $resolvedTargetExecutable -WorkingDirectory $resolvedTargetWorkingDirectory -Arguments ([string]$manifest.target.arguments)
	$result.execution.targetPid = $targetProcess.Id
	$result.execution.commands.target = New-CommandLine -Executable $resolvedTargetExecutable -Arguments ([string]$manifest.target.arguments)

	$telemetryArguments = New-Object 'System.Collections.Generic.List[string]'
	$telemetryArguments.Add([string]$manifest.providerGuid)
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

	$telemetryProcess = Start-ManagedProcess -Executable $resolvedTelemetryExecutable -WorkingDirectory $resolvedTelemetryWorkingDirectory -Arguments (Join-CommandLine $telemetryArguments.ToArray())
	$result.execution.telemetryPid = $telemetryProcess.Id
	$result.execution.commands.telemetry = New-CommandLine -Executable $resolvedTelemetryExecutable -Arguments (Join-CommandLine $telemetryArguments.ToArray())

	Start-Sleep -Seconds ([int]$manifest.timings.warmupSeconds)
	Write-Host "Telemetry command:"
	Write-Host $resolvedTelemetryExecutable
	Write-Host (Join-CommandLine $telemetryArguments.ToArray())

	$manipulationTemplate = [string]$manifest.manipulation.commandLineTemplate
	$manipulationCommandLine = Resolve-Template -Template $manipulationTemplate -Tokens @{
		'{targetPid}' = $targetProcess.Id
		'{runId}' = $runId
		'{runDirectory}' = $runDirectory
		'{telemetryOutput}' = $telemetryOutputPath
	}

	Write-Host "Manipulation command:"
	Write-Host $resolvedManipulationExecutable
	Write-Host $manipulationCommandLine


	$manipulationProcess = Start-ManagedProcess -Executable $resolvedManipulationExecutable -WorkingDirectory $resolvedManipulationWorkingDirectory -Arguments $manipulationCommandLine
	$result.execution.manipulationPid = $manipulationProcess.Id
	$result.execution.commands.manipulation = New-CommandLine -Executable $resolvedManipulationExecutable -Arguments $manipulationCommandLine
	$manipulationProcess.WaitForExit()
	$result.execution.manipulationExitCode = $manipulationProcess.ExitCode

	Start-Sleep -Seconds ([int]$manifest.timings.cooldownSeconds)

	if ($telemetryProcess -and -not $telemetryProcess.HasExited) {
		Stop-Process -Id $telemetryProcess.Id -Force
	}

	if ($targetProcess -and -not $targetProcess.HasExited) {
		Stop-Process -Id $targetProcess.Id -Force
	}

	Write-FinalManifest -Status 'completed'
}
catch {
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
