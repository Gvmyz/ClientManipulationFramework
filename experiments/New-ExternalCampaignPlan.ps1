# Prepare randomized, separate pilot/final queues. This script runs no tools/games.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Pilot', 'Final')] [string] $Phase,
    [ValidateRange(0, 1000)] [int] $Replicates = 0,
    [int] $Seed = 20260908,
    [string] $Only = '',
    [string[]] $Exclude = @(),
    [string] $OutputDirectory = '',
    [switch] $PilotsReviewed,
    [switch] $IncludeOptional
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$campaignId = $Phase.ToLowerInvariant() + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
if ($Replicates -eq 0) { $Replicates = if ($Phase -eq 'Pilot') { 2 } else { 5 } }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot ('campaigns\' + $campaignId) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Output already exists; refusing to overwrite a campaign: $OutputDirectory" }

$cases = @()
$omitted = @()
foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'manifests\external') -Filter '*.json' | Sort-Object Name)) {
    $m = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $status = [string]$m.metadata.extra.validation_status
    $reason = ''
    if ($status -like 'retired*') { $reason = $status }
    elseif ($m.metadata.extra.PSObject.Properties['campaign_optional'] -and $m.metadata.extra.campaign_optional -and -not $IncludeOptional) { $reason = 'Optional condition; use -IncludeOptional to select it.' }
    elseif ($Only -and $m.name -notlike "*$Only*") { $reason = 'Only filter' }
    else {
        foreach ($pattern in $Exclude) {
            if ($m.name -like $pattern) { $reason = "Explicit exclusion: $pattern"; break }
        }
    }
    if ($reason) { $omitted += @{ name = $m.name; reason = $reason }; continue }
    if ($Phase -eq 'Final') {
        if ($status -ne 'pilot_passed' -and -not $PilotsReviewed) { throw 'Review the pilots first, then use -Phase Final -PilotsReviewed. No manifest SHA fields need manual editing.' }
    }
    $cases += @{ file = $file.FullName; manifest = $m; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
}
if (-not $cases.Count) { throw 'No eligible cases selected.' }
$manifestDir = Join-Path $OutputDirectory 'manifests'
New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
$rng = New-Object System.Random -ArgumentList $Seed
$runs = @()
for ($replicate = 1; $replicate -le $Replicates; $replicate++) {
    $block = @($cases)
    for ($i = $block.Count - 1; $i -gt 0; $i--) {
        $j = $rng.Next($i + 1)
        $swap = $block[$i]; $block[$i] = $block[$j]; $block[$j] = $swap
    }
    foreach ($case in $block) {
        $m = $case.manifest | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $m.metadata.extra | Add-Member -NotePropertyName campaign_id -NotePropertyValue $campaignId -Force
        $m.metadata.extra | Add-Member -NotePropertyName phase -NotePropertyValue $Phase.ToLowerInvariant() -Force
        $m.metadata.extra | Add-Member -NotePropertyName repetition -NotePropertyValue $replicate -Force
        $path = Join-Path $manifestDir ("r{0:D2}-{1}.json" -f $replicate, $m.name)
        $m | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
        $runs += [ordered]@{
            order = $runs.Count + 1; repetition = $replicate; name = $m.name
            manifest = $path; manifest_sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            source_manifest = $case.file; source_manifest_sha256 = $case.sha256
        }
    }
}
$planPath = Join-Path $OutputDirectory 'plan.json'
[ordered]@{
    schemaVersion = 1; campaign_id = $campaignId; phase = $Phase.ToLowerInvariant()
    seed = $Seed; replicates = $Replicates; case_count = $cases.Count; pilots_reviewed = [bool]$PilotsReviewed
    runsRoot = (Join-Path $OutputDirectory 'runs'); omitted = @($omitted); runs = @($runs)
} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $planPath -Encoding UTF8
Write-Host ("Prepared {0} cases x {1} repetitions = {2} attempts. No captures executed." -f $cases.Count, $Replicates, $runs.Count)
Write-Host 'Read docs/external-cheats/runbook.md before running the queue. Never mix pilot captures into the scored corpus.'
Write-Output $planPath
