# Compatibility entry point for the versioned, resumable automated campaign.
[CmdletBinding()]
param(
    [ValidateSet('Pilot','Final')] [string]$Phase='Pilot',
    [ValidateRange(0,100)] [int]$RunsPerManifest=0,
    [switch]$PlanOnly,
    [switch]$SkipBootstrap,
    [string]$OutputDirectory=''
)
$ErrorActionPreference='Stop'
$plan=& (Join-Path $PSScriptRoot 'New-AutomatedCampaignPlan.ps1') -Suite RQ3 -Phase $Phase -Replicates $RunsPerManifest -OutputDirectory $OutputDirectory
if ($PlanOnly) { Write-Output $plan; return }
& (Join-Path $PSScriptRoot 'Run-AutomatedCampaign.ps1') -Plan $plan -SkipBootstrap:$SkipBootstrap
