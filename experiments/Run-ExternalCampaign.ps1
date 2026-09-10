# Captures a frozen external-tool queue. Only tool/game actions remain manual.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Plan,
    [switch]$PreflightOnly,
    [switch]$Resume,
    [switch]$SkipBootstrap,
    [ValidateRange(0,60)] [int]$InterRunSleepSeconds = 3
)
$ErrorActionPreference = 'Stop'
$invoke = @{} + $PSBoundParameters
$invoke.AllowManualTools = $true
& (Join-Path $PSScriptRoot 'Run-AutomatedCampaign.ps1') @invoke
