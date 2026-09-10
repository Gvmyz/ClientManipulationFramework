# Functional checks against fresh instances of our own TestTarget. No PPL/ETW.
[CmdletBinding()]
param([string]$BuildRoot = 'ProcessToolkit')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'Campaign-Helpers.ps1')
$build = if ([IO.Path]::IsPathRooted($BuildRoot)) { $BuildRoot } else { Join-Path $repo $BuildRoot }
$bin = Join-Path $build 'x64\Release'
$output = Join-Path $repo ('artifacts\synthetic-smoke-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $output | Out-Null
$cases = @('basic-loadlibrary','patch_tick','hook_inline','apc_classic','basic-manualmap','basic-threadhijack','basic-patch-data','patch_aob','patch_rwxflip','hook_iat')
$results = @()
foreach ($stem in $cases) {
    $routes = if ($stem -in @('basic-loadlibrary','patch_tick','hook_inline','apc_classic')) { @('none','direct_syscall') } else { @('none') }
    foreach ($route in $routes) {
        $target = $null
        $tool = $null
        $caseDir = Join-Path $output "$stem-$route"
        New-Item -ItemType Directory -Path $caseDir | Out-Null
        try {
            $target = Start-Process -FilePath (Join-Path $bin 'TestTarget.exe') -WorkingDirectory $caseDir -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $caseDir 'target.stdout.log') -RedirectStandardError (Join-Path $caseDir 'target.stderr.log')
            $infoPath = Join-Path $caseDir ("target-info-$($target.Id).json")
            $deadline = (Get-Date).AddSeconds(10)
            while (-not (Test-Path -LiteralPath $infoPath)) {
                if ($target.HasExited -or (Get-Date) -gt $deadline) { throw 'TestTarget did not publish its address sidecar.' }
                Start-Sleep -Milliseconds 100
            }
            $info = Get-Content -LiteralPath $infoPath -Raw | ConvertFrom-Json
            $m = Get-Content -LiteralPath (Join-Path $repo "experiments\manifests\$stem.json") -Raw | ConvertFrom-Json
            $command = $m.manipulation.commandLineTemplate.Replace('{targetPid}',[string]$target.Id)
            foreach ($property in $info.PSObject.Properties) { $command = $command.Replace("{targetInfo.$($property.Name)}",[string]$property.Value) }
            $command = $command -replace '\s+--call\s+RunTest(?=\s|$)', ''
            $command = $command.Replace('{repoRoot}\ProcessToolkit\x64\Release\TestDll.dll',('"' + (Join-Path $bin 'TestDll.dll') + '"'))
            $command += ' --observe-usermode-hooks'
            if ($route -eq 'direct_syscall') { $command += ' --via-direct-syscall' }
            if ($command -match '\{[^}]+\}') { throw "Unresolved command: $command" }
            $command | Set-Content -LiteralPath (Join-Path $caseDir 'command.txt')
            $stdoutPath = Join-Path $caseDir 'tool.stdout.log'
            $tool = Start-Process -FilePath (Join-Path $bin 'ProcessToolkit.exe') -ArgumentList $command -WorkingDirectory $caseDir -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError (Join-Path $caseDir 'tool.stderr.log')
            if (-not $tool.WaitForExit(30000)) { throw 'Tool timed out at 30 seconds.' }
            $tool.Refresh(); $target.Refresh()
            $marker = if ($command -match 'TestDll.dll') { Test-PayloadAttachMarker $target.Id 2 } else { $false }
            $outcome = Get-AutomaticOutcome -Command $command -ExitCode $tool.ExitCode -TargetSurvived (-not $target.HasExited) -Baseline $false -Stdout (Get-Content -LiteralPath $stdoutPath -Raw) -AttachMarkerObserved $marker
            $results += [pscustomobject]@{technique=$stem; route=$route; exit_code=$tool.ExitCode; effect_verified=$outcome.effect_verified; target_survived=$outcome.target_survived; evidence=$outcome.effect_evidence; directory=$caseDir}
            Write-Host "$stem/$route : exit $($tool.ExitCode), effect $($outcome.effect_verified), target alive $($outcome.target_survived)"
        } finally {
            if ($tool -and -not $tool.HasExited) { Stop-Process -Id $tool.Id -Force }
            if ($target -and -not $target.HasExited) { Stop-Process -Id $target.Id -Force }
            ConvertTo-Json -InputObject @($results) -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'results.json') -Encoding UTF8
        }
    }
}
$failed = @($results | Where-Object { $_.effect_verified -ne $true -or $_.target_survived -ne $true })
if ($failed.Count) { throw "$($failed.Count) smoke cases failed or remain unverified. Inspect $output" }
Write-Output "PASS: $($results.Count) fresh-target functional checks. These are smoke tests, not thesis captures. Evidence: $output"
