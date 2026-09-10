$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$experiments=Split-Path $PSScriptRoot -Parent
$repo=Split-Path $experiments -Parent
. (Join-Path $experiments 'Campaign-Helpers.ps1')
function Assert($Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
$guid='{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}'
$quality=Get-CaptureQuality "enable $guid status=0 match_any=all`nvm-logging status=0x00000000`ndecoder_version=2`ndecode_health error_events=0 write_errors=0 trace_status=0" 'capture_health events_lost=0 log_buffers_lost=0 realtime_buffers_lost=0; child exited gracefully' @($guid)
Assert ($quality.provider_startup_verified -and $quality.decode_health_verified -and $quality.consumer_shutdown_clean -and $quality.event_loss_observed -eq $false) 'Healthy capture not recognized'
$missing=Get-CaptureQuality '' '' @($guid)
Assert ($null -eq $missing.event_loss_observed -and -not $missing.provider_startup_verified) 'Unknown health was treated as success'
$failed=Get-AutomaticOutcome '--verify' 1 $true $false '[+] anything'
Assert ($failed.effect_verified -eq $false) 'Failed tool was admitted'
$unknown=Get-AutomaticOutcome 'hook-inline --verify --verify-hits 0' 0 $true $false '[+] installed'
Assert ($null -eq $unknown.effect_verified) 'Structural-only verification was counted as functional proof'
$marker=Get-AutomaticOutcome 'inject-manualmap --dll TestDll.dll' 0 $true $false '' -AttachMarkerObserved $true
Assert ($marker.effect_verified -eq $true) 'Independent delivery marker not recognized'
$startupOnly=Get-AutomaticOutcome 'patch-memory --verify' 0 $true $false '[+] Opened process 1234'
Assert ($null -eq $startupOnly.effect_verified) 'A startup success line was treated as independent effect proof'
$patchVerified=Get-AutomaticOutcome 'patch-memory --verify' 0 $true $false '[+] Read-back matches requested patch'
Assert ($patchVerified.effect_verified -eq $true) 'Exact read-back verification not recognized'
$hookVerified=Get-AutomaticOutcome 'hook-inline --verify' 0 $true $false '[+] Hook fired at least 1 time(s)'
Assert ($hookVerified.effect_verified -eq $true) 'Exact nonzero hook-counter verification not recognized'
$hookWrongMessage=Get-AutomaticOutcome 'apc-inject --verify' 0 $true $false '[+] Hook fired at least 1 time(s)'
Assert ($null -eq $hookWrongMessage.effect_verified) 'A different command verification was accepted'
$crashed=Get-AutomaticOutcome 'inject-manualmap --dll TestDll.dll' 0 $false $false '' -AttachMarkerObserved $true
Assert ($crashed.effect_verified -eq $false) 'A marker with a crashed target was admitted'
$unsupported=[pscustomobject]@{name='legacy-x86'; manipulation=[pscustomobject]@{executable='ProcessToolkit/Win32/Release/ProcessToolkit.exe'; commandLineTemplate='patch-memory --via-direct-syscall'}}
try { Assert-SupportedManifest $unsupported; throw 'guard failed' } catch { Assert ($_.Exception.Message -match 'x64-only') 'Interactive legacy x86 direct-syscall accepted' }
$output=Join-Path $repo ('artifacts\campaign-tests-' + [guid]::NewGuid().ToString('N'))
$plan=& (Join-Path $experiments 'New-AutomatedCampaignPlan.ps1') -Suite RQ3 -Phase Pilot -OutputDirectory $output
$p=Get-Content -LiteralPath $plan -Raw | ConvertFrom-Json
Assert ($p.case_count -eq 18 -and $p.runs.Count -eq 36) 'Unexpected RQ3 matrix size'
$conditions=@{}
foreach ($run in $p.runs) {
    $m=Get-Content -LiteralPath $run.manifest -Raw | ConvertFrom-Json
    Assert-AutomatableManifest $m
    Assert ($m.manipulation.executable -like '*\x64\*') 'RQ3 selected an unsupported architecture'
    Assert ($m.manipulation.commandLineTemplate -match '--observe-usermode-hooks') 'Unequal probe configuration'
    Assert ($m.manipulation.commandLineTemplate -notmatch '--call RunTest') 'Extra verification remote thread remains'
    if ($m.metadata.evasion -eq 'temporal_spread') { Assert ($m.manipulation.commandLineTemplate -match '--tick-count 20 --tick-interval-ms 500') 'Timing perturbation changed the wrong parameter' }
    if ($m.metadata.extra.provider_profile -eq 'tionly') { Assert ($m.providers.Count -eq 1 -and $m.providers[0].name -eq 'ThreatIntelligence') 'TI-only profile includes another provider' }
    $key="$($m.metadata.extra.pair_id)|$($m.metadata.extra.provider_profile)|$($m.metadata.extra.repetition)"
    if (-not $conditions.ContainsKey($key)) { $conditions[$key]=@() }
    $conditions[$key]+=$m.metadata.evasion
}
foreach ($routes in $conditions.Values) { Assert ($routes -contains 'none' -and $routes -contains 'direct_syscall') 'Unpaired route intervention' }
$manual=Get-Content -LiteralPath (Join-Path $experiments 'manifests\external\external_extremeinjector_threadhijack_ac.json') -Raw | ConvertFrom-Json
try { Assert-AutomatableManifest $manual; throw 'guard failed' } catch { Assert ($_.Exception.Message -match 'Manual manifest') 'Manual manifest accepted unattended' }
Write-Output 'PASS: health, outcomes, x64-only paired RQ3, timing factor, payload protocol and manual-run guard.'
