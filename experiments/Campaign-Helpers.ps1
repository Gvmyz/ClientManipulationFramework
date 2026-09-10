# Pure helpers shared by the runner, planning and regression checks.
function Get-CaptureQuality {
    param([string]$TelemetryLog, [string]$RunnerLog, [string[]]$ProviderGuids)
    $startup = $ProviderGuids.Count -gt 0
    foreach ($guid in $ProviderGuids) {
        if ($TelemetryLog -notmatch ('(?i)enable ' + [regex]::Escape($guid) + ' status=0(?:\s|$)')) { $startup = $false }
    }
    # `event_loss_observed` reports whether the runner logged any lost
    # events / lost buffers. When the runner does NOT emit a
    # capture_health line at all, we have no evidence of loss (and no
    # evidence of no-loss) — the honest default is $false so downstream
    # gates don't reject the run for absence-of-evidence. A future
    # PPLRunner build that adds the capture_health line will let this
    # detector switch to $true when loss actually occurred.
    $loss = $false
    $matchesFound = [regex]::Matches($RunnerLog, 'capture_health events_lost=(\d+) log_buffers_lost=(\d+) realtime_buffers_lost=(\d+)')
    if ($matchesFound.Count) {
        $last = $matchesFound[$matchesFound.Count - 1]
        $loss = ([long]$last.Groups[1].Value + [long]$last.Groups[2].Value + [long]$last.Groups[3].Value) -gt 0
    }
    [ordered]@{
        decode_health_verified = [bool]($TelemetryLog -match 'decode_health error_events=0 write_errors=0 trace_status=0(?:\s|$)')
        provider_startup_verified = [bool]$startup
        vm_logging_opt_in_verified = [bool]($TelemetryLog -match 'vm-logging.*status=0x00000000')
        decoder_version = $(if ($TelemetryLog -match 'decoder_version=2') { 2 } else { 1 })
        event_loss_observed = $loss
        consumer_shutdown_clean = [bool]($RunnerLog -match 'child exited gracefully' -and $RunnerLog -notmatch '(?i)terminat|fallback')
    }
}

function Get-AutomaticOutcome {
    param([string]$Command, [Nullable[int]]$ExitCode, [bool]$TargetSurvived, [bool]$Baseline, [string]$Stdout, [bool]$AttachMarkerObserved = $false)
    $verified = $null
    $evidence = @()
    # Strip console colour sequences before matching an explicit, command-specific
    # verification result. An unrelated [+] startup line is not effect evidence.
    $plainStdout = $Stdout -replace '\x1b\[[0-?]*[ -/]*[@-~]', ''
    $verificationPattern = $null
    if ($Command -match '(?:^|\s)(?:patch-memory|patch-aob)(?:\s|$)') { $verificationPattern = 'Read-back matches requested patch' }
    elseif ($Command -match '(?:^|\s)hook-inline(?:\s|$)') { $verificationPattern = 'Hook fired at least [1-9]\d* time\(s\)' }
    elseif ($Command -match '(?:^|\s)hook-iat(?:\s|$)') { $verificationPattern = 'IAT hook fired at least [1-9]\d* time\(s\)' }
    elseif ($Command -match '(?:^|\s)apc-inject(?:\s|$)') { $verificationPattern = 'APC fired at least [1-9]\d* time\(s\)' }
    if (-not $TargetSurvived) { $verified = $false; $evidence = @('Target exited before completion of the observation window.') }
    elseif ($null -ne $ExitCode -and $ExitCode -ne 0) { $verified = $false; $evidence = @("Tool exit code $ExitCode") }
    elseif ($ExitCode -eq 0 -and $Baseline) { $verified = $TargetSurvived; $evidence = @('Fixed benign observation completed; target survival checked by runner.') }
    elseif ($ExitCode -eq 0 -and $AttachMarkerObserved) { $verified = $true; $evidence = @('Target-specific TestDll attach event was signaled; no extra remote verification thread.') }
    elseif ($ExitCode -eq 0 -and $verificationPattern -and $Command -match '(?:^|\s)--verify(?:\s|$)' -and $Command -notmatch '--verify-hits\s+0(?:\s|$)' -and $plainStdout -match ('(?m)^\[\+\]\s+' + $verificationPattern + '\s*$')) {
        $verified = $true; $evidence = @('ProcessToolkit reported the command-specific read-back or nonzero execution-counter verification with exit 0; see manipulation.stdout.log.')
    }
    elseif ($ExitCode -eq 0 -and $Command -match '--call\s+RunTest(?:\s|$)' -and $plainStdout -match '(?m)^\[\+\]\s+Called function RunTest\s*$') {
        $verified = $true; $evidence = @('Remote RunTest export call completed; see manipulation.stdout.log.')
    }
    [ordered]@{ outcome=$(if($verified -eq $true){'verified'}elseif($verified -eq $false){'failed'}else{'unverified'}); effect_verified=$verified; effect_evidence=$evidence; target_survived=$TargetSurvived }
}

function Test-PayloadAttachMarker {
    param([int]$TargetPid, [int]$TimeoutSeconds = 5)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $marker = [Threading.EventWaitHandle]::OpenExisting("Local\CMF_TestDll_Attached_$TargetPid")
            try { return $marker.WaitOne(0) } finally { $marker.Dispose() }
        } catch [Threading.WaitHandleCannotBeOpenedException] { }
        if ((Get-Date) -ge $deadline) { return $false }
        Start-Sleep -Milliseconds 100
    } while ($true)
}

function Assert-AutomatableManifest {
    param($Manifest)
    $hasCommand = $Manifest.PSObject.Properties['manipulation'] -and $Manifest.manipulation -and $Manifest.manipulation.commandLineTemplate
    $observation = $Manifest.timings.PSObject.Properties['observationSeconds'] -and [int]$Manifest.timings.observationSeconds -gt 0
    if (-not $hasCommand -and -not $observation) { throw "Manual manifest cannot run unattended: $($Manifest.name)" }
    Assert-SupportedManifest $Manifest
}

function Assert-SupportedManifest {
    param($Manifest)
    $hasCommand = $Manifest.PSObject.Properties['manipulation'] -and $Manifest.manipulation -and $Manifest.manipulation.commandLineTemplate
    if ($hasCommand -and $Manifest.manipulation.commandLineTemplate -match '--via-direct-syscall' -and $Manifest.manipulation.executable -match '(?i)[\\/](Win32|x86)[\\/]') {
        throw "Direct syscalls are x64-only; unsupported manifest: $($Manifest.name)"
    }
}
