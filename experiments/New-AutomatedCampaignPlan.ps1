# Prepare an immutable, seeded schedule; no processes or services are started.
[CmdletBinding()]
param(
    [ValidateSet('Core','RQ3','Games','All')] [string]$Suite = 'Core',
    [ValidateSet('Pilot','Final')] [string]$Phase = 'Pilot',
    [ValidateRange(0,100)] [int]$Replicates = 0,
    [ValidateSet('All','TIOnly')] [string[]]$ProviderProfiles = @('All','TIOnly'),
    [int]$Seed = 20260909,
    [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Campaign-Helpers.ps1')
$repo = Split-Path $PSScriptRoot -Parent
$id = 'auto-' + $Suite.ToLowerInvariant() + '-' + $Phase.ToLowerInvariant() + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot "campaigns\$id" }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Campaign already exists: $OutputDirectory" }
if ($Replicates -eq 0) { $Replicates = if ($Phase -eq 'Pilot') { 2 } else { 10 } }
$core = @('baseline','basic-loadlibrary','basic-manualmap','basic-threadhijack','basic-patch-data','patch_aob','patch_tick','patch_rwxflip','apc_classic','hook_iat','hook_inline')
$rq3 = @('basic-loadlibrary','patch_tick','hook_inline','apc_classic')
$games = @('injection_loadlibrary_assaultcube','injection_manualmap_assaultcube','injection_threadhijack_assaultcube','apc_classic_ac','patch_aob_ac','patch_tick_ac','hook_iat_ac','hook_inline_ac','injection_loadlibrary_xonotic','external\baseline_external_ac','external\baseline_external_xonotic')
$specs = @()
if ($Suite -in @('Core','All')) { foreach ($stem in $core) { $specs += @{stem=$stem; profile='All'; route='none'; group='core'} } }
if ($Suite -in @('Games','All')) { foreach ($stem in $games) { $specs += @{stem=$stem; profile='All'; route='none'; group='games'} } }
if ($Suite -in @('RQ3','All')) {
    foreach ($stem in $rq3) { foreach ($profile in ($ProviderProfiles | Select-Object -Unique)) { foreach ($route in @('none','direct_syscall')) {
        $specs += @{stem=$stem; profile=$profile; route=$route; group='rq3'}
    } } }
    foreach ($profile in ($ProviderProfiles | Select-Object -Unique)) {
        $specs += @{stem='patch_tick'; profile=$profile; route='temporal_spread'; group='rq3'}
    }
}
$cases = @()
foreach ($spec in $specs) {
    $source = Join-Path $PSScriptRoot ("manifests\" + $spec.stem + '.json')
    $m = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json
    Assert-AutomatableManifest $m
    $meta = $m.metadata
    if (-not $meta.PSObject.Properties['extra']) { $meta | Add-Member -NotePropertyName extra -NotePropertyValue ([pscustomobject]@{}) }
    $m.name = 'auto_' + ($spec.stem -replace '^external\\','') + '_' + $spec.group + '_' + $spec.profile.ToLowerInvariant() + '_' + $spec.route
    if ($meta.label -eq 'baseline') { $meta.label = 'benign' }
    $meta | Add-Member -NotePropertyName evasion -NotePropertyValue $spec.route -Force
    $meta | Add-Member -NotePropertyName source -NotePropertyValue 'synthetic' -Force
    if (-not $meta.PSObject.Properties['class']) {
        $kind = if ($meta.label -eq 'benign') { 'benign' } elseif ($spec.stem -match 'patch') { 'patch' } else { 'injection' }
        $variant = if ($kind -eq 'benign') { '' } elseif ($kind -eq 'patch') { 'direct' } elseif ($spec.stem -match 'manualmap') { 'manualmap' } elseif ($spec.stem -match 'threadhijack') { 'threadhijack' } else { 'loadlibrary' }
        $meta | Add-Member -NotePropertyName class -NotePropertyValue $kind
        $meta | Add-Member -NotePropertyName variant -NotePropertyValue $variant -Force
    }
    $extra = $meta.extra
    foreach ($item in @{campaign_id=$id; phase=$Phase.ToLowerInvariant(); provider_profile=$spec.profile.ToLowerInvariant(); pair_id=($spec.group + ':' + $spec.stem); implementation_family='cmf-process-toolkit'; automation_suite=$spec.group; success_protocol='independent-verification-v2'}.GetEnumerator()) {
        $extra | Add-Member -NotePropertyName $item.Key -NotePropertyValue $item.Value -Force
    }
    if ($spec.profile -eq 'TIOnly') { $m.providers = @($m.providers | Where-Object name -eq 'ThreatIntelligence') }
    if ($m.PSObject.Properties['manipulation'] -and $m.manipulation) {
        $command = [string]$m.manipulation.commandLineTemplate
        # Delivery is verified by TestDll's target-specific event, avoiding
        # the additional remote thread created by --call RunTest.
        $command = $command -replace '\s+--call\s+RunTest(?=\s|$)', ''
        $command = $command -replace '(?<!")\{repoRoot\}\\[^\s"]+\.dll', '"$0"'
        if ($command -match 'TestDll\.dll') { $extra | Add-Member -NotePropertyName success_criterion -NotePropertyValue 'Target-specific TestDll attach event; exit code 0; target survives.' -Force }
        if ($spec.group -eq 'rq3') { $command += ' --observe-usermode-hooks' }
        if ($spec.route -eq 'direct_syscall') { $command += ' --via-direct-syscall' }
        if ($spec.route -eq 'temporal_spread') {
            if ($command -notmatch '--tick-count 20' -or $command -notmatch '--tick-interval-ms 50') { throw 'Temporal comparison requires the fixed 20-write, 50 ms base case.' }
            $command = $command -replace '--tick-interval-ms 50', '--tick-interval-ms 500'
            $extra | Add-Member -NotePropertyName tick_interval_ms -NotePropertyValue 500 -Force
            $extra | Add-Member -NotePropertyName intervention -NotePropertyValue 'Same 20 periodic writes, interval 50 ms -> 500 ms. This is not generic injection-stage spreading.' -Force
        }
        $m.manipulation.commandLineTemplate = $command
        Assert-AutomatableManifest $m
    }
    $cases += @{manifest=$m; source=$source; source_sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash}
}
New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'manifests') -Force | Out-Null
$rng = [Random]::new($Seed)
$runs = @()
for ($rep=1; $rep -le $Replicates; $rep++) {
    $block = @($cases)
    for ($i=$block.Count-1; $i -gt 0; $i--) { $j=$rng.Next($i+1); $swap=$block[$i]; $block[$i]=$block[$j]; $block[$j]=$swap }
    foreach ($case in $block) {
        $m = $case.manifest | ConvertTo-Json -Depth 25 | ConvertFrom-Json
        $m.metadata.extra | Add-Member -NotePropertyName repetition -NotePropertyValue $rep -Force
        $path = Join-Path $OutputDirectory ("manifests\r{0:D2}-{1}.json" -f $rep,$m.name)
        $m | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $path -Encoding UTF8
        $runs += [ordered]@{order=$runs.Count+1; repetition=$rep; name=$m.name; manifest=$path; manifest_sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; source_manifest=$case.source; source_manifest_sha256=$case.source_sha256}
    }
}
$plan = Join-Path $OutputDirectory 'plan.json'
[ordered]@{schemaVersion=2; campaign_id=$id; phase=$Phase.ToLowerInvariant(); suite=$Suite; seed=$Seed; replicates=$Replicates; case_count=$cases.Count; runsRoot=(Join-Path $OutputDirectory 'runs'); runs=@($runs)} |
    ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $plan -Encoding UTF8
Write-Host "Prepared $($cases.Count) conditions x $Replicates repetitions = $($runs.Count) attempts. No captures started."
Write-Output $plan
