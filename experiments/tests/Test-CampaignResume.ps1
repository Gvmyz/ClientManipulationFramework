# Runs the real scheduling/journal code with stubbed capture and bootstrap scripts.
# No games, telemetry consumers, protected services, or real campaigns are started.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$experiments = Split-Path $PSScriptRoot -Parent
$repo = Split-Path $experiments -Parent
$testRoot = Join-Path $repo ('artifacts\campaign-resume-tests-' + [guid]::NewGuid().ToString('N'))
$fixture = Join-Path $testRoot 'experiments'
$catalog = Join-Path $testRoot 'manifests'
New-Item -ItemType Directory -Path $fixture,$catalog -Force | Out-Null
foreach ($file in @('Run-AutomatedCampaign.ps1','Run-ExternalCampaign.ps1','Campaign-Helpers.ps1')) {
    Copy-Item -LiteralPath (Join-Path $experiments $file) -Destination $fixture
}
$runner = Join-Path $fixture 'Run-AutomatedCampaign.ps1'
$binary = Join-Path $testRoot 'unused-target.bin'
Set-Content -LiteralPath $binary -Value 'This fixture is never executed.'
@'
param($ManifestPath,$RunsRoot,$Phase,[switch]$PassThru,[switch]$NonInteractive)
$m = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$campaign = Split-Path $RunsRoot -Parent
Add-Content -LiteralPath (Join-Path $campaign 'calls.txt') -Value $m.fixture_order
$stop = Join-Path $campaign 'stop-at.txt'
if ((Test-Path -LiteralPath $stop) -and [int](Get-Content -LiteralPath $stop) -eq $m.fixture_order) { throw 'Simulated capture failure' }
[pscustomobject]@{
    # Deliberately absent: resumption must not need retained run folders.
    runDirectory=(Join-Path $RunsRoot ('run-' + $m.fixture_order))
    outcome=[pscustomobject]@{effect_verified=$true; target_survived=$true}
    captureQuality=[pscustomobject]@{decoder_version=2; provider_startup_verified=$true; vm_logging_opt_in_verified=$true; event_loss_observed=$false; consumer_shutdown_clean=$true; decode_health_verified=$true}
}
'@ | Set-Content -LiteralPath (Join-Path $fixture 'Run-PPLExperiment.ps1') -Encoding UTF8
"'BOOTSTRAP' | Set-Content -LiteralPath (Join-Path `$PSScriptRoot 'bootstrap-called.txt')" |
    Set-Content -LiteralPath (Join-Path $fixture 'Bootstrap-ETWTI.ps1') -Encoding UTF8

function Assert($Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Expect-Failure([scriptblock]$Action,[string]$Pattern) {
    $message = $null
    try { & $Action | Out-Null } catch { $message = $_.Exception.Message }
    Assert ($null -ne $message -and $message -match $Pattern) "Expected '$Pattern'; received '$message'."
}
function Write-JsonArray([string]$Path,[object[]]$Items) {
    $parts = foreach ($item in $Items) { ConvertTo-Json -InputObject $item -Depth 12 -Compress }
    ('[' + (@($parts) -join ',') + ']') | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Read-Entries([string]$Path) {
    $decoded = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($entry in $decoded) { $entry }
}
function New-Entry([int]$Order,[string]$Status='effect_verified') {
    [pscustomobject]@{order=$Order; name="case-$Order"; repetition=1; status=$Status; effect_verified=($Status -eq 'effect_verified'); runDirectory=$null}
}
$jobs = @()
foreach ($order in 1..46) {
    $manifestPath = Join-Path $catalog "$order.json"
    [ordered]@{name="case-$order"; fixture_order=$order; target=@{executable=$binary}; timings=@{observationSeconds=1}; metadata=@{extra=@{}}} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $jobs += [pscustomobject]@{order=$order; name="case-$order"; repetition=1; manifest=$manifestPath; manifest_sha256=(Get-FileHash -LiteralPath $manifestPath).Hash}
}
function New-Case([string]$Name) {
    $dir = Join-Path $testRoot $Name
    New-Item -ItemType Directory -Path $dir | Out-Null
    $planPath = Join-Path $dir 'plan.json'
    [ordered]@{phase='final'; runsRoot=(Join-Path $dir 'runs'); runs=$jobs} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $planPath -Encoding UTF8
    [pscustomobject]@{directory=$dir; plan=$planPath; journal=(Join-Path $dir 'attempts.json'); calls=(Join-Path $dir 'calls.txt')}
}
function Invoke-Case($Case,[switch]$Resume,[int]$StartAt=0,[switch]$PreflightOnly) {
    $params = @{Plan=$Case.plan; SkipBootstrap=$true; InterRunSleepSeconds=0; WarningAction='SilentlyContinue'}
    if ($Resume) { $params.Resume=$true }
    if ($StartAt) { $params.StartAt=$StartAt }
    if ($PreflightOnly) { $params.PreflightOnly=$true }
    & $runner @params | Out-Null
}
function Assert-Calls($Case,[string]$Expected) {
    $actual = if (Test-Path -LiteralPath $Case.calls) { (Get-Content -LiteralPath $Case.calls) -join ',' } else { '' }
    Assert ($actual -eq $Expected) "Unexpected captures for $($Case.directory): $actual; expected $Expected."
}
$first43 = @(1..43 | ForEach-Object { New-Entry $_ })

$c = New-Case 'fresh-single-entry-roundtrip'
Set-Content -LiteralPath (Join-Path $c.directory 'stop-at.txt') -Value 1
Expect-Failure { Invoke-Case $c } 'Campaign paused after capture_failed'
Assert-Calls $c '1'
$raw = [IO.File]::ReadAllText($c.journal)
$read = @(Read-Entries $c.journal)
Assert ($raw.TrimStart().StartsWith('[') -and $read.Count -eq 1 -and $read[0].order -eq 1) 'First checkpoint was not a one-entry JSON array.'
Invoke-Case $c -Resume
Assert-Calls $c ((1..46) -join ',')
Assert (@(Read-Entries $c.journal).Count -eq 46) 'Single-entry resume lost or duplicated attempts.'

$c = New-Case 'existing-journal-missing-runs'
Write-JsonArray $c.journal $first43
Invoke-Case $c -Resume
Assert-Calls $c '44,45,46'
$read = @(Read-Entries $c.journal)
Assert ($read.Count -eq 46 -and $read[0].order -eq 1 -and $read[-1].order -eq 46) 'Journal did not remain a flat array.'
# Completed schedules should return before invoking bootstrap.
& $runner -Plan $c.plan -Resume | Out-Null
Assert (-not (Test-Path -LiteralPath (Join-Path $fixture 'bootstrap-called.txt'))) 'Completed campaign bootstrapped.'

$c = New-Case 'legacy-value-wrapper'
Write-JsonArray $c.journal @([pscustomobject]@{value=$first43; Count=43})
Invoke-Case $c -Resume
Assert-Calls $c '44,45,46'
Assert (@(Read-Entries $c.journal).Count -eq 46) 'Legacy wrapper was not flattened.'

$c = New-Case 'lost-journal'
Expect-Failure { Invoke-Case $c -Resume } 'No journal found'
Invoke-Case $c -Resume -StartAt 44 -PreflightOnly
Assert (-not (Test-Path -LiteralPath $c.journal)) 'Preflight modified the journal.'
Assert-Calls $c ''
Set-Content -LiteralPath (Join-Path $c.directory 'stop-at.txt') -Value 44
Expect-Failure { Invoke-Case $c -Resume -StartAt 44 } 'Campaign paused after capture_failed at order 44.*-Resume -StartAt 44.*plain -Resume skips'
Assert-Calls $c '44'
$read = @(Read-Entries $c.journal)
Assert ($read.Count -eq 44 -and $read[-1].status -eq 'capture_failed') 'Recovery did not persist the failed attempt.'
Assert (@($read | Where-Object { $_.order -lt 44 -and ($_.status -ne 'skipped_before_start' -or $null -ne $_.effect_verified -or $null -ne $_.startedAt) }).Count -eq 0) 'Skipped history was falsely marked verified or started.'
Invoke-Case $c -Resume
Assert-Calls $c '44,45,46'

$c = New-Case 'explicit-retry'
Write-JsonArray $c.journal @($first43 + (New-Entry 44 'capture_failed') + (New-Entry 45))
$old = [IO.File]::ReadAllText($c.journal)
Invoke-Case $c -Resume -StartAt 44
Assert-Calls $c '44,45,46'
$archives = @(Get-ChildItem -LiteralPath $c.directory -Filter 'attempts.before-start-44.*.json')
Assert ($archives.Count -eq 1 -and [IO.File]::ReadAllText($archives[0].FullName) -eq $old) 'Explicit recovery did not archive the original journal.'
Assert (@(Read-Entries $c.journal).Count -eq 46) 'Explicit retry left duplicate active orders.'

foreach ($bad in @('[{"order":1,','{"order":[1,2]}','')) {
    $c = New-Case ('invalid-' + [guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($c.journal,$bad)
    Expect-Failure { Invoke-Case $c -Resume } 'Cannot resume'
    Assert ([IO.File]::ReadAllText($c.journal) -eq $bad) 'Invalid journal was overwritten without explicit recovery.'
    Assert-Calls $c ''
    Invoke-Case $c -Resume -StartAt 44
    Assert-Calls $c '44,45,46'
    $archives = @(Get-ChildItem -LiteralPath $c.directory -Filter 'attempts.before-start-44.*.json')
    Assert ($archives.Count -eq 1 -and [IO.File]::ReadAllText($archives[0].FullName) -eq $bad) 'Corrupt input was not archived.'
}

$c = New-Case 'invalid-boundary'
Write-JsonArray $c.journal $first43
$old = [IO.File]::ReadAllText($c.journal)
Expect-Failure { Invoke-Case $c -Resume -StartAt 47 } 'not a scheduled order'
Expect-Failure { Invoke-Case $c -StartAt 44 } 'requires -Resume'
Assert ([IO.File]::ReadAllText($c.journal) -eq $old) 'Invalid boundary changed journal.'
Assert-Calls $c ''

$c = New-Case 'failed-checkpoint-write'
Write-JsonArray $c.journal $first43
$old = [IO.File]::ReadAllText($c.journal)
# Force replacement failure without filling the disk or changing permissions.
New-Item -ItemType Directory -Path ($c.journal + '.bak') | Out-Null
Expect-Failure { Invoke-Case $c -Resume } 'Replace'
Assert ([IO.File]::ReadAllText($c.journal) -eq $old) 'Checkpoint replacement failure truncated the journal.'
Assert-Calls $c ''
Assert (@(Get-ChildItem -LiteralPath $c.directory -Filter '*.tmp').Count -eq 0) 'Failed checkpoint left a temporary file.'

$c = New-Case 'external-wrapper'
& (Join-Path $fixture 'Run-ExternalCampaign.ps1') -Plan $c.plan -Resume -StartAt 44 -SkipBootstrap -InterRunSleepSeconds 0 | Out-Null
Assert-Calls $c '44,45,46'

Write-Output "PASS ($($PSVersionTable.PSVersion)): fresh/single-entry/saved/lost/corrupt journals, PowerShell 5.1 wrapper recovery, explicit order 44, retry/archive, persistent skips, preflight, bounds, checkpoint failure and external forwarding. Fixtures: $testRoot"
