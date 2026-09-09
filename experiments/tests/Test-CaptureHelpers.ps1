# Regression tests; no services, games or external binaries are started.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$experiments = Split-Path $PSScriptRoot -Parent
$repo = Split-Path $experiments -Parent
. (Join-Path $experiments 'Capture-Helpers.ps1')
$count = 0
foreach ($file in (Get-ChildItem (Join-Path $experiments 'manifests\external') -Filter '*.json')) {
    $m = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $argsList = @(Get-CompactTelemetryMetadata $m.metadata.extra)
    for ($i=0; $i -lt $argsList.Count; $i+=2) {
        if ($argsList[$i] -ne '--meta' -or $argsList[$i+1] -notmatch '^[^=]+=.+$') { throw "Invalid metadata argument in $($m.name)" }
    }
    $command = 'C:\elam\bin\Telemetry.exe --output C:\elam\ti_test.json --session TISession --enable-vm-logging-pid 12345 --run-id ' + $m.name
    foreach ($p in $m.providers) { $command += ' --provider ' + $p.guid + ':' + $p.name }
    $command += ' --label ' + $m.metadata.label + ' --technique ' + $m.metadata.technique + ' --target "' + $m.metadata.target + '"'
    $command += ' ' + ($argsList -join ' ')
    Assert-PPLCommandLength $command
    $count++
}
$probe = [pscustomobject]@{target_bitness=$null; attacker_bitness=''; phase='Pilot'; operator_commands=('long prose ' * 1000); sha256=$null}
$compact = @(Get-CompactTelemetryMetadata $probe)
if (($compact -join '|') -ne '--meta|phase=Pilot') { throw 'Null or prose metadata leaked to CLI' }
Assert-PPLCommandLength ('x' * 2047)
try { Assert-PPLCommandLength ('x' * 2048); throw 'Length guard did not fire' } catch { if ($_.Exception.Message -notmatch '2048 UTF-8 bytes') { throw } }
try { Assert-PPLCommandLength ([string][char]0x00E9 * 1024); throw 'UTF-8 byte guard did not fire' } catch { if ($_.Exception.Message -notmatch '2048 UTF-8 bytes') { throw } }
$artifact = Get-CaptureArtifact -Role test -Path 'experiments\Capture-Helpers.ps1' -RepoRoot $repo
$expected = (Get-FileHash -LiteralPath (Join-Path $experiments 'Capture-Helpers.ps1')).Hash
if ($artifact.status -ne 'recorded' -or $artifact.sha256 -ne $expected) { throw 'Automatic artifact hash failed' }
$absent = Get-CaptureArtifact -Role test -Path 'experiments\__absent_artifact_for_test__.exe' -RepoRoot $repo
if ($absent.status -ne 'missing' -or $null -ne $absent.sha256) { throw 'Missing artifact invented a hash' }
Write-Output "PASS: $count external commands, null metadata, UTF-8 limits and automatic artifact hashing."
