# Lab-only deployment using the SAME certificate already trusted by ELAM.
# Does not create certificates, alter the ELAM driver, or start an experiment.
[CmdletBinding()]
param([string]$BinDirectory='C:\elam\bin', [string]$SignerThumbprint='', [string]$SignToolPath='')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$source=Join-Path $repo 'ProcessToolkit\x64\Release'
$service=Get-Service PPLRunner -ErrorAction Stop
if ($service.Status -ne 'Stopped') { throw 'Finish the active capture and stop PPLRunner before updating its files.' }
$old=Get-AuthenticodeSignature -LiteralPath (Join-Path $BinDirectory 'Telemetry.exe')
if (-not $SignerThumbprint) {
    if (-not $old.SignerCertificate) { throw 'Cannot infer the existing ELAM signer. Supply -SignerThumbprint for the already registered certificate.' }
    $SignerThumbprint=$old.SignerCertificate.Thumbprint
}
if ($old.SignerCertificate -and $old.SignerCertificate.Thumbprint -ne $SignerThumbprint) { throw 'Signer differs from deployed Telemetry. This helper preserves the existing ELAM trust identity.' }
$cert=$null; $machine=$false
foreach ($store in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
    $candidate=Get-ChildItem -LiteralPath $store | Where-Object { $_.Thumbprint -eq $SignerThumbprint -and $_.HasPrivateKey } | Select-Object -First 1
    if ($candidate) { $cert=$candidate; $machine=$store -like '*LocalMachine*'; break }
}
if (-not $cert) { throw 'The lab signing certificate/private key is not available in the certificate store. Import the existing lab certificate using your established procedure; do not create a new signer.' }
if (-not $SignToolPath) {
    $kit=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\*\x64\signtool.exe'
    $SignToolPath=(Get-ChildItem -Path $kit -File | Sort-Object FullName -Descending | Select-Object -First 1).FullName
}
if (-not $SignToolPath) { throw 'Windows SDK signtool.exe is required.' }
$version=& (Join-Path $source 'Telemetry.exe') --version
if ($LASTEXITCODE -ne 0 -or $version -notmatch 'decoder_version=2') { throw 'Rebuild capture v2 before deployment.' }
$names=@('Telemetry.exe','PPLRunner.exe')
foreach ($name in $names) {
    $file=Join-Path $source $name
    $signArgs=@('sign','/fd','SHA256','/ph','/sha1',$SignerThumbprint,'/s','My')
    if ($machine) { $signArgs+='/sm' }
    $signArgs+=$file
    & $SignToolPath @signArgs
    if ($LASTEXITCODE -ne 0) { throw "Signing failed: $file" }
    $signature=Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $SignerThumbprint) { throw "Signature verification failed: $file" }
}
$backup=Join-Path (Split-Path $BinDirectory) ('backups\capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
foreach ($name in $names) {
    Copy-Item -LiteralPath (Join-Path $BinDirectory $name) -Destination (Join-Path $backup $name)
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $BinDirectory $name) -Force
    if ((Get-FileHash -LiteralPath (Join-Path $source $name)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $BinDirectory $name)).Hash) { throw "Staged hash mismatch: $name" }
}
Write-Host "Signed and staged capture v2. Previous binaries: $backup"
Write-Host 'Run Bootstrap-ETWTI.ps1 and a pilot before starting a final campaign.'
