# Bootstrap the ETW-TI capture chain for the current boot session.
#
# Test-signing mode does not persist the ELAM certificate registration across
# reboots, so InstallELAMCertificateInfo must be called every boot before any
# PPL-Antimalware launch will succeed. This script is idempotent — calling it
# repeatedly in the same boot is harmless.
#
# It also verifies that the signed binaries and the PPLRunner service are in
# place, and fails loudly if anything is missing so downstream runs don't
# silently produce empty captures.

[CmdletBinding()]
param(
    [string]$ElamSys      = 'C:\elam\src\ElamLab\x64\Release\ElamLab.sys',
    [string]$TelemetryBin = 'C:\elam\bin\Telemetry.exe',
    [string]$PPLRunnerBin = 'C:\elam\bin\PPLRunner.exe',
    [string]$WorkDir      = 'C:\elam'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Path {
    param([string]$Path, [string]$What)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$What not found at $Path"
    }
}

Write-Host '=== ETW-TI bootstrap ===' -ForegroundColor Cyan

# 1. Verify required files
Assert-Path $ElamSys      'ELAM driver'
Assert-Path $TelemetryBin 'Signed Telemetry.exe'
Assert-Path $PPLRunnerBin 'Signed PPLRunner.exe'
if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir | Out-Null
}

# 2. Verify signatures — the whole PPL chain fails silently if any of these
#    is not signed by ElamLabSigner. Cheap to check up-front.
foreach ($bin in @($TelemetryBin, $PPLRunnerBin)) {
    $sig = Get-AuthenticodeSignature -LiteralPath $bin
    if ($sig.Status -ne 'Valid') {
        throw "$bin has invalid signature: $($sig.Status) / $($sig.StatusMessage)"
    }
    Write-Host ("  signature OK: {0} <- {1}" -f $bin, $sig.SignerCertificate.Subject)
}

# 3. Verify the PPLRunner service exists and is configured for PPL launch
$svc = Get-Service -Name 'PPLRunner' -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host '  PPLRunner service missing — installing now' -ForegroundColor Yellow
    & $PPLRunnerBin --install
    if ($LASTEXITCODE -ne 0) {
        throw "PPLRunner --install failed (exit $LASTEXITCODE)"
    }
} else {
    Write-Host ("  PPLRunner service present (status: {0})" -f $svc.Status)
}

# Check the PROTECTED bit is set on the service config.
$protection = (& sc.exe qprotection PPLRunner) -join ' '
if ($protection -notmatch 'ANTIMALWARE[ _]LIGHT') {
    Write-Host "  sc qprotection: $protection" -ForegroundColor Yellow
    throw 'PPLRunner is not configured for ANTIMALWARE_LIGHT protection. Re-run PPLRunner.exe --install as admin.'
}
Write-Host '  PPLRunner protection: ANTIMALWARE_LIGHT'

# 4. Install the ELAM certificate info (per-boot in test-signing mode).
#    Idempotent: re-registering the same TBS hash is a no-op.
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ElamBootstrap {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool InstallELAMCertificateInfo(IntPtr ELAMFile);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
}
'@ -ErrorAction SilentlyContinue

$INVALID = [IntPtr]::new(-1)
$h = [ElamBootstrap]::CreateFileW($ElamSys, 1, 1, [IntPtr]::Zero, 3, 0x80, [IntPtr]::Zero)
if ($h -eq $INVALID) {
    throw ("CreateFile on ELAM driver failed: " +
           [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)
}
$ok  = [ElamBootstrap]::InstallELAMCertificateInfo($h)
$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
[ElamBootstrap]::CloseHandle($h) | Out-Null

if (-not $ok) {
    throw ("InstallELAMCertificateInfo failed ({0}): {1}" -f $err,
           [ComponentModel.Win32Exception]::new($err).Message)
}
Write-Host '  ELAM certificate info registered' -ForegroundColor Green

Write-Host ''
Write-Host 'Bootstrap complete - ready for ETW-TI captures.' -ForegroundColor Green
