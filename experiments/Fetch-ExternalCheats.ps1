# Fetch-ExternalCheats.ps1
# ------------------------
# Reproduces the External_Cheats/ tree from the upstream URLs recorded in
# docs/external-cheats/README.md. This script is intentionally read-only
# against the network: it clones, and reports which entries still need a
# pinned commit hash. Fill the Commit fields after the first successful
# clone, then commit this file, and from then on the script reproduces
# the exact same source tree.
#
# Run inside the lab VM (or on a host with the External_Cheats path added
# to Windows Defender's exclusion list). Never on a machine that will
# ship code elsewhere.
#
# ASCII-only. PowerShell 5.1 mis-parses em-dashes in files that are not
# UTF-8-with-BOM, so keep this file plain ASCII.

$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."
$dst  = Join-Path $root "External_Cheats"

if (-not (Test-Path $dst)) {
    New-Item -ItemType Directory -Path $dst | Out-Null
}

$sources = @(
    @{
        Name   = "AC/AssaultHook"
        Url    = "https://github.com/matseee/AssaultHook.git"
        Commit = ""
    },
    @{
        Name   = "AC/AssaultCubeExternalBobBuilder"
        Url    = "https://github.com/bobbuilder123/AssaultCubeExternalBobBuilder"
        Commit = ""
    },
    @{
        Name   = "Injectors/ExtremeInjector"
        Url    = "https://github.com/master131/ExtremeInjector.git"
        Commit = ""
    },
    @{
        Name   = "Injectors/Xenos"
        Url    = "https://github.com/DarthTon/Xenos.git"
        Commit = ""
    }
)

foreach ($s in $sources) {
    $out = Join-Path $dst $s.Name
    if (Test-Path $out) {
        Write-Host "[=] $($s.Name) already present, skipping." -ForegroundColor DarkGray
        continue
    }
    if ([string]::IsNullOrWhiteSpace($s.Url)) {
        Write-Host "[!] $($s.Name) has no upstream URL recorded; add it to this script." -ForegroundColor Yellow
        continue
    }
    Write-Host "[+] Cloning $($s.Name) from $($s.Url)" -ForegroundColor Green
    git clone $s.Url $out
    if (-not [string]::IsNullOrWhiteSpace($s.Commit)) {
        Push-Location $out
        try {
            git checkout $s.Commit
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "    [!] No pinned commit; using default branch HEAD. Record the commit hash after building." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done. Record every SHA-256 in docs/external-cheats/README.md." -ForegroundColor Cyan
Write-Host "For each built binary before running:" -ForegroundColor Cyan
Write-Host "  Get-FileHash EXE_PATH -Algorithm SHA256" -ForegroundColor Cyan
Write-Host "  then paste into README.md, then look up on VirusTotal." -ForegroundColor Cyan
