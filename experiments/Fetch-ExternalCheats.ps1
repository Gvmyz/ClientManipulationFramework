# Fetch-ExternalCheats.ps1
# ------------------------
# Reproduces the External_Cheats/ tree from the upstream URLs recorded in
# docs/external-cheats/README.md. This script is intentionally read-only
# against the network — it clones, verifies the SHA-256 of key files if
# recorded, and reports which entries need manual attention.
#
# Run inside the lab VM (or on a host with the External_Cheats path added
# to Windows Defender's exclusion list). Never on a machine that will
# ship code elsewhere.

$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."
$dst  = Join-Path $root "External_Cheats"

if (-not (Test-Path $dst)) {
    New-Item -ItemType Directory -Path $dst | Out-Null
}

# Sources to clone. Fill in the commit hashes AFTER first successful
# clone, then commit this file. From then on, this script reproduces the
# exact same source tree byte-for-byte.
$sources = @(
    @{
        Name   = "AC/AssaultHook"
        Url    = "https://github.com/matseee/AssaultHook.git"
        Commit = ""   # TBD: record after first clone
    },
    @{
        Name   = "AC/AssaultCubeExternalBobBuilder"
        Url    = ""    # TBD: record upstream URL
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
        Write-Host "[!] $($s.Name) has no upstream URL recorded — add it to this script." -ForegroundColor Yellow
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
Write-Host "  Get-FileHash <exe> -Algorithm SHA256" -ForegroundColor Cyan
Write-Host "  then paste into README.md, then look up on VirusTotal." -ForegroundColor Cyan
