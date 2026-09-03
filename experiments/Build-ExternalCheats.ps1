# Build-ExternalCheats.ps1
# ------------------------
# Builds each external cheat / injector under External_Cheats/ WITHOUT
# modifying the cloned upstream trees. Every per-project quirk (missing
# include path, unset language standard, wrong platform label) is fixed
# by prepending arguments to CL via the CL environment variable, which
# MSVC inherits per-invocation.
#
# Reviewer-facing contract: `git clone <upstream>` then run this script
# reproduces the build byte-for-byte, and no diff exists between the
# cloned tree and a fresh clone from GitHub.
#
# ASCII-only (PowerShell 5.1 mis-parses em-dashes without UTF-8 BOM).

param(
    [string] $Only = ""    # optional substring filter on project name
)

$ErrorActionPreference = "Stop"

$msbuildCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
)
$msbuild = $null
foreach ($c in $msbuildCandidates) { if (Test-Path $c) { $msbuild = $c; break } }
if (-not $msbuild) { throw "MSBuild.exe not found in known VS install paths." }

$root = Join-Path $PSScriptRoot ".."
$ext  = Join-Path $root "External_Cheats"

# One entry per external project. Fields:
#   Name        - reporting label
#   Solution    - path to .sln, relative to External_Cheats\
#   Config      - MSBuild /p:Configuration value
#   Platform    - MSBuild /p:Platform value (label as declared in .sln)
#   Toolset     - MSBuild /p:PlatformToolset value
#   CLPrepend   - arguments prepended to every CL invocation for this
#                 project. Use `/I "path"` (absolute) and `/std:c++17`
#                 style flags. Empty string = no overrides.
$projects = @(
    @{
        Name      = "AC / AssaultCubeExternalBobBuilder"
        Solution  = "AC\AssaultCubeExternalBobBuilder\AssaultCubeAimbot.sln"
        Config    = "Release"
        Platform  = "x86"
        Toolset   = "v145"
        CLPrepend = '/I "$(ProjectDirAbs)\imgui" /I "$(ProjectDirAbs)\imgui\backends" /std:c++17'
        ProjectDir = "AC\AssaultCubeExternalBobBuilder"
    }
    # AssaultHook, Xenos, ExtremeInjector entries added after we know
    # their build quirks.
)

foreach ($p in $projects) {
    if ($Only -and ($p.Name -notlike "*$Only*")) { continue }

    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "Building: $($p.Name)" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan

    $sln = Join-Path $ext $p.Solution
    if (-not (Test-Path $sln)) {
        Write-Host "[!] Solution not found: $sln" -ForegroundColor Yellow
        Write-Host "    Skipping. Run Fetch-ExternalCheats.ps1 first, or add manually." -ForegroundColor Yellow
        continue
    }

    # Compute the absolute ProjectDir so /I paths in CL are unambiguous.
    $projectDirAbs = (Resolve-Path (Join-Path $ext $p.ProjectDir)).Path
    $clPrepend = $p.CLPrepend.Replace('$(ProjectDirAbs)', $projectDirAbs)

    # Snapshot and set CL for the duration of this build only.
    $prevCL = $env:CL
    if ([string]::IsNullOrWhiteSpace($clPrepend)) {
        Remove-Item Env:CL -ErrorAction SilentlyContinue
    } else {
        $env:CL = $clPrepend
    }
    Write-Host "CL prepend: $clPrepend" -ForegroundColor DarkGray

    try {
        & $msbuild $sln `
            /p:Configuration=$($p.Config) `
            /p:Platform=$($p.Platform) `
            /p:PlatformToolset=$($p.Toolset) `
            /nologo /v:minimal
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Build FAILED for $($p.Name) (exit $LASTEXITCODE)" -ForegroundColor Red
        } else {
            Write-Host "[+] Build OK for $($p.Name)" -ForegroundColor Green
        }
    } finally {
        if ($null -eq $prevCL) {
            Remove-Item Env:CL -ErrorAction SilentlyContinue
        } else {
            $env:CL = $prevCL
        }
    }
}

Write-Host ""
Write-Host "Done. For each produced binary, record its SHA-256:" -ForegroundColor Cyan
Write-Host "  Get-FileHash EXE_PATH -Algorithm SHA256" -ForegroundColor Cyan
Write-Host "and paste into docs/external-cheats/README.md." -ForegroundColor Cyan
