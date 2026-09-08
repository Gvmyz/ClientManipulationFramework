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
#   Name           - reporting label
#   Solution       - path to .sln, relative to External_Cheats\
#   Config         - MSBuild /p:Configuration value
#   Platform       - MSBuild /p:Platform value (label as declared in .sln;
#                    verify with `Select-String "SolutionConfigurationPlatforms"
#                    -Context 0,6` before adding a new project)
#   Toolset        - MSBuild /p:PlatformToolset value
#   CLPrepend      - arguments prepended to every CL invocation for this
#                    project. Use `/I "path"` (absolute), `/std:c++17`,
#                    `/FI"header"` (force include), or `/Zc:foo-` (relax
#                    conformance). Empty string = no overrides.
#   ExtraMSBuild   - additional /p:Key=Value MSBuild properties for this
#                    project, as an array of strings. Empty array = none.
#                    Use for project-file-level overrides (PCH, forced
#                    includes) that CLPrepend can't reach because the
#                    project sets them later in the CL command line.
$projects = @(
    @{
        Name         = "AC / AssaultCubeExternalBobBuilder"
        Solution     = "AC\AssaultCubeExternalBobBuilder\AssaultCubeAimbot.sln"
        Config       = "Release"
        Platform     = "x86"
        Toolset      = "v145"
        CLPrepend    = '/I "$(ProjectDirAbs)\imgui" /I "$(ProjectDirAbs)\imgui\backends" /std:c++17'
        ExtraMSBuild = @()
        ProjectDir   = "AC\AssaultCubeExternalBobBuilder"
    },
    @{
        # matseee AssaultHook. Builds both the cheat DLL and the bundled
        # injector.exe from the same solution.
        #
        # PCH quirk: the vcxproj sets PrecompiledHeader=Use with pch.h, but
        # the source .cpp files (acFunctions.cpp, dllmain.cpp, aimbot.cpp,
        # ...) do not #include "pch.h", so every non-pch.cpp file fails
        # with C1010. Override at MSBuild time by disabling PCH entirely
        # (-p:PrecompiledHeader=NotUsing) and clearing any forced-include
        # of pch.h (-p:ForcedIncludeFiles=). Prevents having to touch the
        # cloned upstream tree.
        Name         = "AC / AssaultHook (DLL + injector)"
        Solution     = "AC\AssaultHook\src\AssaultHook.sln"
        Config       = "Release"
        Platform     = "x86"
        Toolset      = "v145"
        CLPrepend    = ''
        ExtraMSBuild = @(
            "/p:PrecompiledHeader=NotUsing",
            "/p:ForcedIncludeFiles="
        )
        ProjectDir   = "AC\AssaultHook\src"
    },
    @{
        # DarthTon Xenos, user-mode manual-mapping injector, x86 to match
        # AC's bitness. Vendors BlackBone as a submodule at ext/BlackBone/.
        # Fetch-ExternalCheats.ps1 initialises submodules; if you cloned by
        # hand, run: git submodule update --init --recursive
        #
        # Modern-MSVC conformance breaks BlackBone as vendored:
        #   * std::addressof, std::inserter no longer come in transitively
        #     from <stddef.h>; force-include <memory> and <iterator>.
        #   * /Zc:strictStrings (default on modern MSVC) rejects the
        #     const char[N] -> char* passes in the WoW64 shims; relax
        #     with /Zc:strictStrings-.
        #   * /permissive- (default on modern MSVC) enforces two-phase
        #     template lookup that BlackBone predates; /permissive relaxes
        #     it to the pre-VS2017 rules the code was written against.
        # None of these change the resulting binary's behaviour; they just
        # let the older code compile under the newer compiler defaults.
        Name         = "Injectors / Xenos (x86)"
        Solution     = "Injectors\Xenos\Xenos.sln"
        Config       = "Release"
        Platform     = "Win32"
        Toolset      = "v145"
        CLPrepend    = '/Zc:strictStrings- /permissive /FI"memory" /FI"iterator"'
        ExtraMSBuild = @()
        ProjectDir   = "Injectors\Xenos"
    }
    # ExtremeInjector deliberately omitted: its C++/CLI project targets old
    # .NET runtimes bundled as .zip files under VC/, and modern-toolset
    # retargeting is not worth the effort when Xenos covers the same role.
    # Bring back only if time permits before deadline.
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
        # Base MSBuild arguments plus any per-project extras. Splat via an
        # array so PowerShell keeps the /p:Key=Value tokens as one argument
        # each (Start-Process-style call operator).
        $msbuildArgs = @(
            $sln,
            "/p:Configuration=$($p.Config)",
            "/p:Platform=$($p.Platform)",
            "/p:PlatformToolset=$($p.Toolset)"
        )
        if ($p.ContainsKey("ExtraMSBuild") -and $p.ExtraMSBuild.Count -gt 0) {
            $msbuildArgs += $p.ExtraMSBuild
            Write-Host "Extra MSBuild args: $($p.ExtraMSBuild -join ' ')" -ForegroundColor DarkGray
        }
        $msbuildArgs += @("/nologo", "/v:minimal")

        & $msbuild @msbuildArgs
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
