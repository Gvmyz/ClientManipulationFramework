# Build-ExternalCheats.ps1
# ------------------------
# Builds each external cheat / injector under External_Cheats/ WITHOUT
# modifying the cloned upstream trees. Every per-project quirk (missing
# include path, unset language standard, wrong platform label) is handled
# with MSBuild arguments and the CL (prepend) / _CL_ (append) environment
# variables. Overrides that must win over project options use _CL_.
#
# Reviewer-facing contract: `git clone <upstream>` then run this script
# builds without source/project edits in the cloned tree. Byte-for-byte
# reproducibility also requires pinned inputs and a deterministic toolchain.
#
# ASCII-only (PowerShell 5.1 mis-parses em-dashes without UTF-8 BOM).

param(
    [string] $Only = "",   # optional substring filter on project name
    [string] $Toolset = "", # optional override, e.g. v143 for VS 2022
    [switch] $Rebuild       # discard stale objects/PCH after changing flags
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
#   Solution       - path to .sln or .vcxproj, relative to External_Cheats\
#   Config         - MSBuild /p:Configuration value
#   Platform       - MSBuild /p:Platform value (label as declared in .sln;
#                    verify with `Select-String "SolutionConfigurationPlatforms"
#                    -Context 0,6` before adding a new project)
#   Toolset        - MSBuild /p:PlatformToolset value
#   CLPrepend      - arguments prepended to every CL invocation for this
#                    project. Use `/I "path"` (absolute), `/std:c++17`,
#                    `/FI"header"` (force include), or `/Zc:foo-` (relax
#                    conformance). Empty string = no overrides.
#   CLAppend       - arguments appended via _CL_ AFTER project options.
#                    Use for PCH and conformance overrides that must win.
#   ExtraMSBuild   - additional /p:Key=Value MSBuild properties for this
#                    project, as an array of strings. Empty array = none.
#                    These do not override literal ClCompile item metadata
#                    such as <PrecompiledHeader>Use</PrecompiledHeader>.
$projects = @(
    @{
        Name         = "AC / AssaultCubeExternalBobBuilder"
        Solution     = "AC\AssaultCubeExternalBobBuilder\AssaultCubeAimbot.sln"
        Config       = "Release"
        Platform     = "x86"
        Toolset      = "v145"
        CLPrepend    = '/I "$(ProjectDirAbs)\imgui" /I "$(ProjectDirAbs)\imgui\backends" /std:c++17'
        CLAppend     = ''
        ExtraMSBuild = @()
        ProjectDir   = "AC\AssaultCubeExternalBobBuilder"
    },
    @{
        # matseee AssaultHook. Build the DLL and injector separately so
        # their different character-set requirements can be preserved.
        #
        # PCH quirk: the vcxproj sets PrecompiledHeader=Use with pch.h, but
        # the source .cpp files (acFunctions.cpp, dllmain.cpp, aimbot.cpp,
        # ...) do not #include "pch.h", so every non-pch.cpp file fails
        # with C1010. /p:PrecompiledHeader does not override ClCompile item
        # metadata. /Y- tells the compiler to ignore PCH options entirely.
        # Match the upstream Debug|Win32 language standard in Release.
        Name         = "AC / AssaultHook (DLL)"
        Solution     = "AC\AssaultHook\src\AssaultHook.vcxproj"
        Config       = "Release"
        Platform     = "Win32"
        Toolset      = "v145"
        CLPrepend    = ''
        CLAppend     = '/Y- /std:c++20'
        ExtraMSBuild = @()
        ProjectDir   = "AC\AssaultHook\src"
    },
    @{
        # The bundled injector uses narrow process names and _stricmp, so
        # use MultiByte (as in its Debug|Win32 configuration), not Unicode.
        # This override must not apply to the DLL, which uses wide names.
        Name         = "AC / AssaultHook (injector)"
        Solution     = "AC\AssaultHook\src\injector.vcxproj"
        Config       = "Release"
        Platform     = "Win32"
        Toolset      = "v145"
        CLPrepend    = ''
        CLAppend     = '/Y- /std:c++20'
        ExtraMSBuild = @('/p:CharacterSet=MultiByte')
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
        #   * /std:c++latest implies /permissive- on recent MSVC, enabling
        #     strict string literal checks and stricter template parsing.
        #     Append /permissive and then /Zc:strictStrings- so the project
        #     cannot re-enable these checks after our compatibility flags.
        # These retain legacy compiler behavior without editing the sources.
        Name         = "Injectors / Xenos (x86)"
        Solution     = "Injectors\Xenos\Xenos.sln"
        Config       = "Release"
        Platform     = "Win32"
        Toolset      = "v145"
        CLPrepend    = '/FI"memory" /FI"iterator"'
        CLAppend     = '/permissive /Zc:strictStrings-'
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
    $clAppend = $p.CLAppend.Replace('$(ProjectDirAbs)', $projectDirAbs)

    # Snapshot both compiler environments; restore even when the build fails.
    $prevCL = $env:CL
    $prevCLAppend = $env:_CL_
    try {
        if ([string]::IsNullOrWhiteSpace($clPrepend)) {
            Remove-Item Env:CL -ErrorAction SilentlyContinue
        } else {
            $env:CL = $clPrepend
        }
        if ([string]::IsNullOrWhiteSpace($clAppend)) {
            Remove-Item Env:_CL_ -ErrorAction SilentlyContinue
        } else {
            $env:_CL_ = $clAppend
        }
        Write-Host "CL prepend: $clPrepend" -ForegroundColor DarkGray
        Write-Host "_CL_ append: $clAppend" -ForegroundColor DarkGray

        # Base MSBuild arguments plus any per-project extras. Splat via an
        # array so PowerShell keeps the /p:Key=Value tokens as one argument
        # each (Start-Process-style call operator).
        $effectiveToolset = $p.Toolset
        if ($Toolset) { $effectiveToolset = $Toolset }
        $msbuildArgs = @(
            $sln,
            "/p:Configuration=$($p.Config)",
            "/p:Platform=$($p.Platform)",
            "/p:PlatformToolset=$effectiveToolset"
        )
        if ($Rebuild) { $msbuildArgs += "/t:Rebuild" }
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
        if ($null -eq $prevCLAppend) {
            Remove-Item Env:_CL_ -ErrorAction SilentlyContinue
        } else {
            $env:_CL_ = $prevCLAppend
        }
    }
}

Write-Host ""
Write-Host "Done. For each produced binary, record its SHA-256:" -ForegroundColor Cyan
Write-Host "  Get-FileHash EXE_PATH -Algorithm SHA256" -ForegroundColor Cyan
Write-Host "and paste into docs/external-cheats/README.md." -ForegroundColor Cyan
