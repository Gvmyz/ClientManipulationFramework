# Build pinned external sources WITHOUT editing upstream source/project files.
# Compiler compatibility files live under experiments/build-compat only.
# PowerShell 5.1 / ASCII. .CT files are verified inputs, not compiled programs.
[CmdletBinding()]
param(
    [string] $Only = '',
    [string] $Toolset = 'v145', # use v143 on VS 2022
    [switch] $Rebuild,
    [switch] $IncludeLegacy,
    [switch] $SkipPrebuilt
)

$ErrorActionPreference = 'Stop'
$catalog = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'ExternalCheats.psd1')
$ext = Join-Path (Split-Path $PSScriptRoot -Parent) 'External_Cheats'
$sources = @($catalog.Sources | Where-Object {
    if ($Only) { $_.Name -like "*$Only*" } else { -not $_.Legacy -or $IncludeLegacy }
})
if (-not $sources.Count) { throw "No external source matches '$Only'." }

function Find-MSBuild {
    $command = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $found = @(& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe')
        if ($found.Count) { return $found[0] }
    }
    throw 'MSBuild not found. Install the Visual Studio C++ build tools.'
}

function Assert-PinnedSource($Source, [string] $Directory) {
    if ($Source.Kind -eq 'File') {
        $file = Join-Path $Directory $Source.File
        if (-not (Test-Path -LiteralPath $file)) { throw "Missing table: $file. Run Fetch-ExternalCheats.ps1." }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $Source.Sha256) { throw "Table hash mismatch: $file" }
        return
    }
    $head = & git -C $Directory rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $Source.Commit) { throw "Source is not at the pinned commit: $Directory. Run Fetch-ExternalCheats.ps1." }
    & git -C $Directory diff --quiet HEAD --ignore-submodules=all
    if ($LASTEXITCODE -ne 0) { throw "Tracked source/project changes detected: $Directory" }
    if (Test-Path -LiteralPath (Join-Path $Directory '.gitmodules')) {
        $submodules = @(& git -C $Directory submodule status --recursive)
        if ($LASTEXITCODE -ne 0 -or @($submodules | Where-Object { $_ -match '^[-+U]' }).Count) {
            throw "Missing or mismatched submodule in $Directory. Run Fetch-ExternalCheats.ps1 -Only '$($Source.Name)'."
        }
        & git -C $Directory submodule foreach --recursive 'git diff --quiet HEAD'
        if ($LASTEXITCODE -ne 0) { throw "Tracked submodule changes detected: $Directory" }
    }
}

function Expand-BuildToken([string] $Value, [string] $SourceDir) {
    $Value.Replace('$(SourceDir)', $SourceDir).Replace('$(ExperimentsDir)', $PSScriptRoot)
}

$reportDir = Join-Path $ext ('_build-reports\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$results = @()
foreach ($source in $sources) {
    $sourceDir = Join-Path $ext $source.Name
    if (-not $source.Builds.Count) {
        Write-Warning "$($source.Name) is archived with no supported build recipe."
        continue
    }
    foreach ($build in $source.Builds) {
        if ($SkipPrebuilt -and $build.System -eq 'Prebuilt') {
            Write-Warning "Explicitly skipping prebuilt validation: $($source.Name)"
            continue
        }
        $record = [ordered]@{
            source = $source.Name; commit = $source.Commit; system = $build.System
            configuration = $build.Config; platform = $build.Platform; runtime = $build.Runtime
            version = $source.Version; toolset = $null; compiler = $null
            status = 'failed'; error = $null; artifacts = @()
        }
        $prevCL = $env:CL
        $prevCLAppend = $env:_CL_
        try {
            Assert-PinnedSource $source $sourceDir
            Write-Host ""
            Write-Host "Building: $($source.Name) / $($build.Project)" -ForegroundColor Cyan
            Remove-Item Env:CL, Env:_CL_ -ErrorAction SilentlyContinue
            if ($build.System -eq 'Prebuilt') {
                $provenancePath = Join-Path $sourceDir $build.Provenance
                $binary = Join-Path $sourceDir $build.Artifacts[0]
                if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Place the extracted Extreme Injector v3.exe at: $binary. No compilation or manual JSON editing is required." }
                $binaryHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
                $provenance = if (Test-Path -LiteralPath $provenancePath) { Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
                if (-not $provenance.sha256) {
                    $provenance | Add-Member -NotePropertyName sha256 -NotePropertyValue $binaryHash -Force
                    $provenance | Add-Member -NotePropertyName source_url -NotePropertyValue $source.ReleaseUrl -Force
                    $provenance | Add-Member -NotePropertyName tool_version -NotePropertyValue $source.Version -Force
                    $provenance | Add-Member -NotePropertyName recorded_at -NotePropertyValue (Get-Date).ToString('o') -Force
                    $provenance | Add-Member -NotePropertyName verification -NotePropertyValue 'Local EXE hash recorded automatically; origin, download date and scan outcome are not inferred.' -Force
                    $provenance | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $provenancePath -Encoding UTF8
                    Write-Host "Recorded initial binary hash automatically: $provenancePath"
                }
                if ($provenance.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or $binaryHash -ne $provenance.sha256) {
                    throw 'Prebuilt executable differs from the locally recorded, frozen provenance hash.'
                }
                Write-Host 'Prebuilt release matches operator-recorded provenance. This is not source compilation or publisher authentication.'
            } elseif ($build.System -eq 'Table') {
                [xml]$table = Get-Content -LiteralPath (Join-Path $sourceDir $source.File) -Raw
                if (-not $table.CheatTable -or $table.SelectNodes('//LuaScript|//AssemblerScript').Count) {
                    throw 'Expected the audited, data-only Cheat Engine table.'
                }
                Write-Host 'Table verified. Open with your recorded Cheat Engine installation; no build required.'
            } elseif ($build.System -eq 'DotNet') {
                $dotnet = (Get-Command dotnet.exe -ErrorAction Stop).Source
                $record.compiler = $dotnet
                $record.toolset = (& $dotnet --version | Out-String).Trim()
                $buildArgs = @('build', (Join-Path $sourceDir $build.Project), '-c', $build.Config, '-r', $build.Runtime, '--self-contained', 'false', '--nologo', '-v', 'minimal')
                if ($Rebuild) { $buildArgs += '-t:Rebuild' }
                & $dotnet @buildArgs
                if ($LASTEXITCODE -ne 0) { throw "dotnet build failed (exit $LASTEXITCODE). Requires .NET SDK with Windows desktop targeting support." }
            } else {
                $msbuild = Find-MSBuild
                $record.compiler = $msbuild
                $record.toolset = $Toolset
                $env:CL = Expand-BuildToken $build.CLPrepend $sourceDir
                $env:_CL_ = Expand-BuildToken $build.CLAppend $sourceDir
                Write-Host "CL prepend: $env:CL"
                Write-Host "_CL_ append: $env:_CL_"
                $buildArgs = @((Join-Path $sourceDir $build.Project), "/p:Configuration=$($build.Config)", "/p:Platform=$($build.Platform)", "/p:PlatformToolset=$Toolset", '/nologo', '/v:minimal')
                foreach ($property in $build.Properties) { $buildArgs += Expand-BuildToken $property $sourceDir }
                if ($Rebuild) { $buildArgs += '/t:Rebuild' }
                $log = Join-Path $reportDir (($source.Name -replace '/', '-') + '-' + [IO.Path]::GetFileNameWithoutExtension($build.Project) + '-' + $build.Platform + '.log')
                $buildArgs += @('/fl', "/flp:logfile=$log;verbosity=normal")
                & $msbuild @buildArgs
                if ($LASTEXITCODE -ne 0) { throw "MSBuild failed (exit $LASTEXITCODE). Log: $log" }
            }
            Assert-PinnedSource $source $sourceDir
            foreach ($artifact in $build.Artifacts) {
                $file = Join-Path $sourceDir $artifact
                if (-not (Test-Path -LiteralPath $file)) { throw "Expected output missing: $file" }
                $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
                $record.artifacts += [ordered]@{ path = $file; sha256 = $hash }
                Write-Host "SHA256 $hash  $file"
            }
            $record.status = 'ok'
        } catch {
            $record.error = $_.Exception.Message
            Write-Warning "$($source.Name): $($record.error)"
        } finally {
            if ($null -eq $prevCL) { Remove-Item Env:CL -ErrorAction SilentlyContinue } else { $env:CL = $prevCL }
            if ($null -eq $prevCLAppend) { Remove-Item Env:_CL_ -ErrorAction SilentlyContinue } else { $env:_CL_ = $prevCLAppend }
        }
        $results += [pscustomobject]$record
    }
}
$report = Join-Path $reportDir 'build-report.json'
ConvertTo-Json -InputObject @($results) -Depth 8 | Set-Content -LiteralPath $report -Encoding UTF8
Write-Host "Build report: $report" -ForegroundColor Cyan
if (@($results | Where-Object status -ne 'ok').Count) { throw 'One or more external builds failed. See the build report.' }
Write-Host 'All selected builds/table checks completed. Runtime pilots are still required.' -ForegroundColor Green
