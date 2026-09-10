[CmdletBinding()]
param([string]$MSBuildPath='', [string]$PlatformToolset='', [string]$OutputRoot='', [switch]$Rebuild)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if (-not $MSBuildPath) {
    $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $install=& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath
    if (-not $install) { throw 'Visual Studio with C++ build tools is required.' }
    $MSBuildPath=Join-Path $install 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not $PlatformToolset) {
        $version=& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationVersion
        $PlatformToolset=if ([version]$version -lt [version]'18.0') { 'v143' } else { 'v145' }
    }
}
if (-not $OutputRoot) { $OutputRoot=Join-Path $repo 'ProcessToolkit' }
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
$projects=@('TestTarget\TestTarget.vcxproj','TestDll\TestDll.vcxproj','ProcessToolkit\ProcessToolkit.vcxproj')
foreach ($platform in @('Win32','x64')) {
    $selected=@($projects)
    if ($platform -eq 'x64') { $selected+=@('Telemetry\Telemetry.vcxproj','PPLRunner\PPLRunner\PPLRunner.vcxproj') }
    foreach ($project in $selected) {
        $name=[IO.Path]::GetFileNameWithoutExtension($project)
        $out=(Join-Path $OutputRoot "$platform\Release") + '\'
        $intermediate=(Join-Path $repo "artifacts\capture-build\$platform\$name") + '\'
        $args=@((Join-Path $repo $project),'/m','/nologo','/v:minimal',"/p:Configuration=Release","/p:Platform=$platform",'/p:LanguageStandard=stdcpplatest',"/p:OutDir=$out","/p:IntDir=$intermediate",'/p:BuildProjectReferences=false')
        $args+=if($Rebuild){'/t:Rebuild'}else{'/t:Build'}
        if ($PlatformToolset) { $args+="/p:PlatformToolset=$PlatformToolset" }
        & $MSBuildPath @args
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $project ($platform), exit $LASTEXITCODE" }
    }
}
Write-Host 'Built capture v2, ProcessToolkit and both TestDll architectures. External cheat sources are untouched.'
Write-Host "Outputs: $OutputRoot\<platform>\Release"
Write-Host 'On the lab host: sign the rebuilt Telemetry.exe and PPLRunner.exe with the existing ELAM signer and stage them using the documented lab procedure before capturing.'
