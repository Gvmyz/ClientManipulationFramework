# Shared, pinned inputs for Fetch-ExternalCheats.ps1 and Build-ExternalCheats.ps1.
# Paths are relative to External_Cheats unless an $(ExperimentsDir) token is used.
@{
    Sources = @(
        @{
            Name = 'AC/AssaultCubeExternalBobBuilder'
            Url = 'https://github.com/bobbuilder123/AssaultCubeExternalBobBuilder.git'
            Commit = 'e7a872f291e429e077c837c3e189b3d6cae06f70'
            Kind = 'Git'; Legacy = $false
            Builds = @(@{
                System = 'MSBuild'; Project = 'AssaultCubeAimbot.sln'
                Config = 'Release'; Platform = 'x86'
                CLPrepend = '/I "$(SourceDir)\imgui" /I "$(SourceDir)\imgui\backends"'
                CLAppend = '/std:c++17'
                Properties = @()
                Artifacts = @('Release/AssaultCubeAimbot.exe')
            })
        },
        @{
            Name = 'AC/PatheticAssaultCube'
            Url = 'https://github.com/pathetic/assaultcube-internal.git'
            Commit = 'dbffa11052a66cb78b6e2a14f5308c4c536a140a'
            Kind = 'Git'; Legacy = $false
            Builds = @(@{
                System = 'MSBuild'; Project = 'AssaultCube-Internal.sln'
                Config = 'Release'; Platform = 'x86'
                CLPrepend = ''; CLAppend = ''
                # Release is misconfigured upstream as an EXE. Mirror its
                # working Debug DLL settings using external build overrides.
                Properties = @('/p:ConfigurationType=DynamicLibrary', '/p:CharacterSet=MultiByte', '/p:ForceImportAfterCppTargets=$(ExperimentsDir)\build-compat\PatheticAssaultCube.targets')
                Artifacts = @('Release/AssaultCube-Internal.dll')
            })
        },
        @{
            Name = 'AC/AcTrainer'
            Url = 'https://github.com/lgeniaux/AcTrainer.git'
            Commit = '5716c9f7f5d49990f3342640751f5c8612d0d2df'
            Kind = 'Git'; Legacy = $false
            Builds = @(@{
                System = 'DotNet'; Project = 'AcTrainer/AcTrainer.csproj'
                Config = 'Release'; Runtime = 'win-x86'
                Artifacts = @('AcTrainer/bin/Release/net8.0-windows/win-x86/AcTrainer.exe', 'AcTrainer/bin/Release/net8.0-windows/win-x86/AcTrainer.dll')
            })
        },
        @{
            Name = 'AC/CheatEngineTable'
            Url = 'https://github.com/mbn-code/the-kernel-driver-guide-external'
            Commit = 'c94cbaaa4f4089dfe13e740d20af3aaaa4930c07'
            Kind = 'File'; Legacy = $false
            # Download ONLY this table, not the repository's driver projects.
            File = 'assaultcube.CT'
            DownloadUrl = 'https://raw.githubusercontent.com/mbn-code/the-kernel-driver-guide-external/c94cbaaa4f4089dfe13e740d20af3aaaa4930c07/assaultcube.CT'
            Sha256 = '10693EB92B147E9540754F0BEB2EBCCD17ACF4EB5F7EDFE4CD91C42E04329A08'
            Builds = @(@{ System = 'Table'; Artifacts = @('assaultcube.CT') })
        },
        @{
            Name = 'Injectors/Xenos'
            Url = 'https://github.com/DarthTon/Xenos.git'
            Commit = '4bd7399bf200f9e91f411402a3c3ac7fa4623c7e'
            Kind = 'Git'; Legacy = $false
            Builds = @(@{
                System = 'MSBuild'; Project = 'Xenos.sln'
                Config = 'Release'; Platform = 'Win32'
                CLPrepend = '/FI"$(ExperimentsDir)\build-compat\XenosIncludes.h"'
                CLAppend = '/permissive /Zc:strictStrings-'
                Properties = @()
                Artifacts = @('build/Win32/Release/Xenos.exe')
            }, @{
                System = 'MSBuild'; Project = 'Xenos.sln'
                Config = 'Release'; Platform = 'x64'
                CLPrepend = '/FI"$(ExperimentsDir)\build-compat\XenosIncludes.h"'
                CLAppend = '/permissive /Zc:strictStrings- /D_CRT_SECURE_NO_WARNINGS'
                Properties = @()
                Artifacts = @('build/x64/Release/Xenos64.exe')
            })
        },
        @{
            Name = 'AC/AssaultHook'
            Url = 'https://github.com/matseee/AssaultHook.git'
            Commit = '77762240d49fd32763c514e18f2d6546dc399f20'
            Kind = 'Git'; Legacy = $true
            # Buildable, but runtime failure reported by the operator.
            Builds = @(
                @{
                    System = 'MSBuild'; Project = 'src/AssaultHook.vcxproj'
                    Config = 'Release'; Platform = 'Win32'
                    CLPrepend = ''; CLAppend = '/Y- /std:c++20'
                    Properties = @(); Artifacts = @('src/Release/AssaultHook.dll')
                },
                @{
                    System = 'MSBuild'; Project = 'src/injector.vcxproj'
                    Config = 'Release'; Platform = 'Win32'
                    CLPrepend = ''; CLAppend = '/Y- /std:c++20'
                    Properties = @('/p:CharacterSet=MultiByte')
                    Artifacts = @('src/Release/Injector.exe')
                }
            )
        },
        @{
            Name = 'Injectors/ExtremeInjector'
            Url = 'https://github.com/master131/ExtremeInjector.git'
            Commit = '05087bb7c592e319f6ff0e6850fb1e1dc100ae6e'
            Kind = 'Git'; Legacy = $false
            # This repository contains support files, NOT injector source.
            ReleaseUrl = 'https://github.com/master131/ExtremeInjector/releases/download/v3.7.3/Extreme.Injector.v3.7.3.-.by.master131.rar'
            Version = '3.7.3'
            Builds = @(@{
                System = 'Prebuilt'; Provenance = 'release/provenance.json'
                Artifacts = @('release/Extreme Injector v3.exe')
            })
        }
    )
}
