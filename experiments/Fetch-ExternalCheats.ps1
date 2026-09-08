# Fetch pinned sources without patching upstream files. PowerShell 5.1 / ASCII.
[CmdletBinding()]
param([string] $Only = '', [switch] $IncludeLegacy)

$ErrorActionPreference = 'Stop'
$catalog = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'ExternalCheats.psd1')
$dst = Join-Path (Split-Path $PSScriptRoot -Parent) 'External_Cheats'
$sources = @($catalog.Sources | Where-Object {
    if ($Only) { $_.Name -like "*$Only*" } else { -not $_.Legacy -or $IncludeLegacy }
})
if (-not $sources.Count) { throw "No external source matches '$Only'." }

function Invoke-Git([string[]] $GitArgs) {
    & git @GitArgs
    if ($LASTEXITCODE -ne 0) { throw "git failed ($LASTEXITCODE): $($GitArgs -join ' ')" }
}

New-Item -ItemType Directory -Path $dst -Force | Out-Null
foreach ($source in $sources) {
    $out = Join-Path $dst $source.Name
    Write-Host "[+] $($source.Name) @ $($source.Commit)" -ForegroundColor Cyan
    if ($source.Kind -eq 'File') {
        New-Item -ItemType Directory -Path $out -Force | Out-Null
        $file = Join-Path $out $source.File
        if (-not (Test-Path -LiteralPath $file)) {
            $pending = "$file.download"
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $source.DownloadUrl -OutFile $pending
                if ((Get-FileHash -LiteralPath $pending -Algorithm SHA256).Hash -ne $source.Sha256) {
                    throw "Downloaded file hash mismatch for $($source.Name)."
                }
                Move-Item -LiteralPath $pending -Destination $file
            } finally {
                if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending }
            }
        }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $source.Sha256) {
            throw "Existing table differs from the pinned file: $file. Preserve your copy before fetching again."
        }
        Write-Host '[=] Pinned table verified; no compiler needed.'
        continue
    }

    if (-not (Test-Path -LiteralPath $out)) {
        New-Item -ItemType Directory -Path (Split-Path $out -Parent) -Force | Out-Null
        Invoke-Git -GitArgs @('clone', '--no-checkout', $source.Url, $out)
    } else {
        if (-not (Test-Path -LiteralPath (Join-Path $out '.git'))) { throw "Not a Git checkout: $out" }
        $origin = (Invoke-Git -GitArgs @('-C', $out, 'remote', 'get-url', 'origin') | Out-String).Trim()
        $normalizedOrigin = $origin -replace '^git@github\.com:', 'https://github.com/'
        if (($normalizedOrigin -replace '\.git/?$', '').TrimEnd('/') -ne ($source.Url -replace '\.git/?$', '').TrimEnd('/')) {
            throw "Unexpected origin for $out : $origin"
        }
        $changes = @(Invoke-Git -GitArgs @('-C', $out, 'status', '--porcelain', '--untracked-files=no', '--ignore-submodules=all'))
        if ($changes.Count) { throw "Tracked changes in $out; refusing to overwrite them." }
    }

    & git -C $out cat-file -e "$($source.Commit)^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { Invoke-Git -GitArgs @('-C', $out, 'fetch', 'origin', $source.Commit) }
    Invoke-Git -GitArgs @('-C', $out, 'checkout', '--detach', $source.Commit)
    if (Test-Path -LiteralPath (Join-Path $out '.gitmodules')) {
        # Also repair missing submodules in an EXISTING checkout.
        Invoke-Git -GitArgs @('-C', $out, 'submodule', 'sync', '--recursive')
        Invoke-Git -GitArgs @('-C', $out, 'submodule', 'update', '--init', '--recursive')
    }
    $head = (Invoke-Git -GitArgs @('-C', $out, 'rev-parse', 'HEAD') | Out-String).Trim()
    if ($head -ne $source.Commit) { throw "Pinned commit verification failed: $out" }
    if ($source.ReleaseUrl) {
        Write-Warning "$($source.Name) provides a prebuilt release, not buildable source."
        Write-Host "Official release: $($source.ReleaseUrl)"
        Write-Host 'Stage the lab-verified EXE and provenance.json in its release directory; see docs/external-cheats/runbook.md.'
        Write-Host 'This script fetches its support repository only; it does not bypass binary security blocks.'
    }
}
Write-Host 'Fetch complete. Run Build-ExternalCheats.ps1 next; see docs/external-cheats/README.md.' -ForegroundColor Green
