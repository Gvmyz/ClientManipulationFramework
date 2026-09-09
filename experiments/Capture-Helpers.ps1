# Shared capture helpers. Dot-sourcing performs no capture or service operations.
function Get-CaptureArtifact {
    param([string]$Role, [string]$Path, [string]$RepoRoot)
    $record = [ordered]@{ role=$Role; path=$Path; sha256=$null; status='unresolved'; error=$null }
    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]$record }
    try {
        if (-not [IO.Path]::IsPathRooted($Path)) { $Path = Join-Path $RepoRoot $Path }
        $record.path = [IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -LiteralPath $record.path -PathType Leaf)) { $record.status='missing'; return [pscustomobject]$record }
        $record.sha256 = (Get-FileHash -LiteralPath $record.path -Algorithm SHA256).Hash
        $record.status = 'recorded'
    } catch { $record.status='unreadable'; $record.error=$_.Exception.Message }
    [pscustomobject]$record
}

function Get-CompactTelemetryMetadata {
    param($Extra)
    # Full metadata is kept in manifest.json. Legacy PPLRunner reads 2047 bytes.
    # Telemetry rejects empty --meta values. Do not send prose, paths or hashes.
    foreach ($key in @('target_bitness','attacker_bitness','phase','repetition')) {
        if (-not $Extra) { continue }
        $property = $Extra.PSObject.Properties[$key]
        if (-not $property) { continue }
        $value = [string]$property.Value
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value.Length -le 64) {
            '--meta'
            $key + '=' + $value
        }
    }
}

function Assert-PPLCommandLength {
    param([string]$CommandLine)
    $bytes = [Text.Encoding]::UTF8.GetByteCount($CommandLine)
    if ($bytes -gt 2047) { throw "runner.cfg would contain $bytes UTF-8 bytes; the installed legacy PPLRunner supports at most 2047. Shorten the session/run/path fields." }
}
