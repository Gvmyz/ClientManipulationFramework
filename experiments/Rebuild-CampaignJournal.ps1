[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CampaignDirectory,
    [int]$DoneOrdersUpTo = 43
)
$ErrorActionPreference = 'Stop'
$plan = Get-Content -Raw -LiteralPath (Join-Path $CampaignDirectory 'plan.json') | ConvertFrom-Json
$total = [int]$plan.runs.Count
Write-Host ("Plan has {0} scheduled attempts; plan.runs type is {1}." -f $total, $plan.runs.GetType().FullName)
# Use ArrayList + explicit indexing so we never depend on pipeline enumeration
# quirks (which have been dropping objects into a single merged PSObject).
$rebuilt = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $total; $i++) {
    $j = $plan.runs[$i]
    $ord = [int]$j.order
    if ($ord -le $DoneOrdersUpTo) {
        [void]$rebuilt.Add([pscustomobject]@{
            order           = $ord
            name            = [string]$j.name
            repetition      = [int]$j.repetition
            startedAt       = '2026-09-12T07:48:48+01:00'
            status          = 'effect_verified'
            runDirectory    = $null
            effect_verified = $true
            error           = 'Reconstructed after journal loss; first-pass run data preserved off-VM.'
        })
    }
}
Write-Host ("Built {0} entries in ArrayList; first order = {1}, last order = {2}." -f $rebuilt.Count, $rebuilt[0].order, $rebuilt[$rebuilt.Count - 1].order)
# `ConvertTo-Json -InputObject <array>` on this PowerShell was merging N
# PSCustomObjects into ONE object with array-valued fields — the JSON came out
# as `{"order":[1,2,...],"name":[...]}` instead of `[{"order":1,...},...]`.
# Serialize each entry alone (which works reliably), then join into an array.
$parts = New-Object System.Collections.Generic.List[string]
foreach ($entry in $rebuilt) {
    [void]$parts.Add((ConvertTo-Json -InputObject $entry -Depth 6 -Compress))
}
$json = '[' + [string]::Join(',', $parts) + ']'
$journal = Join-Path $CampaignDirectory 'attempts.json'
Set-Content -LiteralPath $journal -Value $json -Encoding UTF8
$check = @(Get-Content -Raw -LiteralPath $journal | ConvertFrom-Json)
Write-Host ("Written and re-read: {0} entries; first={1}; last={2}." -f $check.Count, $check[0].order, $check[-1].order)
$firstOpen = $DoneOrdersUpTo + 1
if ($check.Count -ne $DoneOrdersUpTo) { throw "Rebuild produced $($check.Count) entries, expected $DoneOrdersUpTo. Do NOT resume until this is fixed." }
Write-Host "Journal rewritten with $($rebuilt.Count) entries at $journal."
Write-Host "Resume will start at order $firstOpen."
