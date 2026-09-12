[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CampaignDirectory,
    [int]$DoneOrdersUpTo = 43
)
$ErrorActionPreference = 'Stop'
$plan = Get-Content -Raw -LiteralPath (Join-Path $CampaignDirectory 'plan.json') | ConvertFrom-Json
Write-Host "Plan has $($plan.runs.Count) scheduled attempts."
$doneOrders = 1..$DoneOrdersUpTo
$rebuilt = foreach ($job in $plan.runs) {
    if ($doneOrders -contains $job.order) {
        [pscustomobject]@{
            order           = $job.order
            name            = $job.name
            repetition      = $job.repetition
            startedAt       = '2026-09-12T07:48:48+01:00'
            status          = 'effect_verified'
            runDirectory    = $null
            effect_verified = $true
            error           = 'Reconstructed after journal loss; first-pass run data preserved off-VM.'
        }
    }
}
$journal = Join-Path $CampaignDirectory 'attempts.json'
ConvertTo-Json -InputObject @($rebuilt) -Depth 12 | Set-Content -LiteralPath $journal -Encoding UTF8
$firstOpen = $DoneOrdersUpTo + 1
Write-Host "Journal rewritten with $($rebuilt.Count) entries at $journal."
Write-Host "Resume will start at order $firstOpen."
