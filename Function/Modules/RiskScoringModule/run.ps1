using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'RiskScoringModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

# Each scoring factor: name -> weight. Deploy-time configuration, not caller-supplied,
# so a playbook can't inflate its own incident's score by sending arbitrary weights.
$factorWeights = @{
    AadRiskLevelHigh       = 30
    AadRiskLevelMedium     = 15
    ThreatIntelMatch       = 25
    UebaHighPriority       = 20
    WatchlistMatch         = -20   # negative: known-good/allow-listed entity lowers risk
    MdeHighExposure        = 15
    RelatedAlertsPresent   = 10
}

$factors = $Request.Body.Factors
if (-not $factors) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Missing 'Factors' object" }
    return
}

$score = 0
$appliedFactors = @()

foreach ($key in $factorWeights.Keys) {
    $raw = $factors.$key
    # Only accept a strict boolean for each factor - never trust a caller-supplied numeric score directly.
    if ($raw -is [bool] -and $raw -eq $true) {
        $score += $factorWeights[$key]
        $appliedFactors += $key
    }
    elseif ($null -ne $raw -and $raw -isnot [bool]) {
        Write-StatLog -Level Warning -Message "Ignored non-boolean risk factor value" -Data @{ factor = $key }
    }
}

# Clamp to a documented 0-100 band regardless of how factor weights sum.
$score = [Math]::Max(0, [Math]::Min(100, $score))

$band = switch ($score) {
    { $_ -ge 70 } { 'High'; break }
    { $_ -ge 35 } { 'Medium'; break }
    default       { 'Low' }
}

Write-StatLog -Message "Risk score computed" -Data @{ score = $score; band = $band; factors = $appliedFactors }
Send-Response ([HttpStatusCode]::OK) @{ score = $score; band = $band; appliedFactors = $appliedFactors }
