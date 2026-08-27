using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'ThreatIntelModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

$maxEntities = 20
$entities = $Request.Body.Entities
if (-not $entities -or $entities.Count -eq 0) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "No entities provided" }
    return
}
if ($entities.Count -gt $maxEntities) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Too many entities (max $maxEntities)" }
    return
}

$validators = @{
    'ip'       = { param($v) Confirm-StatIpAddress $v }
    'host'     = { param($v) Confirm-StatHostname   $v }
    'url'      = { param($v) Confirm-StatUrl        $v }
    'filehash' = { param($v) Confirm-StatFileHash   $v }
}

$results = foreach ($entity in $entities) {
    $validator = $validators[$entity.Type]
    if (-not $validator -or -not (& $validator $entity.Value)) { continue }

    $kqlTemplate = @"
ThreatIntelligenceIndicator
| where TimeGenerated > ago(90d)
| where NetworkIP == TargetValue or DomainName == TargetValue or Url == TargetValue or FileHashValue == TargetValue
| where Active == true
| project TimeGenerated, ThreatType, ConfidenceScore, Description, IndicatorId
| take 50
"@

    $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kqlTemplate -Parameters @{ TargetValue = $entity.Value }

    [pscustomobject]@{
        EntityType  = $entity.Type
        EntityValue = $entity.Value
        IsKnownIndicator = [bool]($r.Results.Count -gt 0)
        Matches     = $r.Results
    }
}

Write-StatLog -Message "Threat intelligence lookup completed" -Data @{ entityCount = $entities.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
