using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'RelatedAlertsModule'
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

# Server-side clamp: caller may request a lookback window but it can never exceed 30 days,
# regardless of what value is supplied, to bound query fan-out cost.
$requestedDays = [int]($Request.Body.LookbackDays ?? 7)
$lookbackDays = [Math]::Min([Math]::Max($requestedDays, 1), 30)

$validators = @{
    'ip'       = { param($v) Confirm-StatIpAddress $v }
    'host'     = { param($v) Confirm-StatHostname   $v }
    'account'  = { param($v) Confirm-StatUpn        $v }
    'filehash' = { param($v) Confirm-StatFileHash   $v }
}

$results = foreach ($entity in $entities) {
    $validator = $validators[$entity.Type]
    if (-not $validator -or -not (& $validator $entity.Value)) {
        continue  # skip entity types this module doesn't handle or that fail validation, don't error the whole batch
    }

    $kqlTemplate = @"
SecurityAlert
| where TimeGenerated > ago(${lookbackDays}d)
| where Entities has TargetValue
| project TimeGenerated, AlertName, AlertSeverity, SystemAlertId
| take 100
"@

    $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kqlTemplate -Parameters @{ TargetValue = $entity.Value }

    [pscustomobject]@{
        EntityType   = $entity.Type
        EntityValue  = $entity.Value
        RelatedAlerts = $r.Results
    }
}

Write-StatLog -Message "Related alerts lookup completed" -Data @{ entityCount = $entities.Count; lookbackDays = $lookbackDays }
Send-Response ([HttpStatusCode]::OK) @{ lookbackDays = $lookbackDays; results = $results }
