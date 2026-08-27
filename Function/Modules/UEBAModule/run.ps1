using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'UEBAModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

$maxEntities = 20
$accountEntities = $Request.Body.Entities | Where-Object { $_.Type -eq 'account' }

if (-not $accountEntities -or $accountEntities.Count -eq 0) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "No 'account' entities provided" }
    return
}
if ($accountEntities.Count -gt $maxEntities) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Too many account entities (max $maxEntities)" }
    return
}
$invalid = $accountEntities | Where-Object { -not (Confirm-StatUpn $_.Value) }
if ($invalid) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "One or more account entities failed UPN validation"; values = $invalid.Value }
    return
}

$results = foreach ($entity in $accountEntities) {
    $kqlTemplate = @"
BehaviorAnalytics
| where TimeGenerated > ago(14d)
| where UserPrincipalName == TargetAccount
| where ActivityInsights has 'true'
| project TimeGenerated, ActivityType, InvestigationPriority, ActivityInsights
| top 20 by InvestigationPriority desc
"@
    $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kqlTemplate -Parameters @{ TargetAccount = $entity.Value }

    [pscustomobject]@{
        Account          = $entity.Value
        AnomalousActivity = $r.Results
        MaxPriority       = if ($r.Results) { ($r.Results.InvestigationPriority | Measure-Object -Maximum).Maximum } else { 0 }
    }
}

Write-StatLog -Message "UEBA lookup completed" -Data @{ accountCount = $accountEntities.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
