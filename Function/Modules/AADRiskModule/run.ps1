using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'AADRiskModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\OutputSanitizer.psm1') -Force

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

# Graph calls are made with the Function App's own managed-identity-derived token via
# Connect-MgGraph -Identity (no client secret, no cached app-only token on disk).
try {
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
}
catch {
    Write-StatLog -Level Error -Message "Failed to acquire Graph token via managed identity"
    Send-Response ([HttpStatusCode]::InternalServerError) @{ error = "Graph authentication failed" }
    return
}

$results = foreach ($entity in $accountEntities) {
    # $filter is built from a value that has already passed Confirm-StatUpn, so it cannot
    # contain OData-meaningful characters (quotes, parens); still single-quote-escaped defensively.
    $safeUpn = $entity.Value -replace "'", "''"
    try {
        $riskyUser = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=userPrincipalName eq '$safeUpn'" -ErrorAction Stop
        $riskDetail = $riskyUser.value | Select-Object -First 1

        [pscustomobject]@{
            UserPrincipalName = Protect-StatOutputText $entity.Value
            RiskLevel         = $riskDetail.riskLevel   ?? 'none'
            RiskState         = $riskDetail.riskState    ?? 'none'
            RiskLastUpdated   = $riskDetail.riskLastUpdatedDateTime
        }
    }
    catch {
        Write-StatLog -Level Warning -Message "Risky user lookup failed for an entity"
        [pscustomobject]@{ UserPrincipalName = Protect-StatOutputText $entity.Value; RiskLevel = 'unknown'; Error = 'lookup failed' }
    }
}

Write-StatLog -Message "AAD Risk lookup completed" -Data @{ accountCount = $accountEntities.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
