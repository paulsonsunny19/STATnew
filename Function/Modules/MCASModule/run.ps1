using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'MCASModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\SecretResolver.psm1') -Force
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

$mcasTenantUrl = $env:MCAS_TENANT_URL   # e.g. https://<tenant>.<region>.portal.cloudappsecurity.com
$mcasToken = Get-StatSecret -SecretName 'mcas-api-token'

$results = foreach ($entity in $accountEntities) {
    try {
        $body = @{ filters = @{ entity = @{ eq = @($entity.Value) } } } | ConvertTo-Json -Depth 5
        $response = Invoke-RestMethod `
            -Uri "$mcasTenantUrl/api/v1/entities/" `
            -Method Post `
            -Headers @{ Authorization = "Token $mcasToken" } `
            -ContentType 'application/json' `
            -Body $body `
            -TimeoutSec 15

        $match = $response.data | Select-Object -First 1
        [pscustomobject]@{
            Account               = Protect-StatOutputText $entity.Value
            InvestigationPriority = $match.investigationPriority ?? 0
            IsFlagged             = [bool]($match.isFlagged)
        }
    }
    catch {
        Write-StatLog -Level Warning -Message "MCAS lookup failed for an entity"
        [pscustomobject]@{ Account = Protect-StatOutputText $entity.Value; InvestigationPriority = $null; Error = 'lookup failed' }
    }
}

Write-StatLog -Message "MCAS investigation score lookup completed" -Data @{ accountCount = $accountEntities.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
