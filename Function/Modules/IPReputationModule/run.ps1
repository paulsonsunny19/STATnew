using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'IPReputationModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\SecretResolver.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\OutputSanitizer.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = $Body
        Headers    = @{ 'Content-Type' = 'application/json' }
    })
}

# --- Validate input: this module only accepts 'ip' typed entities that pass strict parsing.
$ipEntities = $Request.Body.Entities | Where-Object { $_.Type -eq 'ip' }

if (-not $ipEntities -or $ipEntities.Count -eq 0) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "No 'ip' entities provided" }
    return
}

$manifestMax = 20
if ($ipEntities.Count -gt $manifestMax) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Too many IP entities (max $manifestMax per module manifest)" }
    return
}

$invalidIps = $ipEntities | Where-Object { -not (Confirm-StatIpAddress $_.Value) }
if ($invalidIps) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "One or more IP entities failed validation"; values = $invalidIps.Value }
    return
}

$results = foreach ($entity in $ipEntities) {

    # --- Parameterized KQL: the IP value is bound server-side via `let`, never concatenated. ---
    $kqlTemplate = @"
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where SourceIP == TargetIp or DestinationIP == TargetIp
| summarize EventCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by SourceIP, DestinationIP
| take 100
"@

    $queryResult = Invoke-StatKqlQuery `
        -WorkspaceId $env:SENTINEL_WORKSPACE_ID `
        -QueryTemplate $kqlTemplate `
        -Parameters @{ TargetIp = $entity.Value }

    # --- External threat intel lookup: API key resolved just-in-time from Key Vault, never cached to disk. ---
    $tiApiKey = Get-StatSecret -SecretName 'ti-api-key'
    $tiResponse = $null
    try {
        $tiResponse = Invoke-RestMethod `
            -Uri "https://threatintel.example-provider.com/api/v1/ip/$($entity.Value)" `
            -Headers @{ 'Authorization' = "Bearer $tiApiKey" } `
            -Method Get `
            -TimeoutSec 10
    }
    catch {
        Write-StatLog -Level Warning -Message "Threat intel lookup failed" -Data @{ ip = $entity.Value }
    }

    [pscustomobject]@{
        IPAddress        = $entity.Value
        InternalActivity = $queryResult.Results
        ThreatIntel       = if ($tiResponse) {
            [pscustomobject]@{
                Reputation = Protect-StatOutputText ($tiResponse.reputation ?? 'unknown')
                Category   = Protect-StatOutputText ($tiResponse.category ?? 'unknown')
            }
        } else { $null }
    }
}

Write-StatLog -Message "IP reputation lookup completed" -Data @{ ipCount = $ipEntities.Count }

Send-Response ([HttpStatusCode]::OK) @{ results = $results }
