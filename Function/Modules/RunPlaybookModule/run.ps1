using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'RunPlaybookModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\SecretResolver.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

$allowList = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'PlaybookAllowList.psd1')

$playbookName = $Request.Body.PlaybookName
if (-not $playbookName -or -not $allowList.ContainsKey($playbookName)) {
    Write-StatLog -Level Warning -Message "Rejected request for non-allow-listed playbook" -Data @{ requested = $playbookName }
    Send-Response ([HttpStatusCode]::BadRequest) @{
        error             = "Unknown or non-allow-listed PlaybookName"
        availablePlaybooks = @($allowList.Keys)
    }
    return
}

# The incident/entity context is passed through as-is to the target playbook - it was already
# validated by the Base Module before this call, so it's safe to forward.
$forwardedContext = @{
    IncidentARMId = $Request.Body.IncidentARMId
    Entities      = $Request.Body.Entities
    TriggeredBy   = 'RunPlaybookModule'
    TriggeredAt   = (Get-Date).ToUniversalTime().ToString('o')
}

try {
    $triggerUrl = Get-StatSecret -SecretName $allowList[$playbookName]
    $response = Invoke-RestMethod -Uri $triggerUrl -Method Post -Body ($forwardedContext | ConvertTo-Json -Depth 10) -ContentType 'application/json' -TimeoutSec 30
}
catch {
    Write-StatLog -Level Error -Message "Failed to invoke downstream playbook" -Data @{ playbook = $playbookName }
    Send-Response ([HttpStatusCode]::InternalServerError) @{ error = "Failed to invoke playbook '$playbookName'" }
    return
}

Write-StatLog -Message "Downstream playbook invoked" -Data @{ playbook = $playbookName }
Send-Response ([HttpStatusCode]::OK) @{ playbook = $playbookName; invoked = $true }
