using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'OutOfOfficeModule'
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

try { Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop }
catch {
    Write-StatLog -Level Error -Message "Failed to acquire Graph token via managed identity"
    Send-Response ([HttpStatusCode]::InternalServerError) @{ error = "Graph authentication failed" }
    return
}

$results = foreach ($entity in $accountEntities) {
    $safeUpn = [uri]::EscapeDataString($entity.Value)
    try {
        $settings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$safeUpn/mailboxSettings/automaticRepliesSetting" -ErrorAction Stop
        [pscustomobject]@{
            Account         = Protect-StatOutputText $entity.Value
            AutoRepliesSet  = ($settings.status -ne 'disabled')
            Status          = $settings.status
            ScheduledStart  = $settings.scheduledStartDateTime.dateTime
            ScheduledEnd    = $settings.scheduledEndDateTime.dateTime
        }
    }
    catch {
        Write-StatLog -Level Warning -Message "Mailbox settings lookup failed for an entity"
        [pscustomobject]@{ Account = Protect-StatOutputText $entity.Value; AutoRepliesSet = $null; Error = 'lookup failed' }
    }
}

Write-StatLog -Message "Out of office lookup completed" -Data @{ accountCount = $accountEntities.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
