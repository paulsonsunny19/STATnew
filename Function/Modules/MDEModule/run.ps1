using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'MDEModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\OutputSanitizer.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

$maxEntities = 20
$accountEntities = $Request.Body.Entities | Where-Object { $_.Type -eq 'account' }
$ipEntities      = $Request.Body.Entities | Where-Object { $_.Type -eq 'ip' }

if ((-not $accountEntities -or $accountEntities.Count -eq 0) -and (-not $ipEntities -or $ipEntities.Count -eq 0)) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "No 'account' or 'ip' entities provided" }
    return
}
if (($accountEntities.Count + $ipEntities.Count) -gt $maxEntities) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Too many entities (max $maxEntities combined)" }
    return
}
$badAccounts = $accountEntities | Where-Object { -not (Confirm-StatUpn $_.Value) }
$badIps      = $ipEntities | Where-Object { -not (Confirm-StatIpAddress $_.Value) }
if ($badAccounts -or $badIps) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "One or more entities failed validation"; accounts = $badAccounts.Value; ips = $badIps.Value }
    return
}

try { Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop }
catch {
    Write-StatLog -Level Error -Message "Failed to acquire Graph token via managed identity"
    Send-Response ([HttpStatusCode]::InternalServerError) @{ error = "Graph authentication failed" }
    return
}

# Correlate accounts/IPs to device names via SigninLogs / device sign-in activity, parameterized.
$deviceNames = New-Object System.Collections.Generic.HashSet[string]

foreach ($entity in $accountEntities) {
    $kql = "DeviceLogonEvents | where TimeGenerated > ago(14d) | where AccountUpn == TargetAccount | distinct DeviceName | take 25"
    $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kql -Parameters @{ TargetAccount = $entity.Value }
    foreach ($row in $r.Results) { $deviceNames.Add($row.DeviceName) | Out-Null }
}
foreach ($entity in $ipEntities) {
    $kql = "DeviceNetworkEvents | where TimeGenerated > ago(14d) | where LocalIP == TargetIp or RemoteIP == TargetIp | distinct DeviceName | take 25"
    $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kql -Parameters @{ TargetIp = $entity.Value }
    foreach ($row in $r.Results) { $deviceNames.Add($row.DeviceName) | Out-Null }
}

$results = foreach ($deviceName in $deviceNames) {
    $safeDevice = [uri]::EscapeDataString($deviceName)
    try {
        $machine = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/machines?`$filter=computerDnsName eq '$safeDevice'" -ErrorAction Stop
        $m = $machine.value | Select-Object -First 1
        [pscustomobject]@{
            DeviceName    = Protect-StatOutputText $deviceName
            RiskScore     = $m.riskScore ?? 'unknown'
            ExposureLevel = $m.exposureLevel ?? 'unknown'
        }
    }
    catch {
        Write-StatLog -Level Warning -Message "MDE machine lookup failed for a device"
        [pscustomobject]@{ DeviceName = Protect-StatOutputText $deviceName; RiskScore = 'unknown'; ExposureLevel = 'unknown' }
    }
}

Write-StatLog -Message "MDE risk lookup completed" -Data @{ deviceCount = $deviceNames.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
