using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'WatchlistModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

# Watchlist alias must be strictly alphanumeric/underscore/hyphen - this is embedded in the
# table-name-like _GetWatchlist('<alias>') call, which does not support KQL's `let` parameter
# binding, so it gets its own tight allow-list pattern rather than the general KQL-safe-string check.
$alias = $Request.Body.WatchlistAlias
if (-not $alias -or $alias -notmatch '^[a-zA-Z0-9_-]{1,64}$') {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "WatchlistAlias is missing or contains disallowed characters" }
    return
}

$maxEntities = 20
$entities = $Request.Body.Entities | Where-Object { $_.Type -in @('account', 'ip') }
if (-not $entities -or $entities.Count -eq 0) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "No 'account' or 'ip' entities provided" }
    return
}
if ($entities.Count -gt $maxEntities) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Too many entities (max $maxEntities)" }
    return
}
$badAccounts = $entities | Where-Object { $_.Type -eq 'account' -and -not (Confirm-StatUpn $_.Value) }
$badIps      = $entities | Where-Object { $_.Type -eq 'ip' -and -not (Confirm-StatIpAddress $_.Value) }
if ($badAccounts -or $badIps) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "One or more entities failed validation" }
    return
}

$results = foreach ($entity in $entities) {
    if ($entity.Type -eq 'account') {
        $kqlTemplate = @"
_GetWatchlist('$alias')
| where UserPrincipalName =~ TargetValue or SamAccountName =~ TargetValue
| take 5
"@
        $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kqlTemplate -Parameters @{ TargetValue = $entity.Value }
    }
    else {
        # CIDR-aware match: covers both exact-IP watchlist rows and CIDR-block rows via ipv4_is_in_range.
        $kqlTemplate = @"
_GetWatchlist('$alias')
| where isnotempty(IPAddress) and (IPAddress == TargetValue or ipv4_is_in_range(TargetValue, IPAddress))
| take 5
"@
        $r = Invoke-StatKqlQuery -WorkspaceId $env:SENTINEL_WORKSPACE_ID -QueryTemplate $kqlTemplate -Parameters @{ TargetValue = $entity.Value }
    }

    [pscustomobject]@{
        EntityType  = $entity.Type
        EntityValue = $entity.Value
        FoundOnWatchlist = [bool]($r.Results.Count -gt 0)
        Matches = $r.Results
    }
}

Write-StatLog -Message "Watchlist lookup completed" -Data @{ alias = $alias; entityCount = $entities.Count }
Send-Response ([HttpStatusCode]::OK) @{ watchlist = $alias; results = $results }
