using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'FileInsightsModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

$maxEntities = 20
$hashEntities = $Request.Body.Entities | Where-Object { $_.Type -eq 'filehash' }

if (-not $hashEntities -or $hashEntities.Count -eq 0) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "No 'filehash' entities provided" }
    return
}
if ($hashEntities.Count -gt $maxEntities) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Too many hash entities (max $maxEntities)" }
    return
}
# Strict format check BEFORE anything touches a query - rejects, never "cleans", malformed hashes.
$invalid = $hashEntities | Where-Object { -not (Confirm-StatFileHash $_.Value) }
if ($invalid) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "One or more hash entities are not valid MD5/SHA1/SHA256"; values = $invalid.Value }
    return
}

$results = foreach ($entity in $hashEntities) {

    $kqlTemplate = @"
let hashList = pack_array(TargetHash);
EmailAttachmentInfo
| where FileType has_any (hashList) or SHA256 in (hashList) or SHA1 in (hashList) or MD5 in (hashList)
| take 50
| join kind=leftouter (FileProfile(TargetHash, 1000)) on SHA256
| project NetworkMessageId, FileName, SHA256, GlobalPrevalence, Signer, IsCertificateValid, IsRootSignerMicrosoft
"@

    $queryResult = Invoke-StatKqlQuery `
        -WorkspaceId $env:SENTINEL_WORKSPACE_ID `
        -QueryTemplate $kqlTemplate `
        -Parameters @{ TargetHash = $entity.Value }

    [pscustomobject]@{
        Hash             = $entity.Value
        FoundAsAttachment = [bool]($queryResult.Results.Count -gt 0)
        Details           = $queryResult.Results
    }
}

Write-StatLog -Message "File insights lookup completed" -Data @{ hashCount = $hashEntities.Count }
Send-Response ([HttpStatusCode]::OK) @{ results = $results }
