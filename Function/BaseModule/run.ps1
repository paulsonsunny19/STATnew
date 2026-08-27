using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'BaseModule'
Import-Module (Join-Path $PSScriptRoot '..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\Shared\Logging.psm1') -Force

# --- CORS / origin allow-list -------------------------------------------------
# Only the configured Logic Apps / APIM origin may call this endpoint directly.
# (Defense in depth alongside Easy Auth configured at the Function App level in Bicep.)
$allowedOrigin = $env:ALLOWED_ORIGIN
$requestOrigin = $Request.Headers['Origin']
if ($allowedOrigin -and $requestOrigin -and $requestOrigin -ne $allowedOrigin) {
    Write-StatLog -Level Warning -Message "Rejected request from disallowed origin" -Data @{ origin = $requestOrigin }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::Forbidden
        Body       = @{ error = "Origin not allowed" }
    })
    return
}

# --- Schema validation ---------------------------------------------------------
$maxEntities = [int]($env:MAX_ENTITY_COUNT ?? 50)
$validation = Confirm-StatEntitySchema -Body $Request.Body -MaxEntityCount $maxEntities

if (-not $validation.IsValid) {
    Write-StatLog -Level Warning -Message "Rejected malformed request body" -Data @{ errors = $validation.Errors }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body       = @{ error = "Validation failed"; details = $validation.Errors }
    })
    return
}

# --- Normalize into the context object triage modules expect -------------------
# Only known, validated fields are copied forward. Anything not explicitly
# allow-listed here is dropped rather than passed through, so an unexpected
# field in the incoming payload can't leak into downstream module logic.
$normalizedEntities = foreach ($entity in $Request.Body.Entities) {
    [pscustomobject]@{
        Type  = $entity.Type
        Value = $entity.Value
    }
}

$context = [pscustomobject]@{
    IncidentARMId = $Request.Body.IncidentARMId
    Entities      = @($normalizedEntities)
    RetrievedAt   = (Get-Date).ToUniversalTime().ToString('o')
}

Write-StatLog -Message "Base Module normalized incident context" -Data @{ entityCount = $context.Entities.Count }

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body       = $context
    Headers    = @{ 'Content-Type' = 'application/json' }
})
