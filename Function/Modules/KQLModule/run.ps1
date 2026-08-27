using namespace System.Net

param($Request, $TriggerMetadata)

$env:FUNCTION_NAME = 'KQLModule'
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Validation.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\KqlQuery.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\..\..\Shared\Logging.psm1') -Force

function Send-Response([int]$StatusCode, [object]$Body) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode; Body = $Body; Headers = @{ 'Content-Type' = 'application/json' }
    })
}

# --- Load the deploy-time, code-reviewed query allow-list. Never accept raw KQL from the caller. ---
$library = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'QueryLibrary.psd1')

$templateName = $Request.Body.QueryTemplateName
if (-not $templateName -or -not $library.ContainsKey($templateName)) {
    Send-Response ([HttpStatusCode]::BadRequest) @{
        error             = "Unknown or missing QueryTemplateName"
        availableTemplates = @($library.Keys)
    }
    return
}

$template = $library[$templateName]
$matchingEntities = $Request.Body.Entities | Where-Object { $_.Type -eq $template.ParamEntityType }

if (-not $matchingEntities -or $matchingEntities.Count -eq 0) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Template '$templateName' requires an entity of type '$($template.ParamEntityType)', none provided" }
    return
}

# Validate the specific entity type this template needs, same as the dedicated modules do.
$validator = switch ($template.ParamEntityType) {
    'ip'      { { param($v) Confirm-StatIpAddress $v } }
    'host'    { { param($v) Confirm-StatHostname   $v } }
    'account' { { param($v) Confirm-StatUpn        $v } }
    'filehash'{ { param($v) Confirm-StatFileHash   $v } }
}
$target = $matchingEntities[0].Value
if (-not (& $validator $target)) {
    Send-Response ([HttpStatusCode]::BadRequest) @{ error = "Entity value failed validation for template '$templateName'" }
    return
}

$queryResult = Invoke-StatKqlQuery `
    -WorkspaceId $env:SENTINEL_WORKSPACE_ID `
    -QueryTemplate $template.Query `
    -Parameters @{ $template.RequiredParam = $target }

Write-StatLog -Message "Named KQL template executed" -Data @{ template = $templateName }
Send-Response ([HttpStatusCode]::OK) @{ template = $templateName; results = $queryResult.Results }
