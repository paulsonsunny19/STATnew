#Requires -Modules Microsoft.Graph.Applications

<#
.SYNOPSIS
    Grants the Microsoft Graph application permissions required by STAT-Secure modules to the
    Function App's system-assigned managed identity.

.DESCRIPTION
    Run this ONCE, manually, after `Deploy/main.bicep` has deployed the Function App, by an
    account holding Global Administrator or Privileged Role Administrator. It is intentionally
    NOT part of the Bicep template: granting Graph application permissions is a sensitive,
    tenant-wide action, and this project treats it as a step that a privileged human must
    explicitly review and run rather than something that happens silently during infra deploy.

    Only the specific scopes each module actually needs are granted - see each module's
    module.manifest.json for the documented rationale.

.PARAMETER FunctionAppPrincipalId
    The managed identity's Object (principal) ID - available as an output of main.bicep
    (`functionAppPrincipalId`), or from: az functionapp identity show --name <app> --query principalId
#>

param(
    [Parameter(Mandatory)]
    [string]$FunctionAppPrincipalId
)

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"

# Microsoft Graph's own well-known service principal (same app ID in every tenant).
$graphSpAppId = "00000003-0000-0000-c000-000000000000"
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphSpAppId'"

# Scopes required, by module. Review this list before running - each grants the managed
# identity tenant-wide read access to the named resource type.
$requiredScopes = @(
    "IdentityRiskyUser.Read.All",  # AADRiskModule
    "AuditLog.Read.All",           # AADRiskModule (MFA fraud reports / sign-in risk detail)
    "Machine.Read.All",            # MDEModule
    "MailboxSettings.Read"         # OutOfOfficeModule
)

foreach ($scopeName in $requiredScopes) {
    $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $scopeName -and $_.AllowedMemberTypes -contains "Application" }

    if (-not $appRole) {
        Write-Warning "Could not find application app role '$scopeName' on the Graph service principal - skipping."
        continue
    }

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $FunctionAppPrincipalId -All |
        Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }

    if ($existing) {
        Write-Host "Already granted: $scopeName" -ForegroundColor Yellow
        continue
    }

    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $FunctionAppPrincipalId `
        -PrincipalId $FunctionAppPrincipalId `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id | Out-Null

    Write-Host "Granted: $scopeName" -ForegroundColor Green
}

Write-Host "`nDone. Verify grants in the Entra admin center under Enterprise Applications > (this managed identity) > Permissions."
