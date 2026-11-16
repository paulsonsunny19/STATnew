#Requires -Modules Microsoft.Graph.Applications

<#
.SYNOPSIS
    Grants the Microsoft Graph application permission needed by the External File Activity
    playbooks to their user-assigned managed identity.

.DESCRIPTION
    Run once after deploying azuredeploy.json, as Global Administrator or Privileged Role
    Administrator. Granting Graph application permissions is a tenant-wide action and cannot
    be done from an ARM template.

    Permission granted:
      ThreatHunting.Read.All - run Defender XDR advanced hunting queries (CloudAppEvents)
                               through POST /security/runHuntingQuery.

    Email is sent through the Office 365 Outlook connector, so no Mail.* permission is needed.

.PARAMETER ManagedIdentityPrincipalId
    The managed identity's Object (principal) ID. It is the deployment output
    'managedIdentityPrincipalId', or run:
      az identity show -g <rg> -n <identity-name> --query principalId -o tsv

.EXAMPLE
    ./Grant-GraphPermissions.ps1 -ManagedIdentityPrincipalId 00000000-0000-0000-0000-000000000000
#>

param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ManagedIdentityPrincipalId
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All' -NoWelcome

# Microsoft Graph's service principal has the same appId in every tenant.
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

$requiredRoles = @(
    'ThreatHunting.Read.All'
)

foreach ($roleName in $requiredRoles) {
    $appRole = $graphSp.AppRoles |
        Where-Object { $_.Value -eq $roleName -and $_.AllowedMemberTypes -contains 'Application' }

    if (-not $appRole) {
        Write-Warning "App role '$roleName' not found on the Microsoft Graph service principal - skipping."
        continue
    }

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityPrincipalId -All |
        Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }

    if ($existing) {
        Write-Host "Already granted: $roleName" -ForegroundColor Yellow
        continue
    }

    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $ManagedIdentityPrincipalId `
        -PrincipalId $ManagedIdentityPrincipalId `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id | Out-Null

    Write-Host "Granted: $roleName" -ForegroundColor Green
}

Write-Host "`nDone. Token caching means the new permission can take up to ~1 hour to apply to the playbooks."
