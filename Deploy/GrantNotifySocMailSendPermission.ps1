#Requires -Modules Microsoft.Graph.Applications

<#
.SYNOPSIS
    Grants the Microsoft Graph "Mail.Send" application permission to a Logic App's
    system-assigned managed identity. Generic - run it once per playbook that sends mail via
    Graph (currently LogicApp/NotifySocTeams and LogicApp/GlobalAdminDailyReport).

.DESCRIPTION
    Run this ONCE per playbook, manually, after the playbook's azuredeploy.json has deployed
    the workflow, by an account holding Global Administrator or Privileged Role Administrator.
    It is intentionally NOT part of the ARM template: granting a Graph application permission
    that can send mail as any mailbox in the tenant is a sensitive, tenant-wide action, and
    this project treats it as a step a privileged human must explicitly review and run rather
    than something that happens silently during a deploy - same pattern as
    Deploy/GrantGraphPermissions.ps1 for the Function App's identity.

    "Mail.Send" at the application level can send as ANY mailbox unless you additionally scope
    it with an Exchange Online application access policy. This script grants the Graph
    permission only; it does NOT create that scoping policy - see the README in whichever
    playbook you're granting for (`New-ApplicationAccessPolicy` step), and do not skip it.

.PARAMETER LogicAppPrincipalId
    The target workflow's managed identity Object (principal) ID - available as the
    `logicAppPrincipalId` output of that playbook's azuredeploy.json, or from:
    az resource show --ids <logicAppResourceId> --query identity.principalId -o tsv
#>

param(
    [Parameter(Mandatory)]
    [string]$LogicAppPrincipalId
)

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"

# Microsoft Graph's own well-known service principal (same app ID in every tenant).
$graphSpAppId = "00000003-0000-0000-c000-000000000000"
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphSpAppId'"

$scopeName = "Mail.Send"
$appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $scopeName -and $_.AllowedMemberTypes -contains "Application" }

if (-not $appRole) {
    throw "Could not find application app role '$scopeName' on the Graph service principal."
}

$existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $LogicAppPrincipalId -All |
    Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }

if ($existing) {
    Write-Host "Already granted: $scopeName" -ForegroundColor Yellow
}
else {
    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $LogicAppPrincipalId `
        -PrincipalId $LogicAppPrincipalId `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id | Out-Null

    Write-Host "Granted: $scopeName" -ForegroundColor Green
}

Write-Host "`nIMPORTANT: Mail.Send at the application level can send mail as ANY mailbox in the" -ForegroundColor Cyan
Write-Host "tenant. Scope it down to only the SenderMailboxUpn used by this playbook with an" -ForegroundColor Cyan
Write-Host "Exchange Online application access policy - see that playbook's README.md." -ForegroundColor Cyan
Write-Host "Verify the grant in the Entra admin center under Enterprise Applications > (this managed identity) > Permissions."
