# NotifySocTeams playbook - Global Administrator usage notification

Implements the `NotifySocTeams` playbook referenced by
`Function/Modules/RunPlaybookModule/PlaybookAllowList.psd1` (Key Vault secret
`playbook-trigger-notifysoc`). It is triggered two ways:

1. **Directly**, by wiring a Sentinel automation rule / another Logic App to call this
   workflow's own trigger URL when a `Microsoft.SecurityInsights/alertRules` incident is
   created by the `AnalyticsRules/GlobalAdminRoleUsage` NRT rule (or any other rule you choose
   to route here).
2. **Indirectly**, via `RunPlaybookModule`, which forwards `{ IncidentARMId, Entities,
   TriggeredBy, TriggeredAt }` to whichever trigger URL is stored under the
   `playbook-trigger-notifysoc` Key Vault secret - point that secret at this workflow's
   trigger URL (see `LogicApp/README.md`'s `Trigger_Remediation_Playbook` step for an example
   of a caller).

## What it does

```
HTTP trigger (IncidentARMId, Entities)
        │
        ▼
Get_Incident_Alerts ──── fetch the Sentinel alert(s) on this incident
        │
        ▼
Parse_GA_Alert_Details ─ pull RequestId / GlobalAdminAccount / RequestingOrActivatingActor /
                          ActivationType out of the alert's ExtendedProperties (falls back to
                          the first 'account' entity if the rule that raised the incident
                          didn't populate those custom details)
        │
        ├──► Get_PIM_Request_Details ── join back into AuditLogs by RequestId (or account UPN)
        │    to resolve: who REQUESTED the activation, who APPROVED it (if PIM approval was
        │    required), when it was ACTIVATED, and any justification/ticket number recorded
        │
        └──► Get_GA_Activities_Performed ── list what the account did (AuditLogs) during the
             activation window
        │
        ▼
Compose_Email_Body ── HTML summary table
        │
        ▼
Send_Email_via_Graph ── POST /users/{SenderMailboxUpn}/sendMail, authenticated with this
                         Logic App's own system-assigned managed identity (Mail.Send) - no
                         stored connector credential, consistent with this repo's zero-secrets
                         posture
        │
        ▼
Add_Comment_To_Incident ── logs on the Sentinel incident that SOC was notified and how
```

The email SOC receives answers exactly the three questions this playbook exists for:

- **What was done** using the Global Administrator role (the activities list, plus a link back
  to the Sentinel incident for the full unabridged list).
- **Who requested** the elevation (`RequestedBy`, pulled from the PIM "requested"/"activate"
  audit event's initiating actor).
- **Who approved** it (`ApprovedBy`, pulled from the PIM "approved" audit event's initiating
  actor, or explicitly reported as "Self-activation / no approval on record" when the PIM role
  setting doesn't require approval).

## Deploy

```bash
az deployment group create \
  --resource-group <logic-apps-rg> \
  --template-file azuredeploy.json \
  --parameters \
    SentinelSubscriptionId=<subId> \
    SentinelResourceGroup=<sentinel-rg> \
    SentinelWorkspaceName=<workspace-name> \
    SocTeamEmail=soc-team@yourdomain.com \
    SenderMailboxUpn=sentinel-automation@yourdomain.com
```

After deploying, create (or update, if it already exists) the API connections named
`azuresentinel` and `azuremonitorlogs` in the same resource group and authorize them - the
Sentinel connection needs the workflow's own managed identity or a scoped app registration
with `Microsoft Sentinel Contributor` (to post incident comments) and `Microsoft Sentinel
Reader` at minimum; the Azure Monitor Logs connection needs `Log Analytics Reader` on the
workspace.

## Required permission: Microsoft Graph `Mail.Send`

`Send_Email_via_Graph` authenticates with this Logic App's **system-assigned managed
identity** - never a stored Office 365 connector OAuth credential or an SMTP password. Grant
it the Graph **application** permission `Mail.Send` once, by a Global/Privileged Role
Administrator, using `Deploy/GrantNotifySocMailSendPermission.ps1` (mirrors the pattern already
used for the Function App's identity in `Deploy/GrantGraphPermissions.ps1` - a sensitive,
tenant-wide grant deliberately kept out of the Bicep/ARM deploy path so a human reviews it).

`Mail.Send` at the application level can send mail as **any** mailbox in the tenant unless you
scope it down. Do that with an
[Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
restricting this managed identity to only `SenderMailboxUpn` - don't leave it tenant-wide.

## Parameters

| Parameter | Purpose |
|---|---|
| `SocTeamEmail` | Distribution list / mailbox that receives the notification |
| `SenderMailboxUpn` | Mailbox the notification is sent "from" via Graph `sendMail` |
| `ActivationWindowHours` | Lookback/lookahead window for "activities performed" (default 24h - align with your PIM policy's max activation duration) |

## Validate before production use

Same caveat as the NRT rule: PIM `OperationName` strings and `AdditionalDetails` key names
should be validated against your tenant's `AuditLogs` (see
`AnalyticsRules/GlobalAdminRoleUsage/README.md`). If `RequestedBy`/`ApprovedBy` come back
"Unknown" in the test email, check the raw audit rows in Log Analytics for the field names
your tenant actually emits and adjust `Get_PIM_Request_Details`'s query accordingly.
