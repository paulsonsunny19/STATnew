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
Send_Email_via_Office365 ── Office 365 Outlook "Send an email (V2)" connector action, sent
                         via a connection authorized as SenderMailboxUpn (see below - this
                         connector doesn't support managed identity, unlike azuresentinel/
                         azuremonitorlogs)
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

`azuredeploy.json` creates the `azuresentinel`, `azuremonitorlogs`, and `office365`
`Microsoft.Web/connections` resource shells for you - deploying no longer fails with
`ApiConnectionNotFound`. What ARM can't do is the OAuth/identity consent step, so **after
deploying, open each of the three connections in the Azure portal (same resource group) and
authorize them**:
- `azuresentinel` - sign in with an account (or app registration) holding `Microsoft Sentinel
  Contributor` (to post incident comments) and `Microsoft Sentinel Reader` at minimum.
- `azuremonitorlogs` - sign in with an account holding `Log Analytics Reader` on the workspace.
- `office365` - covered below.

An unauthorized connection deploys fine but fails at run time with errors like
`ApiConnectionNotFound` (if the connection resource is genuinely missing - now fixed) or
`ConnectionAuthorizationFailed`/`InvalidAuthenticationToken` (if it exists but was never
authorized) - if you hit either after deploying this template, check the connection's status in
the portal before assuming the template itself is broken.

## Sending mail: Office 365 Outlook connector, authorized as a shared mailbox

`Send_Email_via_Office365` calls the Office 365 Outlook connector's `SendEmailV2` operation.
**This connector does not support "Connect with managed identity"** - unlike `azuresentinel`
and `azuremonitorlogs` above, Exchange Online mailbox access isn't governed by Azure RBAC, so
there's no managed-identity option for it in the portal. The `office365` connection must be
authorized the normal way: signing in as a real account.

**What to do once, after deploying:**

1. Create (or use an existing) **dedicated shared/service mailbox** for this automation - e.g.
   `sentinel-automation@yourdomain.com` - rather than a real person's mailbox, so the connection
   doesn't break when someone's password rotates or they leave. Set `SenderMailboxUpn` to it.
2. In the Azure portal, open the `office365` connection in this resource group and authorize it
   by signing in **as that mailbox** (or as an account granted `Send As`/`Send on Behalf` rights
   on it - in which case set the `From` field's behavior by testing which one your tenant
   honors). Modern auth handles MFA once at sign-in; Logic Apps then manages the token refresh,
   so this isn't a stored password, but it is a standing delegated grant tied to that account -
   monitor it (a disabled account, revoked MFA method, or forced re-consent will break the
   connection and needs re-authorizing).
3. **Test-send before relying on this in production** to confirm the email actually arrives
   "from" `SenderMailboxUpn` as expected.

If you'd rather have a genuinely credential-free, managed-identity-only send path, the
alternative is a raw HTTP action calling Microsoft Graph's `sendMail` endpoint directly
(`authentication: ManagedServiceIdentity`) with the `Mail.Send` application permission granted
via `Deploy/GrantNotifySocMailSendPermission.ps1` - that mechanism works because it's a generic
HTTP call, not dependent on this specific connector's feature set. Ask if you want this playbook
reverted to that approach instead.

## Parameters

| Parameter | Purpose |
|---|---|
| `SocTeamEmail` | Distribution list / mailbox that receives the notification |
| `SenderMailboxUpn` | Mailbox the notification is sent "from" via the Office 365 Outlook connector |
| `ActivationWindowHours` | Lookback/lookahead window for "activities performed" (default 24h - align with your PIM policy's max activation duration) |

## Validate before production use

Same caveat as the NRT rule: PIM `OperationName` strings and `AdditionalDetails` key names
should be validated against your tenant's `AuditLogs` (see
`AnalyticsRules/GlobalAdminRoleUsage/README.md`). If `RequestedBy`/`ApprovedBy` come back
"Unknown" in the test email, check the raw audit rows in Log Analytics for the field names
your tenant actually emits and adjust `Get_PIM_Request_Details`'s query accordingly.
