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

## Identity: user-assigned, not system-assigned

This workflow uses a **user-assigned managed identity** (`Microsoft.ManagedIdentity/userAssignedIdentities`,
named by the `UserAssignedIdentityName` parameter, default `notifysocteams-identity`) that
`azuredeploy.json` creates and attaches to the Logic App - not the workflow's own system-assigned
identity. The difference matters operationally: a system-assigned identity's principal ID (and
every RBAC role you granted it) is deleted the moment the Logic App is deleted, and a new one is
issued on redeploy - so role assignments have to be redone every time. A user-assigned identity
is its own standalone resource; redeploying or even deleting-and-recreating this Logic App
doesn't touch it, so the RBAC grants below survive. It can also be reused across other
playbooks later if you want one identity for the whole STAT-Secure automation surface, rather
than one per playbook (this template creates a dedicated one by default - point
`UserAssignedIdentityName` at an existing identity's name instead if you'd rather share one).

After deploying, grant its principal ID (the `userAssignedIdentityPrincipalId` output, or
`az identity show --name notifysocteams-identity --resource-group <rg> --query principalId`)
the same roles you would have granted a system-assigned identity: `Microsoft Sentinel
Contributor` + `Microsoft Sentinel Reader` for `azuresentinel`, `Log Analytics Reader` for
`azuremonitorlogs`.

**If you authorize `azuresentinel`/`azuremonitorlogs` via managed identity**, that touches three
separate places in this template, all required together (`WorkflowManagedIdentityConfigurationInvalid`
means one of them is missing):
1. The **connection reference** itself, in `properties.parameters.$connections.value.<name>` -
   needs a `connectionProperties: { authentication: { type: "ManagedServiceIdentity", identity:
   "<UAI resource ID>" } }` block. This is what the error message's "missing 'authentication'
   property in connection properties" is about - it's *not* referring to the action.
2. Every **action** that calls the connection - needs `"authentication": {"type":
   "ManagedServiceIdentity", "identity": "<UAI resource ID>"}` in its `inputs`, alongside `host`.
3. The workflow resource's own `identity` block must list that same user-assigned identity under
   `userAssignedIdentities` - otherwise the `identity` reference in (1) and (2) points at an
   identity the workflow was never actually assigned, and authorization fails.

The `identity` field in both places is always
`[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', parameters('UserAssignedIdentityName'))]`
- if you rename the parameter or swap in an existing identity, that expression still resolves
correctly since it's parameterized, not hardcoded.

This template sets all three for `azuresentinel` and `azuremonitorlogs` (actions:
`Get_Incident_Alerts`, `Get_PIM_Request_Details`, `Get_GA_Activities_Performed`,
`Add_Comment_To_Incident`) - if you add a new action against either connection, carry all three
over. `Send_Email_via_Office365`/`office365` deliberately has **none** of this, since that
connector can't be authorized via managed identity (user-assigned or system-assigned) at all
(see below) - it's authorized by signing in as a real mailbox regardless of identity type.

**In the Azure portal, when authorizing `azuresentinel`/`azuremonitorlogs`**, choose "Connect
with managed identity" and pick the **user-assigned identity** from the dropdown (it will be
listed by the name you set in `UserAssignedIdentityName`) - not "System-assigned," since this
workflow no longer has one.

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
(`authentication: {type: ManagedServiceIdentity, identity: <UAI resource ID>}`) with the
`Mail.Send` application permission granted to the user-assigned identity via
`Deploy/GrantNotifySocMailSendPermission.ps1` - that mechanism works because it's a generic HTTP
call, not dependent on this specific connector's feature set. Ask if you want this playbook
reverted to that approach instead.

## Parameters

| Parameter | Purpose |
|---|---|
| `SocTeamEmail` | Distribution list / mailbox that receives the notification |
| `SenderMailboxUpn` | Mailbox the notification is sent "from" via the Office 365 Outlook connector |
| `ActivationWindowHours` | Lookback/lookahead window for "activities performed" (default 24h - align with your PIM policy's max activation duration) |
| `UserAssignedIdentityName` | Name of the user-assigned managed identity created for this workflow (default `notifysocteams-identity`) - point at an existing identity's name to share one across playbooks instead |

## A note on the Azure Monitor Logs connector's response shape

Both Log Analytics query results (`Get_PIM_Request_Details`, `Get_GA_Activities_Performed`) are
read as `body(...)?['value']` being **directly an array of row objects keyed by column name**
(e.g. `body('Get_PIM_Request_Details')?['value']?[0]?['RequestedBy']`) - not the raw Kusto REST
shape (`tables[0].rows` as positional arrays) an earlier version of this template assumed, which
failed at run time. If either query action's downstream expression still errors after
redeploying, open the failed run in the portal, expand that action's raw output, and check what
`value` actually contains - see `LogicApp/GlobalAdminDailyReport/README.md` for the same note in
more detail (that playbook hit this first).

## Validate before production use

Same caveat as the NRT rule: PIM `OperationName` strings and `AdditionalDetails` key names
should be validated against your tenant's `AuditLogs` (see
`AnalyticsRules/GlobalAdminRoleUsage/README.md`). If `RequestedBy`/`ApprovedBy` come back
"Unknown" in the test email, check the raw audit rows in Log Analytics for the field names
your tenant actually emits and adjust `Get_PIM_Request_Details`'s query accordingly.
