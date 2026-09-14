# GlobalAdminDailyReport playbook - daily SOC digest

Sends SOC a daily email at **9:30 AM Europe/Dublin (GMT/BST, DST-aware)** covering every
Global Administrator PIM/role event from the previous calendar day: who requested activation,
who approved/denied it, tickets/justifications, and any activation that timed out or expired.

Unlike `NotifySocTeams` (which fires per-incident, in near-real-time, off the
`AnalyticsRules/GlobalAdminRoleUsage` NRT rule), this is a **standalone, schedule-driven**
workflow - it is not wired to Sentinel incidents at all, just a `Recurrence` trigger and a
Log Analytics query. Run both: NRT + `NotifySocTeams` for immediate alerting, this for a daily
roll-up SOC can review even if an individual alert was missed or suppressed.

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

`azuredeploy.json` creates the `azuremonitorlogs` and `office365` `Microsoft.Web/connections`
resource shells for you - deploying no longer fails with `ApiConnectionNotFound`. After
deploying, open each in the Azure portal (same resource group) and authorize it:
`azuremonitorlogs` needs a sign-in with `Log Analytics Reader` on the workspace (this is a
separate connection resource from the one `NotifySocTeams` creates, even though it's the same
connector - each playbook deploys and authorizes its own); `office365` is covered below.

## Sending mail: Office 365 Outlook connector + managed identity (no stored mailbox sign-in)

Same approach as `NotifySocTeams`: `Send_Email_via_Office365` calls the Office 365 Outlook
connector's `SendEmailV2` operation with `"authentication": {"type": "ManagedServiceIdentity"}`,
so the call is authorized using this Logic App's own system-assigned managed identity rather
than a signed-in user's stored OAuth credential.

After deploying, open the `office365` connection this template creates and authorize it via
**"Connect with managed identity"** in the Azure portal, selecting this workflow's identity.
That still requires Exchange Online to authorize the identity to send as `SenderMailboxUpn` -
it just moves how you grant that from a Graph SDK script
(`Deploy/GrantNotifySocMailSendPermission.ps1`, still available as a fallback if your
tenant/connector version doesn't offer the managed-identity connection option) to the portal's
own consent flow. Either way, scope it down with an
[Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
restricting the identity to only `SenderMailboxUpn`, and send a test report before relying on
this daily - verify the email actually arrives "from" the expected address.

## Schedule

| Parameter | Default | Notes |
|---|---|---|
| `ReportHour` / `ReportMinute` | 9 / 30 | Local time, in `ReportTimeZone` |
| `ReportTimeZone` | `GMT Standard Time` | Windows time zone ID for the Logic App's `Recurrence` trigger (Dublin/London, DST-aware) |

**Two time zone settings must be kept in sync**, because they're read by two different engines:
- The ARM parameter `ReportTimeZone` (`"GMT Standard Time"`, a **Windows** time zone ID) - read
  by the Logic Apps Recurrence trigger.
- The `ReportTimeZone` `let` variable hardcoded inside the KQL query in `azuredeploy.json`
  (`"Europe/Dublin"`, an **IANA** time zone name) - read by Kusto's `datetime_utc_to_local()`,
  used to compute "yesterday" as a local calendar day (DST-aware) rather than a naive UTC day.

If you change the report's time zone, update both: the ARM parameter (Windows ID) and the
`let ReportTimeZone = "..."` line inside the query string (IANA name).

## What's in the report

One row per PIM request/direct assignment (`RoleAssignmentRequestId`) that had at least one
audit event during the previous local day:

| Column | Meaning |
|---|---|
| Activated At | When the role actually became active (PIM completion or direct assignment) |
| Account | The Global Administrator account |
| Type | `PIM-Activation` or `Direct-Assignment` |
| Requested By / Requested At | Who asked for activation, and when |
| Approved By / Denied By | Who actioned the approval, whichever applies |
| Timed Out | `true` if nobody approved before the request expired |
| Requester Justification/Ticket, Ticket Number | What the requestor entered (often an auto-filled ServiceNow `RITM` ticket number) |
| Approver Comment | The approver's own note - can be free text distinct from the requestor's ticket number |
| Revoked At | When the PIM activation window closed and the role was removed |
| Correlation ID | `RoleAssignmentRequestId` - use this to pull the full raw audit trail for one request in Log Analytics |

If no Global Administrator activity happened, the email still sends with a single
"No Global Administrator activity recorded yesterday" row, so SOC gets a positive confirmation
the pipeline is alive rather than silence being ambiguous between "nothing happened" and
"the report broke."

## Validated against real tenant data

The `OperationName` strings and `AdditionalDetails` keys in this query (notably joining on
`RoleAssignmentRequestId`, not `RequestId` - the latter's meaning is inconsistent across PIM
lifecycle stages) were confirmed against a real `AuditLogs` export from this tenant, not just
Microsoft's documentation. See `AnalyticsRules/GlobalAdminRoleUsage/README.md` for the same
caveat applied to the NRT rule. One gap: the sample export had no `"Add member to role"`
(direct, non-PIM assignment) rows, so `GlobalAdminAccount`/`RequestedBy` are only populated
for PIM-activation rows today - a direct assignment row will show up in the report (via
`ActivatedAt`/`ActivationType`) but with those two fields blank until validated.
