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
`azuremonitorlogs` via **"Connect with managed identity"**, granted `Log Analytics Reader` on
the workspace (this is a separate connection resource from the one `NotifySocTeams` creates,
even though it's the same connector - each playbook deploys and authorizes its own); `office365`
is covered below.

**Authorizing the connection via managed identity isn't the whole story** - the action that
calls it (`Get_Yesterday_GA_Report`) must also declare
`"authentication": {"type": "ManagedServiceIdentity"}` in its `inputs`, or you'll hit `The
workflow connection parameter 'azuremonitorlogs' is not valid ... configured to support managed
identity but the connection parameter is either missing 'authentication' ...`. This template
already sets that; carry it over if you add another action against this connection.

## Sending mail: Office 365 Outlook connector, authorized as a shared mailbox

Same approach as `NotifySocTeams`: `Send_Email_via_Office365` calls the Office 365 Outlook
connector's `SendEmailV2` operation. **This connector does not support "Connect with managed
identity"** - unlike `azuremonitorlogs`, Exchange Online mailbox access isn't governed by
Azure RBAC, so there's no managed-identity option for it in the portal.

After deploying, use a **dedicated shared/service mailbox** (e.g.
`sentinel-automation@yourdomain.com`, set as `SenderMailboxUpn`) rather than a person's
mailbox, and authorize the `office365` connection this template creates by signing in **as that
mailbox** in the Azure portal. This is a standing delegated OAuth grant, not a stored password -
Logic Apps manages the token refresh - but it is tied to that account, so a disabled account,
revoked MFA, or forced re-consent will break the connection and need re-authorizing. Send a
test report before relying on this daily - verify the email actually arrives "from" the
expected address.

If you'd rather have a genuinely credential-free, managed-identity-only send path, the
alternative is a raw HTTP action calling Microsoft Graph's `sendMail` endpoint directly
(`authentication: ManagedServiceIdentity`) with the `Mail.Send` application permission granted
via `Deploy/GrantNotifySocMailSendPermission.ps1`. Ask if you want this playbook reverted to
that approach instead.

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

## A note on the Azure Monitor Logs connector's response shape

`Get_Yesterday_GA_Report`'s output is read as `body(...)?['value']` being **directly an array
of row objects keyed by column name** (e.g. `item()?['GlobalAdminAccount']`) - not the raw Kusto
REST shape (`tables[0].rows` as an array of positional arrays) an earlier version of this
template assumed, which failed with `ExpressionEvaluationFailed ... must be a valid array`.
This is based on the commonly-documented behavior of the Consumption "Azure Monitor Logs -
Run query and list results" action, but connector response shapes have changed across API
revisions before. If `For_each_Row` still fails after redeploying, open the failed run in the
portal, expand `Get_Yesterday_GA_Report`'s raw output, and check what `value` actually looks
like - paste it back and the query/foreach expression can be corrected to match exactly rather
than guessed again.

## Validated against real tenant data

The `OperationName` strings and `AdditionalDetails` keys in this query (notably joining on
`RoleAssignmentRequestId`, not `RequestId` - the latter's meaning is inconsistent across PIM
lifecycle stages) were confirmed against a real `AuditLogs` export from this tenant, not just
Microsoft's documentation. See `AnalyticsRules/GlobalAdminRoleUsage/README.md` for the same
caveat applied to the NRT rule. One gap: the sample export had no `"Add member to role"`
(direct, non-PIM assignment) rows, so `GlobalAdminAccount`/`RequestedBy` are only populated
for PIM-activation rows today - a direct assignment row will show up in the report (via
`ActivatedAt`/`ActivationType`) but with those two fields blank until validated.
