# Global Administrator role usage - NRT analytics rule

`azuredeploy.json` deploys a Microsoft Sentinel **NRT (Near-Real-Time)** analytics rule that
fires within about a minute of the Global Administrator directory role being activated (PIM)
or assigned directly to a user, so SOC finds out immediately rather than on a 5-15 minute
scheduled-rule cadence.

This rule is deliberately narrow: it is single-table, single-purpose detection (a hard
requirement for NRT rules - they cannot join across tables or take longer than ~60 seconds to
run). It does **not** try to answer "who approved this" or "what did they do while elevated" -
that enrichment happens downstream, once, in `LogicApp/NotifySocTeams`, which is wired to this
rule's incidents and does the heavier correlation query there.

## Prerequisites

- The **Entra ID (Azure AD)** data connector must be enabled in this workspace with **Audit
  Logs** flowing in (`AuditLogs` table). Sign-in logs (`SigninLogs`) are used by the downstream
  playbook, not this rule, but enable that log stream too if you want sign-in context in the
  SOC email.
- PIM (Privileged Identity Management) must be in use for Global Administrator activation for
  the `PIM-Activation` detection path to fire; direct/permanent assignments are still caught by
  the `Direct-Assignment` path even without PIM.

## Deploy

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file azuredeploy.json \
  --parameters WorkspaceName=<log-analytics-workspace-name>
```

## Validate the query against your tenant before enabling

Microsoft documents the general shape of PIM audit events in `AuditLogs`, but the exact
`OperationName` strings and the key names inside `AdditionalDetails` (e.g. `RequestId`,
`Justification`, `TicketNumber`) have varied slightly across Entra ID role management module
versions and tenant configurations. Before relying on this rule in production:

1. Run the rule's `query` (in `azuredeploy.json`) as an ad-hoc Log Analytics query.
2. Trigger a real (or test) Global Administrator PIM activation in a non-production context.
3. Confirm a row appears with the expected `TargetUser`, `InitiatingActor`, `ActivationType`,
   and a non-empty `RequestId`.
4. If `RequestId` (or another field) comes back empty, inspect the raw `AdditionalDetails` /
   `TargetResources` columns for that row and adjust the key names in the query and in
   `LogicApp/NotifySocTeams`'s enrichment query to match.

## What happens after it fires

1. An incident is created (grouped by entity for 5 hours, so repeated activity by the same
   account/actor within a window lands on one incident instead of paging SOC per event).
2. Wire this rule's incidents to the STAT-Secure automation the same way the sample playbook
   does (`LogicApp/azuredeploy.json`): on incident creation, call `RunPlaybookModule` with
   `PlaybookName: "NotifySocTeams"`. That playbook fetches this alert's custom details
   (`RequestId`, `GlobalAdminAccount`, `RequestingOrActivatingActor`, `ActivationType`), joins
   back into `AuditLogs` to resolve the PIM requestor/approver and every action the account took
   while elevated, and emails SOC. See `LogicApp/NotifySocTeams/README.md`.

## Entities mapped

| Entity | Source column | Meaning |
|---|---|---|
| Account | `TargetUser` | The account the Global Administrator role was activated/assigned on |
| Account | `InitiatingActor` | Who performed the completing action (the requestor, for self-service PIM activation) |
| IP | `InitiatingIp` | Source IP of the initiating actor, when Entra ID populates it |

## Tuning

- `suppressionDuration` / incident grouping default to 5 hours, matching the typical maximum
  PIM activation duration - adjust `lookbackDuration` in `incidentConfiguration` if your PIM
  policy allows longer activations.
- `RuleSeverity` defaults to `High`. Consider `Informational`/`Low` plus a dedicated workbook
  instead of an incident-per-activation if Global Administrator PIM activation is routine at
  your organization and you only want to alert on anomalies (e.g. combine with
  `AADRiskModule`/`UEBAModule` output before deciding severity, rather than alerting on every
  activation).
