# Sample triage Logic App

`azuredeploy.json` deploys a Consumption Logic App demonstrating the intended STAT-Secure
usage pattern, triggered on Sentinel incident creation:

```
Sentinel incident created
        │
        ▼
   Base Module  ──── normalizes + validates entities
        │
   ┌────┼──────────────┬──────────────────┐
   ▼    ▼               ▼                  ▼
AAD Risk  Threat Intel  UEBA          Related Alerts
   │        │            │                  │
   └────────┴─────┬──────┴──────────────────┘
                   ▼
            Risk Scoring Module
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
   Band = High            Band = Medium/Low
        │                     │
  Raise severity        Add triage comment,
  + Run Playbook          take no action
  (NotifySocTeams)
```

## Security notes specific to this Logic App

- **System-assigned managed identity** on the Logic App itself (not a shared account), used for
  the Sentinel API connection where possible.
- The **STAT-Secure API connection** authenticates via the Entra ID app registration configured
  in `Connector/openapi.json` — not a static Function key embedded in the connection.
- `Trigger_Remediation_Playbook` only ever calls `RunPlaybook` with a **fixed, hardcoded
  `PlaybookName`** (`NotifySocTeams`) baked into this workflow definition — the playbook name is
  never built from incident data, so a crafted incident field can't redirect this call to a
  different (possibly destructive) playbook.
- Before deploying, review and adjust which playbook the high-risk branch triggers — swap
  `NotifySocTeams` for a remediation playbook like `IsolateDevice` or `DisableAccount` only
  after you've validated the downstream playbook's own blast radius and added appropriate
  approval gates (e.g. an Adaptive Card approval step) for anything destructive.

## `NotifySocTeams`

`NotifySocTeams/azuredeploy.json` is the actual implementation of the `NotifySocTeams` playbook
`PlaybookAllowList.psd1` references (Key Vault secret `playbook-trigger-notifysoc`). It's built
specifically around Global Administrator role usage: it enriches an incident with who
requested the elevation, who approved it, and what the account did while elevated, then emails
SOC. Pair it with `AnalyticsRules/GlobalAdminRoleUsage` for the NRT detection that feeds it.
See `NotifySocTeams/README.md` for deployment and how the Office 365 Outlook connector is
authorized via managed identity.

## `GlobalAdminDailyReport`

`GlobalAdminDailyReport/azuredeploy.json` is a separate, schedule-driven playbook (a
`Recurrence` trigger, not a Sentinel incident trigger) that emails SOC a daily digest at 9:30 AM
Europe/Dublin of every Global Administrator PIM/role event from the previous calendar day.
Deploy it alongside `NotifySocTeams` for a roll-up that isn't dependent on any single incident
firing. See `GlobalAdminDailyReport/README.md`.
