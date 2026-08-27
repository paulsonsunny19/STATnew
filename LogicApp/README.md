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
