# STAT-Secure

A security-hardened reimplementation of the **Microsoft Sentinel Triage AssistanT (STAT)**
pattern: a PowerShell Azure Function App, fronted by a Logic Apps custom connector, that
normalizes Sentinel incident/entity data (Base Module) and exposes callable triage modules
for use in Sentinel automation playbooks.

This is a from-scratch reimplementation focused on closing common weaknesses found in
"grab an API key and call a function" style Sentinel automation connectors — not a copy of
any specific codebase.

## What's different from a typical STAT-style deployment

| Area | Typical / original pattern | This implementation |
|---|---|---|
| Secrets | API keys / connection strings in App Settings or `local.settings.json` | **Zero secrets in app config.** Function App uses a **system-assigned Managed Identity**; all credentials (Sentinel workspace, Graph app, third-party API keys) live in **Key Vault** and are resolved at runtime via `Get-AzKeyVaultSecret` / Key Vault references |
| Function auth | `authLevel: function` (a single shared key, often logged, forwarded, or committed) | **Entra ID (Easy Auth) on the Function App**, function keys disabled by default, optional IP allow-list at the front door |
| Permissions | One broad app registration (`Directory.Read.All`, `SecurityEvents.ReadWrite.All`, etc.) shared across every module | **Per-module scoped permissions**, documented in each module manifest, requested only for what that module touches |
| Input handling | Incident/entity JSON trusted as-is; values interpolated into KQL/Graph calls | **Typed schema validation** on every request body before any downstream call; rejects malformed GUIDs, IPs, hostnames, KQL-unsafe strings |
| KQL queries | String-concatenated queries | **Parameterized** via bound query parameters, never string interpolation of user input |
| Logging | Full incident/entity objects written to `Write-Host` / App Insights | **Redaction layer** strips PII/secret-shaped values before anything is logged |
| Output back to Sentinel | Raw text/markdown inserted into incident comments | **Output encoding** to prevent markdown/HTML injection into the incident timeline |
| Network | Function App on default public endpoint, CORS `*` | **Private endpoint optional**, CORS locked to specific Logic Apps/APIM origin, `https only` enforced |

## Repository layout

```
STAT-Secure/
├── Function/
│   ├── host.json
│   ├── profile.ps1
│   ├── requirements.psd1
│   ├── local.settings.json.example
│   ├── BaseModule/
│   └── Modules/
│       ├── IPReputationModule/
│       ├── AADRiskModule/
│       ├── FileInsightsModule/
│       ├── KQLModule/                (+ QueryLibrary.psd1 - allow-listed query templates)
│       ├── MCASModule/
│       ├── MDEModule/
│       ├── OutOfOfficeModule/
│       ├── RelatedAlertsModule/
│       ├── ThreatIntelModule/
│       ├── UEBAModule/
│       ├── WatchlistModule/
│       ├── RiskScoringModule/
│       └── RunPlaybookModule/         (+ PlaybookAllowList.psd1 - allow-listed downstream playbooks)
├── Shared/
│   ├── Validation.psm1
│   ├── SecretResolver.psm1
│   ├── Logging.psm1
│   ├── KqlQuery.psm1
│   └── OutputSanitizer.psm1
├── Connector/
│   └── openapi.json
├── LogicApp/
│   ├── azuredeploy.json           (sample end-to-end triage playbook)
│   └── README.md
├── Deploy/
│   ├── main.bicep
│   └── GrantGraphPermissions.ps1  (run once, manually, by a privileged admin)
└── Docs/
    └── SECURITY.md
```

## Module coverage

All 12 modules from the original STAT module library are implemented, plus the Base Module
and a sample Logic App wiring them together:

| Module | Original purpose | Key security change here |
|---|---|---|
| Base | Normalizes/enriches incident + entity data | Unknown fields dropped, not passed through; strict entity-count cap |
| Azure AD Risks | Entra ID Identity Protection risk, MFA fraud/failures | Read-only Graph scopes only, no risk dismissal capability |
| File Insights | Email attachment + `FileProfile()` lookup | Hashes validated against strict hex/length patterns before use |
| KQL | Run custom KQL against Sentinel/Advanced Hunting | **Rebuilt as a named-template allow-list** - no free-text KQL accepted from callers |
| Microsoft Defender for Cloud Apps | MCAS investigation priority score | Scoped API token from Key Vault only |
| Microsoft Defender for Endpoint | Device risk score / exposure level | Uses Graph Security API + managed identity, not a separate MDE app secret |
| Office 365 Out of Office | Mailbox auto-reply status | `MailboxSettings.Read` only, no mail content access |
| Related Alerts | Other alerts referencing same entities | Lookback window server-clamped to 30 days max |
| Threat Intelligence | Cross-reference `ThreatIntelligenceIndicator` | Read-only; no indicator write/tag scope |
| UEBA | `BehaviorAnalytics` deviation lookup | Parameterized KQL, no free-text pass-through |
| Watchlists | UPN/IP/CIDR watchlist matching | Watchlist alias strictly pattern-validated before use |
| Risk Scoring | Aggregate module outputs into a score | Deploy-time weights, not caller-supplied; strict boolean-only inputs |
| Run Playbook | Invoke another Sentinel playbook | **Rebuilt as an allow-list of pre-registered playbook names** - the original accepts an arbitrary target from the caller |

## Getting started

See `Docs/SECURITY.md` for the threat model this design addresses, and `Deploy/main.bicep`
for a one-shot deployment of the Function App, Key Vault, and Managed Identity role
assignments (no manual secret entry required — you seed Key Vault separately, then the
Function App is granted `get`/`list` access via RBAC, not a vault access policy with a
shared key).
