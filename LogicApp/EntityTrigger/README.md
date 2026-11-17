# STAT-Secure entity triage playbook

A Microsoft Sentinel playbook that starts on an **entity trigger**: an analyst opens an
incident, selects an entity (an account, host, IP, file hash or URL), and runs the playbook on
it. The playbook runs only the STAT-Secure modules that apply to that entity type, scores the
results, and posts a summary comment on the incident.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpaulsonsunny19%2FSTATnew%2Fmain%2FLogicApp%2FEntityTrigger%2Fazuredeploy.json)

> The button loads the template from the `main` branch on GitHub, so it works only if the
> repository is public. For a private repository, use **Deploy a custom template** in the portal
> and upload `azuredeploy.json`, or deploy it with the CLI (see below).

## Flow

```
Analyst: Incident > Entities > Run playbook
        │
        ▼
 No incident context? ──► stop (Cancelled)
        │
        ▼
   Base Module (validates the single entity)
        │
        ▼
 Switch on EntityType
   Account  : AAD Risk, UEBA, MDE, Related Alerts
   IP       : IP Reputation, Threat Intel, MDE, Related Alerts
   Host     : Threat Intel, Related Alerts
   FileHash : File Insights, Threat Intel, Related Alerts
   URL      : Threat Intel
        │
        ▼
 Risk Scoring Module (boolean factors only)
        │
        ▼
 Comment on incident (band, score, findings)
        │
        ▼
 Band = High and RaiseSeverityOnHighRisk ──► severity High + tag STAT-Secure-HighRisk
```

A module that fails does not stop the run. Its factor stays `false`, and the incident comment
says that the module did not complete.

## One playbook per entity type

A Sentinel entity trigger is tied to one entity type, so each deployment creates one playbook
for the `EntityType` you pick. To cover several types, deploy the template again with a
different `EntityType`. The default `PlaybookName` is `STAT-Secure-Entity-<EntityType>`, so the
names don't collide.

| Entity type | Value sent to STAT-Secure |
|---|---|
| Account | `Name@UPNSuffix` (must be a valid UPN, or the Base Module rejects it) |
| Host | `HostName` |
| IP | `Address` |
| FileHash | `Value` (MD5, SHA1 or SHA256) |
| URL | `Url` |

## Prerequisites

1. The STAT-Secure Function App is deployed (`Deploy/main.bicep`).
2. The STAT-Secure **custom connector** (`Connector/openapi.json`) and an **API connection** to
   it exist in the same resource group as the playbook. Pass that connection's name as
   `STATConnectionName` (default `statsecure-connector`).

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `EntityType` | `Account` | `Account`, `Host`, `IP`, `FileHash` or `URL` |
| `PlaybookName` | `STAT-Secure-Entity-<EntityType>` | Logic App name |
| `STATConnectionName` | `statsecure-connector` | Existing STAT-Secure API connection |
| `RelatedAlertsLookbackDays` | `7` | 1 to 30 (the module also clamps this to 30) |
| `RaiseSeverityOnHighRisk` | `true` | On a High band, set severity to High and add a tag |

## Deploy with the Azure CLI

```bash
az deployment group create --resource-group <sentinel-rg> --template-file LogicApp/EntityTrigger/azuredeploy.json --parameters EntityType=Account
```

## After deployment

1. **Grant the playbook access to Sentinel.** The template creates a Microsoft Sentinel API
   connection that authenticates with the Logic App's system-assigned managed identity (no stored
   user credentials). Give that identity (deployment output `logicAppPrincipalId`) the
   **Microsoft Sentinel Responder** role on the Sentinel workspace's resource group, so it can
   comment on and update incidents:

   ```bash
   az role assignment create --assignee-object-id <logicAppPrincipalId> --assignee-principal-type ServicePrincipal --role "Microsoft Sentinel Responder" --scope /subscriptions/<sub-id>/resourceGroups/<sentinel-rg>
   ```

2. **Let Sentinel run playbooks in this resource group.** In Sentinel go to
   **Settings > Settings > Playbook permissions** and add the playbook's resource group. This
   grants Sentinel's service account **Microsoft Sentinel Automation Contributor** on it.
3. **Authorize the STAT-Secure connection** if it has not been authorized yet: open the API
   connection in the portal and sign in with the Entra ID app registration from the connector.
4. **Run it.** Open an incident, go to **Entities**, select an entity of the deployed type, and
   choose **Run playbook**.

## Security notes

- **Incident context is required.** Every STAT-Secure call is scoped to an incident ID. If the
  playbook is run from an entity page outside an incident, it stops before calling anything.
- **Only one entity is sent**, and the Base Module validates it (UPN, IP, hostname, hash or URL
  pattern) before any module runs.
- **No playbook chaining.** Unlike the incident-trigger sample, this playbook never calls
  `RunPlaybook`. It is started by an analyst on demand, so remediation stays a separate,
  deliberate step.
- **The comment is HTML-escaped.** The entity value is escaped before it goes into the incident
  comment, and module text fields are already passed through `Protect-StatOutputText`.
