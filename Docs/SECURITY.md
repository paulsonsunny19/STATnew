# Threat model & control mapping

| # | Threat | Control |
|---|---|---|
| 1 | Function key or API key leaked via source control, logs, or a compromised Logic App | Function App uses Entra ID Easy Auth; system-assigned Managed Identity for all outbound Azure calls; no static keys issued for the primary flow |
| 2 | Third-party API keys (threat intel, etc.) sitting in App Settings, readable by anyone with Reader on the resource | All such secrets live in Key Vault, resolved via `Get-StatSecret` (Managed Identity + `Key Vault Secrets User` RBAC only — not Contributor/Admin) |
| 3 | KQL injection via an attacker-shaped entity value (e.g. a phishing email's spoofed hostname becoming a "host" entity) | `Invoke-StatKqlQuery` binds all values via `let` statements server-side; modules never string-concatenate entity values into KQL |
| 4 | Over-privileged app registration used across all modules, so compromising one module's flow yields access to everything | Each module ships a `module.manifest.json` declaring the exact permissions it needs; deployment grants scoped RBAC roles (e.g. `Log Analytics Reader`, not `Contributor`) rather than one shared "automation" service principal with broad rights |
| 5 | Malformed/oversized entity payload causing excessive KQL fan-out or a denial-of-service against the workspace | `Confirm-StatEntitySchema` enforces `MAX_ENTITY_COUNT`; Base Module rejects payloads exceeding it before any downstream call is made |
| 6 | Sensitive data (UPNs, IPs, secrets) written to Application Insights and later exported to a lower-trust SIEM/support ticket | `Write-StatLog` runs all structured data through `Protect-StatLogObject`, which redacts known-sensitive field names before serialization |
| 7 | Markdown/HTML injection into a Sentinel incident comment, misleading an analyst | `Protect-StatOutputText` escapes markdown control characters and HTML angle brackets, and truncates length, before any module output is written back to an incident |
| 8 | Anyone who can reach the Function App's public endpoint (not just the intended Logic App) invoking triage modules directly | CORS locked to `ALLOWED_ORIGIN`; Easy Auth requires an Entra ID token scoped to this app registration; storage/Key Vault network ACLs default to `Deny` |
| 9 | Compromised secret has a long useful life because it's cached indefinitely in Function App memory | `Get-StatSecret` caches for 300 seconds only; `Clear-StatSecretCache` available for explicit invalidation |
| 10 | TLS downgrade / plaintext transport for outbound calls | `profile.ps1` pins `SecurityProtocol` to TLS 1.2+; `httpsOnly: true` enforced on the Function App resource |

## What this does not cover

- **Supply chain**: `requirements.psd1` pins major versions but you should additionally pin
  exact versions and review changes before bumping in production.
- **Runbook-level secrets rotation**: Key Vault holds secrets, but you still need a rotation
  policy/automation (e.g. Key Vault's built-in rotation for supported secret types) for the
  third-party API keys that live there.
- **WAF/DDoS**: put the Function App behind Azure Front Door or APIM with WAF policies if it's
  ever exposed beyond the Logic Apps environment.
