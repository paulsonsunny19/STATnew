<#
.SYNOPSIS
    Resolves secrets exclusively from Key Vault using the Function App's Managed Identity.

.NOTES
    Security rationale: the original STAT-style pattern often reads API keys directly out of
    App Settings (plaintext at rest in the Function App config, visible to anyone with
    "Website Contributor" on the resource, and trivially exfiltrated via `az functionapp
    config appsettings list`). This module ensures the ONLY way a secret enters memory is a
    just-in-time Key Vault read authenticated by Managed Identity, and secrets are never
    written back to App Settings, logs, or disk.
#>

$script:SecretCache = @{}
$script:CacheTtlSeconds = 300  # short TTL: limits blast radius of a compromised secret without hammering Key Vault

function Get-StatSecret {
    <#
    .SYNOPSIS
        Retrieves a secret from Key Vault by name, with a short-lived in-memory cache.
    .PARAMETER SecretName
        The Key Vault secret name to retrieve.
    .OUTPUTS
        System.String - the secret value (caller is responsible for not logging it).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9-]{1,127}$')]  # matches Key Vault secret name constraints; blocks injection via secret name
        [string]$SecretName
    )

    $vaultName = $env:KEY_VAULT_NAME
    if ([string]::IsNullOrWhiteSpace($vaultName)) {
        throw "KEY_VAULT_NAME app setting is not configured. Refusing to resolve secrets without a known vault."
    }

    $cacheKey = "$vaultName/$SecretName"
    $cached = $script:SecretCache[$cacheKey]
    if ($cached -and ((Get-Date) - $cached.Timestamp).TotalSeconds -lt $script:CacheTtlSeconds) {
        return $cached.Value
    }

    try {
        $secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $SecretName -AsPlainText -ErrorAction Stop
    }
    catch {
        # Deliberately do not include $_ (which may echo the secret name/vault path with internal
        # detail) beyond what's needed to triage — never log the exception's full response body.
        throw "Failed to resolve secret '$SecretName' from vault '$vaultName'. Verify the Function App's managed identity has 'Key Vault Secrets User' role."
    }

    $script:SecretCache[$cacheKey] = @{ Value = $secret; Timestamp = Get-Date }
    return $secret
}

function Clear-StatSecretCache {
    <# Call after use in long-lived contexts, or on a timer, to bound secret lifetime in memory. #>
    $script:SecretCache = @{}
}

Export-ModuleMember -Function Get-StatSecret, Clear-StatSecretCache
