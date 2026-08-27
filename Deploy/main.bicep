@description('Base name used to derive resource names')
param baseName string = 'statsecure'

@description('Azure region')
param location string = resourceGroup().location

@description('Entra ID tenant ID used for Easy Auth on the Function App')
param entraTenantId string

@description('Entra ID App Registration (client) ID used for Easy Auth on the Function App')
param entraClientId string

@description('Origin allowed to call the Function App (your Logic Apps / APIM front door)')
param allowedOrigin string

@description('Existing Log Analytics workspace resource ID that Sentinel is enabled on')
param sentinelWorkspaceResourceId string

var funcAppName = '${baseName}-func'
var storageAccountName = toLower('${baseName}sa${uniqueString(resourceGroup().id)}')
var appInsightsName = '${baseName}-ai'
var keyVaultName = '${baseName}-kv-${uniqueString(resourceGroup().id)}'
var planName = '${baseName}-plan'

// --- Storage account: required by Functions runtime. No public blob access. ---
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: sentinelWorkspaceResourceId
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: planName
  location: location
  sku: { name: 'EP1', tier: 'ElasticPremium' }  // Elastic Premium: supports VNet integration/private endpoints, unlike Consumption
}

// --- Key Vault: RBAC authorization only. No access policies, no vault-wide secret list rights. ---
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: entraTenantId
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

// --- Function App: system-assigned managed identity, HTTPS-only, TLS 1.2, Easy Auth, locked CORS. ---
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: funcAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      cors: {
        allowedOrigins: [allowedOrigin]
        supportCredentials: false
      }
      appSettings: [
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'powershell' }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'KEY_VAULT_NAME', value: keyVault.name }
        { name: 'ALLOWED_ORIGIN', value: allowedOrigin }
        { name: 'MAX_ENTITY_COUNT', value: '50' }
        { name: 'SENTINEL_WORKSPACE_ID', value: reference(sentinelWorkspaceResourceId, '2022-10-01').customerId }
      ]
    }
  }
}

// --- Easy Auth: require an authenticated Entra ID caller (the Logic Apps managed identity / APIM). ---
resource authSettings 'Microsoft.Web/sites/config@2023-01-01' = {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: entraClientId
          openIdIssuer: 'https://sts.windows.net/${entraTenantId}/'
        }
        validation: {
          allowedAudiences: ['api://${entraClientId}']
        }
      }
    }
  }
}

// --- RBAC: grant the Function App's managed identity ONLY "Key Vault Secrets User" (read secrets),
//     never Key Vault Administrator/Contributor. Least privilege for the identity itself.
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource kvSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- RBAC: grant read access to the Sentinel Log Analytics workspace only, not the workspace's resource group. ---
var logAnalyticsReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a8bb'

resource lawReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sentinelWorkspaceResourceId, functionApp.id, logAnalyticsReaderRoleId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsReaderRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output functionAppName string = functionApp.name
output functionAppPrincipalId string = functionApp.identity.principalId
output keyVaultName string = keyVault.name

// NOTE: Microsoft Graph application permissions (IdentityRiskyUser.Read.All, Machine.Read.All,
// MailboxSettings.Read, AuditLog.Read.All - used by AADRiskModule, MDEModule, OutOfOfficeModule)
// cannot be granted via an ARM/Bicep role assignment; Graph app role assignments require the
// Microsoft Graph resource service principal's app role IDs and are typically granted via
// Deploy/GrantGraphPermissions.ps1 (run once, post-deployment, by a Global/Privileged Role
// Administrator) rather than embedded here. Keeping that step as an explicit, audited,
// human-run script - rather than folding it into this template - is intentional: it ensures
// a person with the right privilege reviews exactly which Graph scopes are being granted to
// this identity before they're granted.
