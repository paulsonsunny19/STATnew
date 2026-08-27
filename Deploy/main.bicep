@description('Base name used to derive resource names')
@maxLength(10)
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
// Storage names are globally unique, lowercase alphanumeric, and max 24 chars.
// 10-char baseName + 2-char "sa" + 12-char unique suffix = 24 chars.
var storageAccountName = toLower('${baseName}sa${take(uniqueString(resourceGroup().id), 12)}')
var appInsightsName = '${baseName}-ai'
var keyVaultName = '${baseName}-kv-${uniqueString(resourceGroup().id)}'
var planName = '${baseName}-plan'

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
  sku: { name: 'EP1', tier: 'ElasticPremium' }
}

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
