# Azure Functions PowerShell profile.ps1
# Runs once per cold start, before any function invocation.

# Fail loudly rather than silently on typos / uninitialized variables in any module.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Authenticate to Azure using the Function App's system-assigned Managed Identity.
# No client secret, no certificate, nothing stored in App Settings.
if ($env:MSI_SECRET) {
    Connect-AzAccount -Identity | Out-Null
}

# Pin TLS to 1.2+ for any outbound calls made with .NET HttpClient/Invoke-RestMethod.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Load shared modules once at cold start so every function invocation reuses them.
$sharedModulePath = Join-Path $PSScriptRoot "..\Shared"
Get-ChildItem -Path $sharedModulePath -Filter "*.psm1" -ErrorAction SilentlyContinue | ForEach-Object {
    Import-Module $_.FullName -Force -Global
}
