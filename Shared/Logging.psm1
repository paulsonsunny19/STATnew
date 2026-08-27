<#
.SYNOPSIS
    Structured logging wrapper that redacts secret-shaped values and known PII fields
    before anything reaches Write-Host / Application Insights.

.NOTES
    Security rationale: App Insights traces are readable by anyone with Reader on the
    resource group, are often exported to a SIEM with broader access, and commonly get
    pasted into support tickets. Full entity objects (containing UPNs, IPs, sometimes tokens
    passed through incident custom details) should never be logged verbatim.
#>

$script:RedactedFields = @('password', 'secret', 'apikey', 'api_key', 'token', 'authorization', 'connectionstring', 'client_secret')

function Protect-StatLogObject {
    param([Parameter(Mandatory)][object]$InputObject)

    $clone = $InputObject | ConvertTo-Json -Depth 10 | ConvertFrom-Json

    function Redact-Recursive($obj) {
        if ($obj -is [System.Management.Automation.PSCustomObject]) {
            foreach ($prop in $obj.PSObject.Properties) {
                if ($script:RedactedFields -contains $prop.Name.ToLower()) {
                    $prop.Value = '***REDACTED***'
                }
                elseif ($prop.Value -is [System.Management.Automation.PSCustomObject] -or $prop.Value -is [array]) {
                    Redact-Recursive $prop.Value
                }
            }
        }
        elseif ($obj -is [array]) {
            foreach ($item in $obj) { Redact-Recursive $item }
        }
    }

    Redact-Recursive $clone
    return $clone
}

function Write-StatLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Level = 'Information',
        [object]$Data
    )

    $entry = @{
        message = $Message
        level   = $Level
        module  = $env:FUNCTION_NAME
    }
    if ($Data) {
        $entry.data = Protect-StatLogObject -InputObject $Data
    }

    Write-Host ($entry | ConvertTo-Json -Depth 10 -Compress)
}

Export-ModuleMember -Function Write-StatLog, Protect-StatLogObject
