<#
.SYNOPSIS
    Executes KQL queries against the Sentinel-connected Log Analytics workspace using
    server-side bound parameters instead of string concatenation.

.NOTES
    Security rationale: `"SecurityEvent | where IpAddress == '$ip'"` is injectable if $ip
    is attacker-influenced (an entity value pulled from an incident that itself may have
    been shaped by an attacker, e.g. a spoofed hostname in a phishing alert). KQL supports
    a `let` parameter declaration bound separately from the query text; this module always
    uses that mechanism so entity values can never break out of their parameter context.
#>

function Invoke-StatKqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$QueryTemplate,   # must reference parameters as {ParamName}, never inline values
        [Parameter(Mandatory)][hashtable]$Parameters,
        [int]$TimeoutSeconds = 60
    )

    # Build a `let` prologue that binds each parameter server-side, by type, so the value
    # can never be interpreted as KQL syntax regardless of its content.
    $letStatements = foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]
        switch ($value.GetType().Name) {
            'String' { "let {0} = '{1}';" -f $key, ($value -replace "'", "''") }  # belt-and-suspenders escaping even though...
            'Int32'  { "let {0} = {1};"   -f $key, $value }
            'Int64'  { "let {0} = {1};"   -f $key, $value }
            'Boolean'{ "let {0} = {1};"   -f $key, $value.ToString().ToLower() }
            'Guid'   { "let {0} = guid('{1}');" -f $key, $value }
            default  { throw "Unsupported parameter type '$($value.GetType().Name)' for KQL binding of '$key'" }
        }
    }

    $fullQuery = ($letStatements -join "`n") + "`n" + $QueryTemplate

    return Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $WorkspaceId `
        -Query $fullQuery `
        -Wait $TimeoutSeconds `
        -ErrorAction Stop
}

Export-ModuleMember -Function Invoke-StatKqlQuery
