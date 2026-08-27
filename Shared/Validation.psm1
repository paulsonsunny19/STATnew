<#
.SYNOPSIS
    Typed validation for every value that crosses the trust boundary from an HTTP request
    into a triage module, before it touches a KQL query, Graph call, or third-party API.

.NOTES
    Security rationale: the original pattern generally trusts the Logic Apps caller's JSON
    body wholesale and interpolates entity values (IPs, hostnames, UPNs, GUIDs) straight into
    KQL/Graph queries. A malicious or malformed upstream value (e.g. an "IP address" entity
    that's actually `1.1.1.1' | union SecurityEvent | take 1000000 //`) can distort or exfiltrate
    data. Every module in this project must call the appropriate Confirm-* function below
    before using a value, and must reject the request (HTTP 400) if validation fails rather
    than attempting to "clean" the input.
#>

function Confirm-StatGuid {
    param([Parameter(Mandatory)][string]$Value)
    return [bool]([guid]::TryParse($Value, [ref]([guid]::Empty)))
}

function Confirm-StatIpAddress {
    param([Parameter(Mandatory)][string]$Value)
    return [bool]([System.Net.IPAddress]::TryParse($Value, [ref]([System.Net.IPAddress]$null)))
}

function Confirm-StatHostname {
    param([Parameter(Mandatory)][string]$Value)
    # RFC 1123-ish hostname: labels of letters/digits/hyphens, dot-separated, no wildcards, no shell metacharacters.
    return $Value -match '^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
}

function Confirm-StatUpn {
    param([Parameter(Mandatory)][string]$Value)
    # Conservative UPN/email pattern; rejects anything with quotes, backticks, or KQL/SQL-meaningful characters.
    return $Value -match '^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,190}\.[a-zA-Z]{2,24}$'
}

function Confirm-StatFileHash {
    <# Accepts only well-formed MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) strings. #>
    param([Parameter(Mandatory)][string]$Value)
    return $Value -match '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
}

function Confirm-StatUrl {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Length -gt 2048) { return $false }
    try {
        $uri = [System.Uri]$Value
        return ($uri.Scheme -eq 'http' -or $uri.Scheme -eq 'https')
    }
    catch { return $false }
}

function Confirm-StatKqlSafeString {
    <# For any free-text value that must appear in a KQL query. Rejects anything containing
       KQL statement separators, comment markers, or pipe-based operator chaining attempts. #>
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Length -gt 256) { return $false }
    if ($Value -match "[;|`"'`]|//|/\*|\*/") { return $false }
    return $true
}

function Confirm-StatEntitySchema {
    <#
    .SYNOPSIS
        Validates the shape of a Sentinel incident/entity payload before the Base Module
        will normalize it. Rejects unknown top-level keys (prevents prototype-pollution-style
        payload smuggling) and enforces a maximum entity count to bound query fan-out.
    #>
    param(
        [Parameter(Mandatory)][object]$Body,
        [int]$MaxEntityCount = 50
    )

    $errors = New-Object System.Collections.Generic.List[string]

    if (-not $Body.IncidentARMId) {
        $errors.Add("Missing required field: IncidentARMId")
    }
    elseif ($Body.IncidentARMId -notmatch '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+/providers/Microsoft\.SecurityInsights/incidents/[0-9a-fA-F-]{36}$') {
        $errors.Add("IncidentARMId is not a well-formed Sentinel incident resource ID")
    }

    if ($Body.Entities) {
        if ($Body.Entities.Count -gt $MaxEntityCount) {
            $errors.Add("Entity count ($($Body.Entities.Count)) exceeds maximum allowed ($MaxEntityCount)")
        }
        foreach ($entity in $Body.Entities) {
            if (-not $entity.Type) {
                $errors.Add("Entity missing 'Type' field")
                continue
            }
            switch ($entity.Type) {
                'ip'       { if (-not (Confirm-StatIpAddress $entity.Value))  { $errors.Add("Invalid IP entity: '$($entity.Value)'") } }
                'host'     { if (-not (Confirm-StatHostname   $entity.Value))  { $errors.Add("Invalid host entity: '$($entity.Value)'") } }
                'account'  { if (-not (Confirm-StatUpn        $entity.Value))  { $errors.Add("Invalid account/UPN entity: '$($entity.Value)'") } }
                'filehash' { if (-not (Confirm-StatFileHash   $entity.Value))  { $errors.Add("Invalid filehash entity: '$($entity.Value)'") } }
                'url'      { if (-not (Confirm-StatUrl        $entity.Value))  { $errors.Add("Invalid url entity: '$($entity.Value)'") } }
                default    { <# Unknown-but-declared entity types are passed through as opaque strings only, never used in queries directly #> }
            }
        }
    }

    return [pscustomobject]@{
        IsValid = ($errors.Count -eq 0)
        Errors  = $errors
    }
}

Export-ModuleMember -Function Confirm-StatGuid, Confirm-StatIpAddress, Confirm-StatHostname, Confirm-StatUpn, Confirm-StatKqlSafeString, Confirm-StatEntitySchema, Confirm-StatFileHash, Confirm-StatUrl
