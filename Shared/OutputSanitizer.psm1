<#
.SYNOPSIS
    Sanitizes module output before it's written back into a Sentinel incident comment,
    task, or tag via the playbook.

.NOTES
    Security rationale: incident comments render as markdown in the Sentinel/Defender
    portal. A triage module that reflects an attacker-controlled value (e.g. a hostname or
    URL entity) straight into a comment can inject markdown links, images, or formatting
    that mislead an analyst reviewing the incident (e.g. a fake "this is a false positive"
    styled callout, or a link that looks internal but isn't).
#>

function Protect-StatOutputText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $escaped = $Text `
        -replace '\\', '\\\\' `
        -replace '\[', '\[' `
        -replace '\]', '\]' `
        -replace '\(', '\(' `
        -replace '\)', '\)' `
        -replace '`', '\`' `
        -replace '\*', '\*' `
        -replace '_', '\_' `
        -replace '#', '\#' `
        -replace '<', '&lt;' `
        -replace '>', '&gt;'

    # Cap length so a single field can't blow out the incident comment size or bury the
    # rest of the analyst-facing summary.
    if ($escaped.Length -gt 2000) {
        $escaped = $escaped.Substring(0, 2000) + '... (truncated)'
    }
    return $escaped
}

Export-ModuleMember -Function Protect-StatOutputText
