<#
    .SYNOPSIS
        Resolves a firewall resource string to its actual value.
    .DESCRIPTION
        This function takes a firewall resource string (e.g., "@C:\Windows\System32\firewallapi.dll,-28546")
        and resolves it to a human-readable string using the ResourceStringResolver class.
    .PARAMETER ResourceString
        The resource string to resolve. Can be null or empty.
    .EXAMPLE
        Resolve-FirewallResourceString -ResourceString "@C:\Windows\System32\firewallapi.dll,-28546"
        Returns the resolved string.
    .OUTPUTS
        [string] - The resolved firewall resource string.
    .NOTES
        This function relies on the ResourceStringResolver C# class.
#>
function Resolve-FirewallResourceString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$ResourceString
    )
    try {
        # If input is null or empty, return it as-is
        if ([string]::IsNullOrWhiteSpace($ResourceString)) {
            Write-TimestampedMessage "Resource string is null or empty. Returning as-is."
            return $ResourceString
        }
        Write-TimestampedMessage "Resolving firewall resource string: $ResourceString"
        # Call the C# method to resolve
        $resolvedString = [ResourceStringResolver]::GetString($ResourceString)
        Write-TimestampedMessage "Resolved string: $resolvedString"
        return $resolvedString
    }
    catch {
        Write-Warning "Failed to resolve resource string: $ResourceString. Returning input value."
        return $ResourceString
    }
}
