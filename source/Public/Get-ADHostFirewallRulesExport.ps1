<#
    .SYNOPSIS
        Retrieves firewall rules from remote machines with filtering options.
    .DESCRIPTION
        This function collects firewall rules from the specified remote computers.
        It allows filtering based on rule status (Enabled, Disabled, or All)
        and direction (Inbound, Outbound, or All).
        Additionally, it resolves rule group names, includes protocol and port information,
        and retrieves associated program paths, local addresses, and remote addresses.
    .PARAMETER ComputerName
        Specifies one or more remote computers from which to retrieve firewall rules.
    .PARAMETER RuleStatus
        Specifies which firewall rules to retrieve based on their enabled status.
        Options:
        - "All"       : Retrieves all firewall rules (enabled and disabled).
        - "Enabled"   : Retrieves only enabled firewall rules (Default).
        - "Disabled"  : Retrieves only disabled firewall rules.
    .PARAMETER Direction
        Specifies the direction of firewall rules to retrieve.
        Options:
        - "All"       : Retrieves both inbound and outbound rules.
        - "Inbound"   : Retrieves only inbound firewall rules (Default).
        - "Outbound"  : Retrieves only outbound firewall rules.
    .EXAMPLE
        Get-ADHostFirewallRulesExport -ComputerName "Server01"
        Retrieves only enabled inbound firewall rules from "Server01" (default behavior).
    .EXAMPLE
        Get-ADHostFirewallRulesExport -ComputerName "Server01" -RuleStatus All -Direction Outbound
        Retrieves all outbound firewall rules from "Server01".
    .EXAMPLE
        Get-ADHostFirewallRulesExport -ComputerName "Server01", "Server02" -RuleStatus Disabled
        Retrieves only disabled inbound firewall rules from both "Server01" and "Server02".
    .EXAMPLE
        "Server01", "Server02" | Get-ADHostFirewallRulesExport -Direction All
        Retrieves both inbound and outbound enabled firewall rules from "Server01" and "Server02".
    .OUTPUTS
        [FirewallRule] (Custom Class).
        Each object contains details about a firewall rule, including:

        - ComputerName    : The remote host where the firewall rule is applied.
        - Group          : The resolved name of the firewall rule group.
        - DisplayName    : The display name of the firewall rule.
        - FWProfile      : The firewall profile(s) associated with the rule.
        - IsDomain       : Indicates whether the rule applies to the domain profile.
        - IsPrivate      : Indicates whether the rule applies to the private profile.
        - IsPublic       : Indicates whether the rule applies to the public profile.
        - IsAny          : Indicates if the rule applies to all profiles.
        - Action         : Whether the rule allows or blocks traffic.
        - Enabled        : Indicates whether the rule is enabled.
        - Direction      : Whether the rule applies to inbound or outbound traffic.
        - Protocol       : The protocol associated with the firewall rule.
        - LocalPort      : The local port(s) affected by the rule.
        - LocalAddress   : The local IP addresses affected by the rule.
        - RemoteAddress  : The remote IP addresses affected by the rule.
        - Program        : The executable associated with the firewall rule (if applicable).
    .NOTES
        - Requires administrative privileges on remote machines.
        - Uses Invoke-Command to query firewall rules remotely.
        - Resolves localized firewall rule group names where applicable.
        - Optimized to retrieve address filters and application filters in batch.
        - Uses lookup tables to efficiently map rule instance IDs to addresses and programs.
    .COMPONENT
        Windows Defender Firewall with Advanced Security (NetSecurity module)
    .LINK
        https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule
    .LINK
        https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter
    .LINK
        https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter
#>

function Get-ADHostFirewallRulesExport {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([FirewallRule])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName,
        [Parameter()]
        [ValidateSet('All', 'Enabled', 'Disabled')]
        [string]$RuleStatus = 'Enabled',
        [Parameter()]
        [ValidateSet('All', 'Inbound', 'Outbound')]
        [string]$Direction = 'Inbound'
    )
    begin {
        Write-TimestampedMessage 'Initializing Get-ADHostFirewallRulesExport function.'
        $results = [System.Collections.Generic.List[FirewallRule]]::new()
        # Load C# class for resolving resource strings
        #$resolverDefinition = Get-Content -Path (Join-Path $PSScriptRoot 'Types\ResourceStringResolver.cs') -Raw
        $resolverDefinition = [ResourceStringResolver]::SourceCode
    }
    process {
        $total = $ComputerName.Count
        $count = 0
        foreach ($server in $ComputerName) {
            $count++
            Write-Progress -Activity 'Retrieving Firewall Rules' `
                -Status "Processing: $server ($count of $total)" `
                -PercentComplete (($count / $total) * 100)
            if ($PSCmdlet.ShouldProcess($server, 'Retrieve firewall rules')) {
                Write-TimestampedMessage "Processing firewall rules for: $server"
                try {
                    # Invoke command with the resolver type definition
                    $remoteData = Invoke-Command -ComputerName $server -ScriptBlock {
                        param($RuleStatus, $Direction, $resolverDefinition)
                        # Ensure NetSecurity is imported
                        Import-Module NetSecurity -ErrorAction Continue
                        # Load ResourceStringResolver if not already defined
                        if (-not ("ResourceStringResolver" -as [type])) {
                            Add-Type -TypeDefinition $resolverDefinition -Language CSharp
                        }
                        # Convert RuleStatus into string values for filtering
                        $enabledValue = switch ($RuleStatus) {
                            'Enabled' { $true }
                            'Disabled' { $false }
                            default { $null }   # "All"
                        }
                        # Retrieve all firewall rules once
                        $firewallRules = Get-NetFirewallRule
                        if ($null -ne $enabledValue) {
                            $firewallRules = $firewallRules | Where-Object { $_.Enabled -eq $enabledValue }
                        }
                        if ($Direction -ne 'All') {
                            $firewallRules = $firewallRules | Where-Object { $_.Direction -eq $Direction }
                        }
                        # Retrieve all address filters once
                        $addressFilters = Get-NetFirewallAddressFilter -All
                        # Retrieve all application filters once
                        $applicationFilters = Get-NetFirewallApplicationFilter -All
                        # Create lookup tables
                        $addressLookup = @{}
                        foreach ($filter in $addressFilters) {
                            $addressLookup[$filter.InstanceID] = @{
                                LocalAddress  = $filter.LocalAddress
                                RemoteAddress = $filter.RemoteAddress
                            }
                        }
                        $appLookup = @{}
                        foreach ($appFilter in $applicationFilters) {
                            $appLookup[$appFilter.InstanceID] = $appFilter.Program
                        }
                        $resolvedRules = @()
                        foreach ($rule in $firewallRules) {
                            # For port/protocol info
                            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                            # Resolve firewall rule group name remotely
                            $resolvedGroup = [ResourceStringResolver]::GetString($rule.Group)
                            # Convert FWProfile array to a comma-separated string
                            $profileList = $rule.Profile -join ', '
                            # Handle profile conditions correctly
                            $isDomain  = $rule.Profile -contains 'Domain'
                            $isPrivate = $rule.Profile -contains 'Private'
                            $isPublic  = $rule.Profile -contains 'Public'
                            # If 'Any' is in the profile list, assume all profiles apply
                            if ($rule.Profile -contains 'Any') {
                                $isDomain  = $true
                                $isPrivate = $true
                                $isPublic  = $true
                            }
                            $isAny = $isDomain -and $isPrivate -and $isPublic
                            # Get the associated addresses
                            $localAddress  = 'Any'
                            $remoteAddress = 'Any'
                            if ($addressLookup.ContainsKey($rule.InstanceID)) {
                                $localAddress  = $addressLookup[$rule.InstanceID].LocalAddress
                                $remoteAddress = $addressLookup[$rule.InstanceID].RemoteAddress
                            }
                            # Get the associated program
                            $program = 'N/A'
                            if ($appLookup.ContainsKey($rule.InstanceID)) {
                                $program = $appLookup[$rule.InstanceID]
                            }
                            # Build the resolved rule object
                            $resolvedRules += [PSCustomObject]@{
                                Group        = $resolvedGroup
                                DisplayName  = $rule.DisplayName
                                FWProfile    = $profileList
                                IsDomain     = $isDomain
                                IsPrivate    = $isPrivate
                                IsPublic     = $isPublic
                                IsAny        = $isAny
                                Action       = $rule.Action
                                Enabled      = $rule.Enabled
                                Direction    = $rule.Direction
                                Protocol     = $portFilter.Protocol
                                LocalPort    = $portFilter.LocalPort
                                LocalAddress = $localAddress
                                RemoteAddress = $remoteAddress
                                Program      = $program
                            }
                        }
                        return $resolvedRules
                    } -ArgumentList $RuleStatus, $Direction, $resolverDefinition -ErrorAction Stop
                    # Convert the PSCustomObjects from remote to FirewallRule objects locally
                    foreach ($ruleObj in $remoteData) {
                        $firewallRule = [FirewallRule]::new(
                            $server,
                            $ruleObj.Group,
                            $ruleObj.DisplayName,
                            $ruleObj.FWProfile,
                            $ruleObj.IsDomain,
                            $ruleObj.IsPrivate,
                            $ruleObj.IsPublic,
                            $ruleObj.IsAny,
                            $ruleObj.Action,
                            [System.Convert]::ToBoolean($ruleObj.Enabled),
                            $ruleObj.Direction,
                            $ruleObj.Protocol,
                            $ruleObj.LocalPort,
                            $ruleObj.LocalAddress,
                            $ruleObj.RemoteAddress,
                            $ruleObj.Program
                        )
                        [void]$results.Add($firewallRule)
                    }
                }
                catch {
                    Write-Warning "Error retrieving firewall rules from $server`: $($_.Exception.Message)"
                }
            }
            else {
                Write-TimestampedMessage "Operation canceled for $server"
            }
        }
        Write-Progress -Activity 'Retrieving Firewall Rules' -Completed
    }
    end {
        Write-TimestampedMessage 'Returning results for Get-ADHostFirewallRulesExport function.'
        return $results
    }
}