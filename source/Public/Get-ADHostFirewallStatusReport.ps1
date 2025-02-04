<#
    .SYNOPSIS
        Retrieves firewall status and manageability information for specified hosts.
    .DESCRIPTION
        This function retrieves firewall status and evaluates remote manageability
        for a list of specified computers. It determines if each host is remotely
        accessible via WS-Management (WinRM) and retrieves firewall configuration settings
        for accessible hosts. If a host is unreachable, "N/A" values are assigned to firewall properties.
    .PARAMETER ComputerName
        Specifies one or more computer names from which to retrieve firewall status
        and manageability information. The function expects an array of computer names.
    .EXAMPLE
        Get-ADHostFirewallStatusReport -ComputerName "Server01"
        Retrieves firewall status and manageability details for "Server01".
    .EXAMPLE
        $activeServers = Get-ADHostManageability -DaysInactive 30 -Servers
        Get-ADHostFirewallStatusReport -ComputerName $activeServers.ComputerName
        Retrieves firewall status for all Active Directory servers that were active within the last 30 days.
    .EXAMPLE
        Get-ADHostFirewallStatusReport -ComputerName @("Workstation01", "Workstation02")
        Retrieves firewall status and manageability details for the specified workstations.
    .OUTPUTS
        PSCustomObject. Each object contains:

        - ComputerName               : The name of the remote host.
        - IPAddress                  : The detected network address (if available).
        - IsRemotable                : Indicates if the host is reachable via WS-Management.
        - Domain_Enabled             : Firewall status for the Domain profile.
        - Domain_LogFileName         : The log file path for the Domain profile.
        - Domain_LogMaxSizeKilobytes : The maximum log file size for the Domain profile.
        - Domain_LogAllowed          : Indicates if allowed traffic is logged in the Domain profile.
        - Domain_LogBlocked          : Indicates if blocked traffic is logged in the Domain profile.
        - Private_Enabled            : Firewall status for the Private profile.
        - Private_LogFileName        : The log file path for the Private profile.
        - Private_LogMaxSizeKilobytes: The maximum log file size for the Private profile.
        - Private_LogAllowed         : Indicates if allowed traffic is logged in the Private profile.
        - Private_LogBlocked         : Indicates if blocked traffic is logged in the Private profile.
        - Public_Enabled             : Firewall status for the Public profile.
        - Public_LogFileName         : The log file path for the Public profile.
        - Public_LogMaxSizeKilobytes : The maximum log file size for the Public profile.
        - Public_LogAllowed          : Indicates if allowed traffic is logged in the Public profile.
        - Public_LogBlocked          : Indicates if blocked traffic is logged in the Public profile.
    .NOTES
        - This function requires administrative privileges to execute.
        - Hosts must have WS-Management (WinRM) enabled to retrieve firewall settings remotely.
        - If a host is unreachable, firewall properties are set to "N/A".
        - The function updates progress dynamically as hosts are processed.
    .TROUBLESHOOTING NOTE
        - Ensure that the firewall allows remote management.
        - If a host is reported as unreachable, confirm network connectivity and the
          WS-Management service status.
        - If WinRM is disabled, enable it using: `Enable-PSRemoting -Force`
    .COMPONENT
        Windows Defender Firewall with Advanced Security (NetSecurity module)
    .LINK
        https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile
    .LINK
        https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule
#>


function Get-ADHostFirewallStatusReport {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName
    )
    begin {
        Write-TimestampedMessage 'Initializing Get-ADHostFirewallStatusReport function.'
        Write-Progress -Activity "Initializing" -Status "Preparing to retrieve firewall information..." -PercentComplete 0
    }
    process {
        if ($PSCmdlet.ShouldProcess("Hosts", "Retrieve manageability and firewall status")) {
            try {
                $totalHosts = $ComputerName.Count
                $count = 0
                $results = foreach ($host in $ComputerName) {
                    $count++
                    $percentComplete = [math]::Round(($count / $totalHosts) * 100)
                    Write-TimestampedMessage "Processing: $host"
                    # Test manageability using Test-WSMan
                    $testRemoting = Test-WSMan -ComputerName $host -ErrorAction SilentlyContinue
                    $isRemotable = $null -ne $testRemoting
                    if ($isRemotable) {
                        try {
                            # ✅ **Update progress BEFORE firewall query**
                            Write-Progress -Activity "Retrieving Firewall Status" -Status "Querying $host firewall settings..." -PercentComplete $percentComplete
                            Write-TimestampedMessage "Host $host is remotely accessible. Retrieving firewall status..."
                            $fwResult = Get-ADHostFirewallStatus -ComputerName $host
                            $fw = $fwResult[0]  # Expecting a single object
                            [PSCustomObject]@{
                                ComputerName                = $host
                                IPAddress                   = $testRemoting.NetworkAddress
                                IsRemotable                 = $isRemotable
                                Domain_Enabled              = $fw.Domain_Enabled
                                Domain_LogFileName          = $fw.Domain_LogFileName
                                Domain_LogMaxSizeKilobytes  = $fw.Domain_LogMaxSizeKilobytes
                                Domain_LogAllowed           = $fw.Domain_LogAllowed
                                Domain_LogBlocked           = $fw.Domain_LogBlocked
                                # Private
                                Private_Enabled             = $fw.Private_Enabled
                                Private_LogFileName         = $fw.Private_LogFileName
                                Private_LogMaxSizeKilobytes = $fw.Private_LogMaxSizeKilobytes
                                Private_LogAllowed          = $fw.Private_LogAllowed
                                Private_LogBlocked          = $fw.Private_LogBlocked
                                # Public
                                Public_Enabled              = $fw.Public_Enabled
                                Public_LogFileName          = $fw.Public_LogFileName
                                Public_LogMaxSizeKilobytes  = $fw.Public_LogMaxSizeKilobytes
                                Public_LogAllowed           = $fw.Public_LogAllowed
                                Public_LogBlocked           = $fw.Public_LogBlocked
                            }
                        }
                        catch {
                            throw "Error retrieving firewall status for $host`: $($_.Exception.Message)"
                        }
                    }
                    else {
                        Write-TimestampedMessage "Host $host is NOT remotely accessible. Assigning 'N/A' values."
                        [PSCustomObject]@{
                            ComputerName                = $host
                            IPAddress                   = 'N/A'
                            IsRemotable                 = $isRemotable
                            Domain_Enabled              = 'N/A'
                            Domain_LogFileName          = 'N/A'
                            Domain_LogMaxSizeKilobytes  = 'N/A'
                            Domain_LogAllowed           = 'N/A'
                            Domain_LogBlocked           = 'N/A'
                            # Private
                            Private_Enabled             = 'N/A'
                            Private_LogFileName         = 'N/A'
                            Private_LogMaxSizeKilobytes = 'N/A'
                            Private_LogAllowed          = 'N/A'
                            Private_LogBlocked          = 'N/A'
                            # Public
                            Public_Enabled              = 'N/A'
                            Public_LogFileName          = 'N/A'
                            Public_LogMaxSizeKilobytes  = 'N/A'
                            Public_LogAllowed           = 'N/A'
                            Public_LogBlocked           = 'N/A'
                        }
                    }
                }
                Write-Progress -Activity "Processing Hosts" -Status "Completed processing hosts." -Completed
            }
            catch {
                Write-Progress -Activity "Processing Hosts" -Status "Error encountered. See logs." -Completed
                throw "Error retrieving host manageability and firewall status: $($_.Exception.Message)"
            }
        }
        else {
            Write-TimestampedMessage "Operation canceled by ShouldProcess."
        }
    }
    end {
        Write-Progress -Activity "Finalizing" -Status "Returning results..." -PercentComplete 100 -Completed
        Write-TimestampedMessage "End of Get-ADHostFirewallStatusReport function."
        return $results
    }
}

