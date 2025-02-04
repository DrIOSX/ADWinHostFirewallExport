<#
    .SYNOPSIS
        Retrieves the firewall status of a local or remote machine.
    .DESCRIPTION
        This function retrieves the firewall status for either a local or remote machine.
        It gathers firewall profile details including domain, private, and public profiles.
    .PARAMETER ComputerName
        The name(s) of the remote computer(s) to retrieve firewall status from.
    .PARAMETER Local
        Use this switch to retrieve firewall status from the local machine.
    .EXAMPLE
        Get-ADHostFirewallStatus -ComputerName "Server01"
        Retrieves firewall status from the remote machine "Server01".
    .EXAMPLE
        Get-ADHostFirewallStatus -Local
        Retrieves firewall status from the local machine.
    .OUTPUTS
        PSCustomObject. Each object contains firewall profile settings.
    .NOTES
        Requires administrative privileges to execute.
#>
function Get-ADHostFirewallStatus {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        DefaultParameterSetName = 'Remote',
        ConfirmImpact = 'Low'
    )]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Remote'
        )]
        [string[]]$ComputerName,
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Local'
        )]
        [switch]$Local
    )
    begin {
        Write-TimestampedMessage 'Initializing Get-ADHostFirewallStatus function.'
        Write-Progress -Activity 'Initializing' -Status 'Preparing to query firewall status...' -PercentComplete 0
        $results = New-Object System.Collections.Generic.List[Object]
        $totalComputers = $ComputerName.Count
        $count = 0
    }
    process {
        try {
            if ($PSCmdlet.ShouldProcess('Firewall Status', 'Retrieve firewall information')) {
                switch ($PSCmdlet.ParameterSetName) {
                    'Remote' {
                        Write-TimestampedMessage "Retrieving firewall status for remote machines: $($ComputerName -join ', ')"
                        foreach ($server in $ComputerName) {
                            $count++
                            $percentComplete = [math]::Round(($count / $totalComputers) * 100)
                            Write-Progress -Activity 'Retrieving Firewall Status' -Status "Processing $server ($count of $totalComputers)" -PercentComplete $percentComplete
                            Write-TimestampedMessage "Processing machine: $server"
                            try {
                                $result = Invoke-Command -ComputerName $server -ScriptBlock {
                                    $profiles = Get-NetFirewallProfile | Group-Object -Property Name -AsHashTable -AsString
                                    [PSCustomObject]@{
                                        ComputerName                = $env:COMPUTERNAME
                                        Domain_Enabled              = $profiles.Domain.Enabled
                                        Domain_LogFileName          = $profiles.Domain.LogFileName
                                        Domain_LogMaxSizeKilobytes  = $profiles.Domain.LogMaxSizeKilobytes
                                        Domain_LogAllowed           = $profiles.Domain.LogAllowed
                                        Domain_LogBlocked           = $profiles.Domain.LogBlocked
                                        # Private
                                        Private_Enabled             = $profiles.Private.Enabled
                                        Private_LogFileName         = $profiles.Private.LogFileName
                                        Private_LogMaxSizeKilobytes = $profiles.Private.LogMaxSizeKilobytes
                                        Private_LogAllowed          = $profiles.Private.LogAllowed
                                        Private_LogBlocked          = $profiles.Private.LogBlocked
                                        # Public
                                        Public_Enabled              = $profiles.Public.Enabled
                                        Public_LogFileName          = $profiles.Public.LogFileName
                                        Public_LogMaxSizeKilobytes  = $profiles.Public.LogMaxSizeKilobytes
                                        Public_LogAllowed           = $profiles.Public.LogAllowed
                                        Public_LogBlocked           = $profiles.Public.LogBlocked
                                    }
                                } -ErrorAction Stop
                                $cleanResult = $result | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
                                $results.Add($cleanResult) | Out-Null
                            }
                            catch {
                                throw "Error retrieving firewall status from $server`: $($_.Exception.Message)"
                            }
                        }
                    }
                    'Local' {
                        Write-TimestampedMessage 'Retrieving firewall status for the local machine.'
                        try {
                            Write-Progress -Activity 'Retrieving Firewall Status' -Status 'Processing Local Machine' -PercentComplete 100
                            $profiles = Get-NetFirewallProfile | Group-Object -Property Name -AsHashTable -AsString
                            $localResult = [PSCustomObject]@{
                                ComputerName                = $env:COMPUTERNAME
                                Domain_Enabled              = $profiles.Domain.Enabled
                                Domain_LogFileName          = $profiles.Domain.LogFileName
                                Domain_LogMaxSizeKilobytes  = $profiles.Domain.LogMaxSizeKilobytes
                                Domain_LogAllowed           = $profiles.Domain.LogAllowed
                                Domain_LogBlocked           = $profiles.Domain.LogBlocked
                                # Private
                                Private_Enabled             = $profiles.Private.Enabled
                                Private_LogFileName         = $profiles.Private.LogFileName
                                Private_LogMaxSizeKilobytes = $profiles.Private.LogMaxSizeKilobytes
                                Private_LogAllowed          = $profiles.Private.LogAllowed
                                Private_LogBlocked          = $profiles.Private.LogBlocked
                                # Public
                                Public_Enabled              = $profiles.Public.Enabled
                                Public_LogFileName          = $profiles.Public.LogFileName
                                Public_LogMaxSizeKilobytes  = $profiles.Public.LogMaxSizeKilobytes
                                Public_LogAllowed           = $profiles.Public.LogAllowed
                                Public_LogBlocked           = $profiles.Public.LogBlocked
                            }
                            $results.Add($localResult) | Out-Null
                        }
                        catch {
                            throw "Error retrieving local firewall status: $($_.Exception.Message)"
                        }
                    }
                }
            }
            else {
                throw 'Operation canceled by ShouldProcess check.'
            }
        }
        catch {
            throw "Unexpected error: $($_.Exception.Message)"
        }
    }
    end {
        Write-Progress -Activity 'Retrieving Firewall Status' -Status 'Completed processing all hosts.' -Completed
        return $results
    }
}