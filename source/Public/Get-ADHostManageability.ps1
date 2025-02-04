<#
    .SYNOPSIS
        Retrieves Active Directory computers and determines their manageability.
    .DESCRIPTION
        Queries Active Directory for computers based on the specified criteria.
        Checks whether each computer is remotely manageable via WS-Man.
    .PARAMETER DaysInactive
        The number of days since the last logon timestamp to consider a computer active.
    .PARAMETER Servers
        If specified, filters results to include only servers.
    .PARAMETER Workstations
        If specified, filters results to include only workstations.
    .PARAMETER OperatingSystemSearchString
        A custom operating system search string to filter results.
    .PARAMETER SearchBase
        The LDAP search base to limit the query scope.
    .EXAMPLE
        Get-ADHostManageability -DaysInactive 60 -Servers
        Retrieves all servers active within the last 60 days.
    .EXAMPLE
        Get-ADHostManageability -Workstations -OperatingSystemSearchString "Windows 10"
        Retrieves all Windows 10 workstations that are considered active.
    .OUTPUTS
        PSCustomObject. Each object contains host details and manageability status.
    .NOTES
        Requires Active Directory module and administrative privileges.
#>
function Get-ADHostManageability {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [int]$DaysInactive = 90,
        [Parameter()]
        [switch]$Servers,
        [Parameter()]
        [switch]$Workstations,
        [Parameter()]
        [string]$OperatingSystemSearchString,
        [Parameter()]
        [string]$SearchBase
    )
    begin {
        Write-TimestampedMessage 'Initializing Get-ADHostManageability function.'
        Write-Progress -Activity 'Initializing' -Status 'Setting up search filters...' -PercentComplete 0
        $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
        Write-TimestampedMessage "Searching for Active Directory computers active since $cutoffDate"
        # Determine search pattern for OS filtering
        if ($Servers) {
            $searchPattern = '*server*'
        }
        elseif ($Workstations) {
            $searchPattern = '*windows 1*'
        }
        elseif ($OperatingSystemSearchString) {
            $searchPattern = "*$OperatingSystemSearchString*"
        }
        else {
            $searchPattern = '*'
        }
        Write-TimestampedMessage "Operating system search pattern: $searchPattern"
    }
    process {
        if ($PSCmdlet.ShouldProcess('Active Directory Computers', 'Retrieve AD computer objects')) {
            try {
                Write-Progress -Activity 'Querying Active Directory' -Status 'Retrieving computer objects...' -PercentComplete 10
                if ($SearchBase) {
                    Write-TimestampedMessage "Using SearchBase: $SearchBase"
                    $allComputers = Get-ADComputer -SearchBase $SearchBase `
                        -Filter { LastLogonTimeStamp -gt $cutoffDate } `
                        -Properties ipv4Address, OperatingSystem, LastLogonTimeStamp `
                        -ErrorAction Stop
                }
                else {
                    Write-TimestampedMessage "Querying all AD computers with OS filter: $searchPattern"
                    $allComputers = Get-ADComputer -Filter {
                        (LastLogonTimeStamp -gt $cutoffDate) -and
                        (OperatingSystem -like $searchPattern)
                    } -Properties ipv4Address, OperatingSystem, LastLogonTimeStamp `
                        -ErrorAction Stop
                }
                Write-TimestampedMessage "Found $($allComputers.Count) matching computers."
                if ($allComputers.Count -eq 0) {
                    Write-Progress -Activity 'Querying Active Directory' -Status 'No hosts found. Ending process.' -Completed
                    return
                }
                # Process each AD computer to check manageability
                $totalComputers = $allComputers.Count
                $count = 0
                $results = foreach ($comp in $allComputers) {
                    $count++
                    $percentComplete = [math]::Round(($count / $totalComputers) * 100)
                    Write-Progress -Activity 'Checking Manageability' -Status "Checking WS-Man access for $($comp.Name)..." -PercentComplete $percentComplete
                    Write-TimestampedMessage "Checking WS-Man access for $($comp.Name)"
                    $testRemoting = Test-WSMan -ComputerName $comp.Name -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        ComputerName       = $comp.Name
                        IPAddress          = $comp.IPv4Address
                        OperatingSystem    = $comp.OperatingSystem
                        LastLogonTimeStamp = [DateTime]::FromFileTime($comp.LastLogonTimeStamp)
                        IsRemotable        = $null -ne $testRemoting
                    }
                }
                Write-Progress -Activity 'Checking Manageability' -Status 'Completed manageability check.' -Completed
            }
            catch {
                Write-Progress -Activity 'Checking Manageability' -Status 'Error encountered. See logs.' -Completed
                throw "Error retrieving AD computers: $($_.Exception.Message)"
            }
        }
        else {
            Write-TimestampedMessage 'Operation canceled by ShouldProcess.'
        }
    }
    end {
        Write-Progress -Activity 'Finalizing' -Status 'Returning results...' -PercentComplete 100 -Completed
        return $results
    }
}
