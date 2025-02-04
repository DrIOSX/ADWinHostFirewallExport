function Write-TimestampedMessage {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter()]
        [ValidateSet("Verbose", "Warning", "Error", "Info", "Debug")]
        [string]$Type = "Verbose"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.ffff"
    switch ($Type) {
        "Verbose" { Write-Verbose "[$timestamp] $Message" }
        "Warning" { Write-Warning "[$timestamp] $Message" }
        "Error"   { Write-Error "[$timestamp] $Message" }
        "Info"    { Write-Information "[$timestamp] $Message" }
        "Debug"   { Write-Debug "[$timestamp] $Message" }
        default   { Write-Host "[$timestamp] $Message" }
    }
}
