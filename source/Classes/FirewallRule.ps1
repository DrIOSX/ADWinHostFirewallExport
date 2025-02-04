class FirewallRule {
    [string]$ComputerName
    [string]$Group
    [string]$DisplayName
    [string]$FWProfile
    [bool]$IsDomain
    [bool]$IsPrivate
    [bool]$IsPublic
    [bool]$IsAny
    [string]$Action
    [bool]$Enabled
    [string]$Direction
    [string]$Protocol
    [string]$LocalPort
    [string]$LocalAddress
    [string]$RemoteAddress
    [string]$Program

    FirewallRule([string]$computerName, [string]$group, [string]$displayName,
        [string]$FWProfile, [bool]$isDomain, [bool]$isPrivate, [bool]$isPublic,
        [bool]$isAny, [string]$action, [bool]$enabled, [string]$direction,
        [string]$protocol, [string]$localPort, [string]$localAddress, [string]$remoteAddress, [string]$program) {

        $this.ComputerName = $computerName
        $this.Group = $group
        $this.DisplayName = $displayName
        $this.FWProfile = $FWProfile
        $this.IsDomain = $isDomain
        $this.IsPrivate = $isPrivate
        $this.IsPublic = $isPublic
        $this.IsAny = $isAny
        $this.Action = $action
        $this.Enabled = $enabled
        $this.Direction = $direction
        $this.Protocol = $protocol
        $this.LocalPort = $localPort
        $this.LocalAddress = $localAddress
        $this.RemoteAddress = $remoteAddress
        $this.Program = $program
    }
}
