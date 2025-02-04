# Ensure C# class is loaded before module functions
if (-not ("ResourceStringResolver" -as [type])) {
    $csFilePath = Join-Path $PSScriptRoot "Types\ResourceStringResolver.cs"

    if (Test-Path $csFilePath) {
        Write-Verbose "Compiling and loading C# class from: $csFilePath"
        Add-Type -Path $csFilePath -ErrorAction Stop
    }
    else {
        Write-Warning "C# file not found: $csFilePath. Resource string resolution may not work."
    }
}
