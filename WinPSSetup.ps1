# irm 'https://github.com/jorgeasaurus/powershell-profile/raw/main/WinPSSetup.ps1' | iex
$ScriptUrl = 'https://github.com/jorgeasaurus/powershell-profile/raw/main/WinPSSetup.ps1'

# Self-elevate if not admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $shell = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
    Start-Process $shell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm '$ScriptUrl' | iex`"" -Verb RunAs
    exit
}

# Bootstrap to PowerShell Core
if ($PSVersionTable.PSEdition -ne 'Core') {
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        winget install -e --id Microsoft.PowerShell --accept-package-agreements --accept-source-agreements
        $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')
    }
    
    pwsh -NoProfile -ExecutionPolicy Bypass -Command "irm '$ScriptUrl' | iex"
    exit
}

# === Core-only execution below ===
winget install -e --id Microsoft.Sysinternals.PsTools --accept-package-agreements --accept-source-agreements
irm "https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1" | iex
irm https://raw.githubusercontent.com/jorgeasaurus/cmtrace/refs/heads/main/New-CMTraceSymLink.ps1 | iex