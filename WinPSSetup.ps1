# irm 'https://github.com/jorgeasaurus/powershell-profile/raw/main/WinPSSetup.ps1' | iex
$ScriptUrl = 'https://github.com/jorgeasaurus/powershell-profile/raw/main/WinPSSetup.ps1'  # Set this to where you host this script

# Bootstrap to PowerShell Core
if ($PSVersionTable.PSEdition -ne 'Core') {
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        winget install -e --id Microsoft.PowerShell --accept-package-agreements --accept-source-agreements
        # Refresh PATH in current session
        $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')
    }
    
    pwsh -NoProfile -ExecutionPolicy Bypass -Command "irm '$ScriptUrl' | iex"
    exit
}

# === Core-only execution below ===
winget install -e --id Microsoft.Sysinternals.PsTools --accept-package-agreements --accept-source-agreements
irm "https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1" | iex
irm https://raw.githubusercontent.com/jorgeasaurus/cmtrace/refs/heads/main/New-CMTraceSymLink.ps1 | iex