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
        winget install -e --id Microsoft.PowerShell --accept-package-agreements --accept-source-agreements --source winget
        $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')
    }
    
    pwsh -NoProfile -ExecutionPolicy Bypass -Command "irm '$ScriptUrl' | iex"
    exit
}

# === Core-only execution below ===
winget install -e --id Microsoft.Sysinternals.PsTools --accept-package-agreements --accept-source-agreements --source winget
Invoke-RestMethod "https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1" | Invoke-Expression
Invoke-RestMethod https://raw.githubusercontent.com/jorgeasaurus/cmtrace/refs/heads/main/New-CMTraceSymLink.ps1 | Invoke-Expression

# Configure Windows Terminal defaults
$wtSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $wtSettingsPath) {
    $settings = Get-Content $wtSettingsPath -Raw | ConvertFrom-Json

    # Find PowerShell Core profile GUID
    $pwshProfile = $settings.profiles.list | Where-Object { $_.name -eq 'PowerShell' -and $_.source -eq 'Windows.Terminal.PowershellCore' }
    if ($pwshProfile) {
        $settings.defaultProfile = $pwshProfile.guid
    }

    # Set default font
    if (-not $settings.profiles.defaults) {
        $settings.profiles | Add-Member -NotePropertyName 'defaults' -NotePropertyValue @{} -Force
    }
    if (-not $settings.profiles.defaults.font) {
        $settings.profiles.defaults | Add-Member -NotePropertyName 'font' -NotePropertyValue @{} -Force
    }
    $settings.profiles.defaults.font | Add-Member -NotePropertyName 'face' -NotePropertyValue 'CaskaydiaCove Nerd Font Mono' -Force
    $settings.profiles.defaults | Add-Member -NotePropertyName 'opacity' -NotePropertyValue 87 -Force
    $settings.profiles.defaults | Add-Member -NotePropertyName 'useAcrylic' -NotePropertyValue $false -Force

    $settings | ConvertTo-Json -Depth 100 | Set-Content $wtSettingsPath -Encoding UTF8
    Write-Host 'Windows Terminal configured: PowerShell Core default, CaskaydiaCove Nerd Font Mono set.' -ForegroundColor Green
} else {
    Write-Warning 'Windows Terminal settings not found. Skipping terminal configuration.'
}
