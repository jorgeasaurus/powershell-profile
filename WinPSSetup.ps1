# irm 'https://github.com/jorgeasaurus/powershell-profile/raw/main/WinPSSetup.ps1' | iex
$ScriptUrl = 'https://github.com/jorgeasaurus/powershell-profile/raw/main/WinPSSetup.ps1'
$ErrorActionPreference = 'Stop'

function Write-Status {
    param([string]$Message, [string]$Type = 'Info')
    $color = switch ($Type) {
        'Success' { 'Green' }
        'Error' { 'Red' }
        'Warning' { 'Yellow' }
        default { 'Cyan' }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
}

function Test-InternetConnection {
    Write-Status "Testing internet connectivity..."
    try {
        $null = Test-Connection -ComputerName 8.8.8.8 -Count 1 -ErrorAction Stop
        Write-Status "Internet connection verified" -Type Success
        return $true
    } catch {
        Write-Status "No internet connection detected. Please check your network." -Type Error
        return $false
    }
}

function Install-WinGetIfMissing {
    Write-Status "Checking for WinGet..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Status "WinGet not found. Installing App Installer..." -Type Warning
        try {
            # Install App Installer from Microsoft Store
            $progressPreference = 'silentlyContinue'
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
            Write-Status "WinGet installed successfully" -Type Success

            # Refresh PATH
            $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')
        } catch {
            Write-Status "Failed to install WinGet: $_" -Type Error
            throw
        }
    } else {
        Write-Status "WinGet is already installed" -Type Success
    }
}

# Self-elevate if not admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Status "Requesting administrator privileges..." -Type Warning
    try {
        $shell = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }
        Start-Process $shell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm '$ScriptUrl' | iex`"" -Verb RunAs
        exit
    } catch {
        Write-Status "Failed to elevate privileges. Please run as administrator." -Type Error
        exit 1
    }
}

Write-Status "Running as Administrator" -Type Success

# Test internet connection
if (-not (Test-InternetConnection)) {
    exit 1
}

# Ensure WinGet is available
Install-WinGetIfMissing

# Bootstrap to PowerShell Core
if ($PSVersionTable.PSEdition -ne 'Core') {
    Write-Status "Bootstrapping to PowerShell Core..."
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        Write-Status "Installing PowerShell Core via WinGet..."
        try {
            winget install -e --id Microsoft.PowerShell --accept-package-agreements --accept-source-agreements --source winget --silent
            Write-Status "PowerShell Core installed" -Type Success

            # Refresh PATH
            $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')

            # Verify installation
            if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
                Write-Status "PowerShell Core installation failed. Please install manually." -Type Error
                exit 1
            }
        } catch {
            Write-Status "Failed to install PowerShell Core: $_" -Type Error
            exit 1
        }
    } else {
        Write-Status "PowerShell Core already installed" -Type Success
    }

    Write-Status "Relaunching in PowerShell Core..."
    pwsh -NoProfile -ExecutionPolicy Bypass -Command "irm '$ScriptUrl' | iex"
    exit
}

Write-Status "Running in PowerShell Core" -Type Success

# Set execution policy
try {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Write-Status "Execution policy set" -Type Success
} catch {
    Write-Status "Failed to set execution policy: $_" -Type Warning
}

# Install NuGet provider
Write-Status "Installing NuGet package provider..."
try {
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget -or $nuget.Version -lt '2.8.5.201') {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
        Write-Status "NuGet provider installed" -Type Success
    } else {
        Write-Status "NuGet provider already installed" -Type Success
    }
} catch {
    Write-Status "Failed to install NuGet provider: $_" -Type Error
    throw
}

# Trust PSGallery
Write-Status "Configuring PSGallery as trusted repository..."
try {
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Write-Status "PSGallery set as trusted" -Type Success
    } else {
        Write-Status "PSGallery already trusted" -Type Success
    }
} catch {
    Write-Status "Failed to configure PSGallery: $_" -Type Warning
}

# Install PSPreworkout module
Write-Status "Installing PSPreworkout module..."
try {
    if (-not (Get-Module -ListAvailable -Name PSPreworkout)) {
        Install-Module PSPreworkout -Force -AllowClobber -Scope CurrentUser
        Write-Status "PSPreworkout installed" -Type Success
    } else {
        Write-Status "PSPreworkout already installed" -Type Success
    }
    Import-Module PSPreworkout -Force
    Write-Status "PSPreworkout imported" -Type Success
} catch {
    Write-Status "Failed to install/import PSPreworkout: $_" -Type Error
    throw
}

# Ensure WinGet is properly configured
try {
    Install-WinGet
    Write-Status "WinGet configuration verified" -Type Success
} catch {
    Write-Status "WinGet configuration issue: $_" -Type Warning
}

# === Core-only execution below ===

# Install Sysinternals PsTools
Write-Status "Installing Sysinternals PsTools..."
try {
    $psToolsCheck = winget list --id Microsoft.Sysinternals.PsTools --exact 2>$null
    if ($LASTEXITCODE -ne 0) {
        winget install -e --id Microsoft.Sysinternals.PsTools --accept-package-agreements --accept-source-agreements --source winget --silent
        if ($LASTEXITCODE -eq 0) {
            Write-Status "PsTools installed" -Type Success
        } else {
            Write-Status "PsTools installation failed with exit code $LASTEXITCODE" -Type Warning
        }
    } else {
        Write-Status "PsTools already installed" -Type Success
    }
} catch {
    Write-Status "Failed to install PsTools: $_" -Type Warning
}

# Run main setup script
Write-Status "Running main setup script..."
try {
    $setupScript = Invoke-RestMethod "https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1" -ErrorAction Stop
    if ($setupScript) {
        Invoke-Expression $setupScript
        Write-Status "Main setup script completed" -Type Success
    } else {
        Write-Status "Setup script downloaded but was empty" -Type Error
    }
} catch {
    Write-Status "Failed to run main setup script: $_" -Type Error
    Write-Status "You may need to run this manually: irm 'https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1' | iex" -Type Warning
}

# Install CMTrace symlink
Write-Status "Installing CMTrace symlink..."
try {
    $cmTraceScript = Invoke-RestMethod https://raw.githubusercontent.com/jorgeasaurus/cmtrace/refs/heads/main/New-CMTraceSymLink.ps1 -ErrorAction Stop
    if ($cmTraceScript) {
        Invoke-Expression $cmTraceScript
        Write-Status "CMTrace symlink configured" -Type Success
    } else {
        Write-Status "CMTrace script downloaded but was empty" -Type Warning
    }
} catch {
    Write-Status "Failed to install CMTrace symlink: $_" -Type Warning
    Write-Status "This is optional and can be skipped" -Type Info
}

# Configure Windows Terminal defaults
Write-Status "Configuring Windows Terminal..."
try {
    $wtSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"

    if (Test-Path $wtSettingsPath) {
        # Backup existing settings
        $backupPath = "$wtSettingsPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item $wtSettingsPath $backupPath -Force
        Write-Status "Settings backed up to: $backupPath" -Type Info

        $settings = Get-Content $wtSettingsPath -Raw | ConvertFrom-Json

        # Find PowerShell Core profile GUID
        $pwshProfile = $settings.profiles.list | Where-Object { $_.name -eq 'PowerShell' -and $_.source -eq 'Windows.Terminal.PowershellCore' }
        if ($pwshProfile) {
            $settings.defaultProfile = $pwshProfile.guid
            Write-Status "Set PowerShell Core as default profile" -Type Success
        } else {
            Write-Status "PowerShell Core profile not found in Windows Terminal" -Type Warning
        }

        # Initialize defaults object if needed
        if (-not $settings.profiles.defaults) {
            $settings.profiles | Add-Member -NotePropertyName 'defaults' -NotePropertyValue @{} -Force
        }
        if (-not $settings.profiles.defaults.font) {
            $settings.profiles.defaults | Add-Member -NotePropertyName 'font' -NotePropertyValue @{} -Force
        }

        # Set font and appearance
        $settings.profiles.defaults.font | Add-Member -NotePropertyName 'face' -NotePropertyValue 'CaskaydiaCove Nerd Font Mono' -Force
        $settings.profiles.defaults | Add-Member -NotePropertyName 'opacity' -NotePropertyValue 87 -Force
        $settings.profiles.defaults | Add-Member -NotePropertyName 'useAcrylic' -NotePropertyValue $false -Force

        # Save settings
        $settings | ConvertTo-Json -Depth 100 | Set-Content $wtSettingsPath -Encoding UTF8
        Write-Status "Windows Terminal configured successfully" -Type Success
        Write-Status "  - Font: CaskaydiaCove Nerd Font Mono" -Type Info
        Write-Status "  - Opacity: 87%" -Type Info
        Write-Status "  - Acrylic: Disabled" -Type Info
    } else {
        Write-Status "Windows Terminal settings not found. Install Windows Terminal from the Microsoft Store." -Type Warning
        Write-Status "You can install it with: winget install Microsoft.WindowsTerminal" -Type Info
    }
} catch {
    Write-Status "Failed to configure Windows Terminal: $_" -Type Warning
    Write-Status "You can configure Windows Terminal manually later" -Type Info
}

Write-Status "`n=== Setup Complete ===" -Type Success
Write-Status "Please restart your terminal for all changes to take effect." -Type Info
Write-Status "If fonts don't display correctly, ensure CaskaydiaCove Nerd Font is installed." -Type Info
