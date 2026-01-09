#Requires -Version 5.1

<#
.SYNOPSIS
    Complete PowerShell environment setup for Windows and macOS.

.DESCRIPTION
    Comprehensive setup script that:
    - Bootstraps to PowerShell 7 (Windows: auto-installs if needed)
    - Installs PowerShell profile from GitHub
    - Installs Oh My Posh prompt theme
    - Installs CaskaydiaCove Nerd Font
    - Installs PowerShell modules (Terminal-Icons, PSPreworkout, PwshSpectreConsole)
    - Windows only: PsTools, CMTrace, Windows Terminal configuration
    - macOS: Homebrew-based installations

.PARAMETER SkipOptional
    Skip optional components (PsTools, CMTrace).

.PARAMETER NoElevate
    Don't attempt to self-elevate on Windows (will fail if not admin).

.EXAMPLE
    irm https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1 | iex

.EXAMPLE
    .\setup.ps1 -Verbose

.EXAMPLE
    .\setup.ps1 -SkipOptional

.NOTES
    Author: jorgeasaurus
    Repository: https://github.com/jorgeasaurus/powershell-profile
    Supports: Windows (PowerShell 5.1+), macOS (PowerShell 7+)
#>

[CmdletBinding()]
param(
    [switch]$SkipOptional,
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$reranInWindowsTerminal = $env:WINDOWSTERMINAL_RERAN -eq '1'

# ============================================================================
# Self-Elevation (Windows Only)
# ============================================================================

if ($IsWindows -or $PSVersionTable.PSEdition -ne 'Core') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin -and -not $NoElevate) {
        Write-Host "Administrator privileges required. Relaunching as administrator..." -ForegroundColor Yellow

        try {
            $scriptPath = $MyInvocation.MyCommand.Path
            $shell = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' }

            if ($scriptPath) {
                # Running from file
                Start-Process $shell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
            } else {
                # Running from remote (irm | iex)
                $scriptUrl = 'https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1'
                Start-Process $shell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm '$scriptUrl' | iex`"" -Verb RunAs
            }
            exit
        } catch {
            Write-Error "Failed to elevate privileges. Please run as administrator manually."
            exit 1
        }
    }

    if (-not $isAdmin) {
        Write-Error "Administrator privileges required. Run as administrator or omit -NoElevate flag."
        exit 1
    }
}

# ============================================================================
# Bootstrap to PowerShell 7 (Windows Only)
# ============================================================================

if (($IsWindows -or $PSVersionTable.PSEdition -ne 'Core') -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "PowerShell 7 required. Installing..." -ForegroundColor Cyan

    # Install PowerShell 7 directly if we don't have it
    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        $installedViaMsi = $false

        # Check if WinGet is available
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host "Installing WinGet..." -ForegroundColor Yellow

            # Try method 1: App Installer registration (works on normal Windows)
            try {
                Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
                $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')

                if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                    throw "WinGet registration failed"
                }
                Write-Host "[OK] WinGet installed via App Installer" -ForegroundColor Green
            } catch {
                Write-Verbose "App Installer registration failed, trying direct MSI installation for PowerShell 7..."

                # Method 2: Install PowerShell 7 directly via MSI (most reliable for Sandbox/WDAG)
                try {
                    Write-Host "Downloading PowerShell 7 MSI..." -ForegroundColor Yellow
                    $tempDir = "$env:TEMP\pwsh-install"
                    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

                    # Get latest PowerShell release
                    $psRelease = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -UseBasicParsing
                    $msiAsset = $psRelease.assets | Where-Object { $_.name -like '*win-x64.msi' } | Select-Object -First 1

                    if (-not $msiAsset) {
                        throw "Could not find PowerShell MSI in latest release"
                    }

                    $msiPath = "$tempDir\PowerShell-7-win-x64.msi"
                    Write-Verbose "Downloading from: $($msiAsset.browser_download_url)"
                    Invoke-WebRequest -Uri $msiAsset.browser_download_url -OutFile $msiPath -UseBasicParsing

                    Write-Host "Installing PowerShell 7..." -ForegroundColor Cyan
                    $msiArgs = @(
                        "/i", "`"$msiPath`"",
                        "/qn",
                        "/norestart",
                        "ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1",
                        "ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1",
                        "ENABLE_PSREMOTING=1",
                        "REGISTER_MANIFEST=1",
                        "USE_MU=1",
                        "ENABLE_MU=1"
                    )
                    $msiProcess = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow -PassThru

                    if ($msiProcess.ExitCode -ne 0) {
                        throw "MSI installation failed with exit code: $($msiProcess.ExitCode)"
                    }

                    # Refresh PATH
                    $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')

                    # Cleanup
                    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

                    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
                        throw "PowerShell 7 installation succeeded but command not found. Reboot may be required."
                    }

                    $installedViaMsi = $true
                    Write-Host "[OK] PowerShell 7 installed via MSI" -ForegroundColor Green
                } catch {
                    Write-Verbose "Direct MSI installation failed: $($_.Exception.Message)"

                    # Method 3: Microsoft's official installation script
                    try {
                        Write-Host "Trying Microsoft's official PowerShell installer..." -ForegroundColor Yellow
                        $installScript = Invoke-RestMethod -Uri 'https://aka.ms/install-powershell.ps1' -UseBasicParsing
                        Invoke-Expression "& { $installScript } -UseMSI -Quiet"

                        # Refresh PATH
                        $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')

                        if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
                            throw "Microsoft installer completed but PowerShell 7 command not found"
                        }

                        $installedViaMsi = $true
                        Write-Host "[OK] PowerShell 7 installed via Microsoft installer" -ForegroundColor Green
                    } catch {
                        Write-Host ""
                        Write-Host "PowerShell 7 installation failed. Manual installation required:" -ForegroundColor Red
                        Write-Host "  1. Download: https://github.com/PowerShell/PowerShell/releases/latest" -ForegroundColor Yellow
                        Write-Host "  2. Install the win-x64.msi package" -ForegroundColor Yellow
                        Write-Host "  3. Rerun this script in PowerShell 7" -ForegroundColor Yellow
                        Write-Host ""
                        Write-Verbose "Error details: $($_.Exception.Message)"
                        exit 1
                    }
                }
            }
        }

        # Install via WinGet if we have it and haven't already installed via MSI
        if (-not $installedViaMsi -and (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host "Installing PowerShell 7..." -ForegroundColor Cyan
            winget install -e --id Microsoft.PowerShell --accept-package-agreements --accept-source-agreements --silent --source winget

            # Refresh PATH
            $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')

            if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
                Write-Error "PowerShell 7 installation via WinGet failed. Please install manually."
                exit 1
            }
            Write-Host "[OK] PowerShell 7 installed via WinGet" -ForegroundColor Green
        }
    }

    # Relaunch in PowerShell 7
    Write-Host "Relaunching in PowerShell 7..." -ForegroundColor Green
    $scriptPath = $MyInvocation.MyCommand.Path

    if ($scriptPath) {
        pwsh -NoProfile -ExecutionPolicy Bypass -File $scriptPath
    } else {
        pwsh -NoProfile -ExecutionPolicy Bypass -Command "irm 'https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1' | iex"
    }
    exit
}

# ============================================================================
# PowerShell 7+ Execution Starts Here
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  PowerShell Environment Setup" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Match WinPSSetup: ensure process-level execution policy is relaxed for installs
try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
} catch {
    Write-Verbose "Execution policy change failed: $($_.Exception.Message)"
}

# ============================================================================
# Windows Prerequisites
# ============================================================================

if ($IsWindows) {
    # NuGet Provider
    Write-Verbose "Checking NuGet provider..."
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget -or $nuget.Version -lt '2.8.5.201') {
        Write-Verbose "Installing NuGet provider..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        Write-Host "[OK] NuGet provider installed" -ForegroundColor Green
    }

    # Trust PSGallery
    Write-Verbose "Configuring PSGallery..."
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Write-Host "[OK] PSGallery trusted" -ForegroundColor Green
    }
}

# ============================================================================
# WinGet (Windows Only)
# ============================================================================

if ($IsWindows) {
    Write-Verbose "Ensuring WinGet client is available..."
    try {
        if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {
            Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
        }

        Import-Module Microsoft.WinGet.Client -Force -ErrorAction Stop

        $repairCmd = Get-Command Repair-WinGetPackageManager -ErrorAction SilentlyContinue
        if ($repairCmd) {
            Repair-WinGetPackageManager -AllUsers | Out-Null
            Repair-WinGetPackageManager | Out-Null
            Write-Host "[OK] WinGet client repaired/installed" -ForegroundColor Green
        } else {
            Write-Verbose "Repair-WinGetPackageManager not available even after module import"
        }
    } catch {
        Write-Verbose "WinGet client setup skipped: $_"
    }

    # Install Git
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Verbose "Installing Git..."
        try {
            winget install git.git --source winget --accept-package-agreements --accept-source-agreements --silent --disable-interactivity 2>&1 | Out-Null

            # Refresh PATH
            $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')

            if (Get-Command git -ErrorAction SilentlyContinue) {
                Write-Host "[OK] Git installed" -ForegroundColor Green
            } else {
                Write-Verbose "Git installation completed but command not immediately available. May require shell restart."
            }
        } catch {
            Write-Verbose "Git installation skipped: $_"
        }
    }

    # Windows Defender Application Guard (WDAG) - Microsoft Store installer
    $currentUser = [Environment]::UserName
    if ($currentUser -eq 'WDAGUtilityAccount') {
        Write-Host "Detected Windows Defender Application Guard environment" -ForegroundColor Cyan

        # Set region to United States
        Write-Verbose "Setting Windows region to United States..."
        try {
            Set-WinHomeLocation -GeoId 244 -ErrorAction Stop  # 244 = United States
            Write-Host "[OK] Region set to United States" -ForegroundColor Green
        } catch {
            Write-Verbose "Failed to set region: $_"
        }

        Write-Verbose "Installing Microsoft Store for Sandbox/WDAG..."

        try {
            $desktopPath = [Environment]::GetFolderPath('Desktop')
            $repoPath = Join-Path $desktopPath 'Sandbox-Add-MicrosoftStore'

            if (Get-Command git -ErrorAction SilentlyContinue) {
                # Clone the repository
                Write-Verbose "Cloning Sandbox-Add-MicrosoftStore repository..."
                git clone https://github.com/jorgeasaurus/Sandbox-Add-MicrosoftStore $repoPath 2>&1 | Out-Null

                if (Test-Path $repoPath) {
                    # Run the Add-Microsoft-Store.ps1 script
                    $addStoreScript = Join-Path $repoPath 'Add-Microsoft-Store.ps1'
                    if (Test-Path $addStoreScript) {
                        Write-Host "Installing Microsoft Store..." -ForegroundColor Yellow
                        pwsh -NoProfile -ExecutionPolicy Bypass -File $addStoreScript
                        Write-Host "[OK] Microsoft Store installation initiated" -ForegroundColor Green
                    } else {
                        Write-Verbose "Add-Microsoft-Store.ps1 not found in repository"
                    }
                } else {
                    Write-Verbose "Failed to clone Sandbox-Add-MicrosoftStore repository"
                }
            } else {
                Write-Verbose "Git not available for cloning Microsoft Store installer. Install Git first."
            }
        } catch {
            Write-Verbose "Microsoft Store installation for WDAG skipped: $_"
        }
    }
}

# ============================================================================
# Install Profile
# ============================================================================

Write-Verbose "Installing PowerShell profile..."

$profileDir = Split-Path -Parent $PROFILE
if (-not (Test-Path $profileDir)) {
    New-Item -Path $profileDir -ItemType Directory -Force | Out-Null
}

try {
    Invoke-RestMethod -Uri 'https://github.com/jorgeasaurus/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1' -OutFile $PROFILE
    Write-Host "[OK] Profile installed" -ForegroundColor Green
} catch {
    throw "Failed to download profile: $_"
}

# ============================================================================
# Install Oh My Posh
# ============================================================================

if ($IsWindows) {
    if (-not (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) {
        Write-Verbose "Installing Oh My Posh..."
        winget install -e --id JanDeDobbeleer.OhMyPosh --accept-package-agreements --accept-source-agreements --silent | Out-Null
        Write-Host "[OK] Oh My Posh installed" -ForegroundColor Green
    }
} elseif ($IsMacOS) {
    if (-not (Get-Command oh-my-posh -ErrorAction SilentlyContinue)) {
        Write-Verbose "Installing Oh My Posh..."
        brew install oh-my-posh 2>&1 | Out-Null
        Write-Host "[OK] Oh My Posh installed" -ForegroundColor Green
    }
}

# ============================================================================
# Install Nerd Font
# ============================================================================

if ($IsWindows) {
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    $fontInstalled = (New-Object System.Drawing.Text.InstalledFontCollection).Families.Name -contains 'CaskaydiaCove NF'

    if (-not $fontInstalled) {
        Write-Verbose "Installing CaskaydiaCove Nerd Font..."

        $zipPath = "$env:TEMP\CascadiaCode.zip"
        $extractPath = "$env:TEMP\CascadiaCode"

        Invoke-RestMethod -Uri 'https://github.com/ryanoasis/nerd-fonts/releases/download/v3.2.1/CascadiaCode.zip' -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        $shellFonts = (New-Object -ComObject Shell.Application).Namespace(0x14)
        Get-ChildItem -Path $extractPath -Filter "*.ttf" -Recurse | ForEach-Object {
            if (-not (Test-Path "C:\Windows\Fonts\$($_.Name)")) {
                $shellFonts.CopyHere($_.FullName, 0x10)
            }
        }

        Remove-Item $extractPath -Recurse -Force
        Remove-Item $zipPath -Force

        Write-Host "[OK] CaskaydiaCove Nerd Font installed" -ForegroundColor Green
    }
} elseif ($IsMacOS) {
    if (-not (Test-Path "$HOME/Library/Fonts/CaskaydiaCoveNerdFont-Regular.ttf")) {
        Write-Verbose "Installing CaskaydiaCove Nerd Font..."
        brew install --cask font-cascadia-code-nf 2>&1 | Out-Null
        Write-Host "[OK] CaskaydiaCove Nerd Font installed" -ForegroundColor Green
    }
}

# ============================================================================
# Install Core Modules
# ============================================================================

# Terminal-Icons
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Write-Verbose "Installing Terminal-Icons..."
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    Write-Host "[OK] Terminal-Icons installed" -ForegroundColor Green
}

# ============================================================================
# Windows-Specific Modules
# ============================================================================

if ($IsWindows) {
    # PSPreworkout (contains Install-WinGet and other utilities)
    if (-not (Get-Module -ListAvailable -Name PSPreworkout)) {
        Write-Verbose "Installing PSPreworkout..."
        Install-Module PSPreworkout -Force -AllowClobber -Scope CurrentUser -Repository PSGallery
        Write-Host "[OK] PSPreworkout installed" -ForegroundColor Green
    }

    # PwshSpectreConsole (for Show-SystemNeofetch)
    if (-not (Get-Module -ListAvailable -Name PwshSpectreConsole)) {
        Write-Verbose "Installing PwshSpectreConsole..."
        $OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
        Install-Module -Name PwshSpectreConsole -Scope CurrentUser -Force -SkipPublisherCheck -Repository PSGallery
        Write-Host "[OK] PwshSpectreConsole installed" -ForegroundColor Green
    }

    # Optional: PsTools
    if (-not $SkipOptional) {
        Write-Verbose "Installing Sysinternals PsTools..."
        try {
            winget install -e --id Microsoft.Sysinternals.PsTools --accept-package-agreements --accept-source-agreements --silent --disable-interactivity 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] PsTools installed" -ForegroundColor Green
            }
        } catch {
            Write-Verbose "PsTools installation skipped (optional)"
        }
    }

    # Optional: CMTrace Symlink
    if (-not $SkipOptional) {
        Write-Verbose "Installing CMTrace symlink..."
        try {
            $cmTraceScript = Invoke-RestMethod 'https://raw.githubusercontent.com/jorgeasaurus/cmtrace/refs/heads/main/New-CMTraceSymLink.ps1' -ErrorAction Stop
            if ($cmTraceScript) {
                Invoke-Expression $cmTraceScript
                Write-Host "[OK] CMTrace symlink configured" -ForegroundColor Green
            }
        } catch {
            Write-Verbose "CMTrace installation skipped (optional)"
        }
    }
}

# ============================================================================
# Windows Terminal Install/Configure/Relaunch (Windows Only)
# ============================================================================

if ($IsWindows) {
    Write-Verbose "Ensuring Windows Terminal is installed..."

    $wtInstalled = $false
    $wtExecutable = $null

    $wtCommand = Get-Command wt -ErrorAction SilentlyContinue
    if ($wtCommand) {
        $wtExecutable = $wtCommand.Source
        $wtInstalled = $true
    } else {
        try {
            winget install -e --id Microsoft.WindowsTerminal --accept-package-agreements --accept-source-agreements --silent --disable-interactivity --source winget 2>&1 | Out-Null
            $wtCommand = Get-Command wt -ErrorAction SilentlyContinue
            if ($wtCommand) {
                $wtExecutable = $wtCommand.Source
                $wtInstalled = $true
                Write-Host "[OK] Windows Terminal installed" -ForegroundColor Green
            }
        } catch {
            Write-Verbose "Windows Terminal installation skipped: $_"
        }
    }

    if (-not $wtExecutable) {
        $fallbackWt = "$env:LOCALAPPDATA\Microsoft\WindowsApps\wt.exe"
        if (Test-Path $fallbackWt) {
            $wtExecutable = $fallbackWt
            $wtInstalled = $true
        }
    }

    if ($wtInstalled) {
        Write-Verbose "Configuring Windows Terminal..."

        $wtSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"

        if (Test-Path $wtSettingsPath) {
            try {
                # Backup existing settings
                $backupPath = "$wtSettingsPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                Copy-Item $wtSettingsPath $backupPath -Force
                Write-Verbose "Settings backed up to: $backupPath"

                # Read and modify settings
                $settings = Get-Content $wtSettingsPath -Raw | ConvertFrom-Json

                # Find PowerShell Core profile (GUID-independent)
                $pwshProfile = $settings.profiles.list | Where-Object {
                    $_.name -eq 'PowerShell' -and $_.source -eq 'Windows.Terminal.PowershellCore'
                }

                if ($pwshProfile) {
                    $settings.defaultProfile = $pwshProfile.guid

                    # Initialize defaults if needed
                    if (-not $settings.profiles.defaults) {
                        $settings.profiles | Add-Member -NotePropertyName 'defaults' -NotePropertyValue ([PSCustomObject]@{}) -Force
                    }
                    if (-not $settings.profiles.defaults.font) {
                        $settings.profiles.defaults | Add-Member -NotePropertyName 'font' -NotePropertyValue ([PSCustomObject]@{}) -Force
                    }

                    # Configure appearance
                    $settings.profiles.defaults.font | Add-Member -NotePropertyName 'face' -NotePropertyValue 'CaskaydiaCove Nerd Font Mono' -Force
                    $settings.profiles.defaults | Add-Member -NotePropertyName 'opacity' -NotePropertyValue 87 -Force
                    $settings.profiles.defaults | Add-Member -NotePropertyName 'useAcrylic' -NotePropertyValue $true -Force
                    $settings | Add-Member -NotePropertyName 'initialCols' -NotePropertyValue 150 -Force

                    # Save settings
                    $settings | ConvertTo-Json -Depth 100 | Set-Content $wtSettingsPath -Encoding UTF8

                    Write-Host "[OK] Windows Terminal configured (PowerShell 7 default)" -ForegroundColor Green
                } else {
                    Write-Verbose "PowerShell Core profile not found in Windows Terminal"
                }
            } catch {
                Write-Verbose "Windows Terminal configuration skipped: $_"
            }
        } else {
            Write-Verbose "Windows Terminal settings not found yet (launch once to generate settings.json)"
        }

        if (-not $reranInWindowsTerminal -and -not $env:WT_SESSION) {
            try {
                $scriptPath = $MyInvocation.MyCommand.Path
                $wtArgs = @('pwsh', '-NoProfile', '-ExecutionPolicy', 'Bypass')

                if ($scriptPath) {
                    $wtArgs += @('-File', "`"$scriptPath`"")
                    if ($MyInvocation.UnboundArguments) {
                        $wtArgs += $MyInvocation.UnboundArguments
                    }
                } else {
                    $wtArgs += @('-Command', "`"irm 'https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1' | iex`"")
                }

                $wtArgumentList = $wtArgs -join ' '
                Write-Host "Relaunching this script inside Windows Terminal..." -ForegroundColor Yellow
                Start-Process -FilePath $wtExecutable -ArgumentList $wtArgumentList -Environment @{ 'WINDOWSTERMINAL_RERAN' = '1' }
                exit
            } catch {
                Write-Verbose "Windows Terminal relaunch skipped: $_"
            }
        }
    } else {
        Write-Verbose "Windows Terminal not available; skipping configuration"
    }
}

# ============================================================================
# Completion
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

if ($IsWindows) {
    Write-Host "`n  -> Close and reopen Windows Terminal" -ForegroundColor Yellow
    Write-Host "  -> PowerShell 7 is now your default shell`n" -ForegroundColor Yellow
} else {
    Write-Host "`n  -> Restart PowerShell to apply changes`n" -ForegroundColor Yellow
}
