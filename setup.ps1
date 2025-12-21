# PowerShell Core check – this script requires PowerShell 6+ (pwsh)
if ($PSVersionTable.PSVersion.Major -lt 6) {
    Write-Warning "This script requires PowerShell Core (version 6 or higher)."
    Write-Warning "You are running PowerShell $($PSVersionTable.PSVersion)."
    Write-Warning "Please install PowerShell Core from: https://github.com/PowerShell/PowerShell"
    break
}

# OS Check – $IsWindows, $IsMacOS are automatic variables in PowerShell Core
# Elevated privileges check for Windows only
if ($IsWindows) {
    try {
        if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Please run this script as an Administrator!"
            break
        }
    } catch {
        Write-Warning "Failed to check administrative privileges."
    }
} else {
    Write-Host "Non-Windows platform detected. Skipping elevated privileges check."
}

# Function to test internet connectivity (works on all OS)
function Test-InternetConnection {
    try {
        $testConnection = Test-Connection -ComputerName www.google.com -Count 1 -ErrorAction Stop
        return $true
    } catch {
        Write-Warning "Internet connection is required but not available. Please check your connection."
        return $false
    }
}

# Function to install Nerd Fonts (branches for Windows vs. macOS)
function Install-NerdFonts {
    param (
        [string]$FontName = "CascadiaCode",
        [string]$FontDisplayName = "CaskaydiaCove NF",
        [string]$Version = "3.2.1"
    )

    try {
        if ($IsWindows) {
            [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
            $fontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families.Name
            if ($fontFamilies -notcontains "$FontDisplayName") {
                $fontZipUrl = "https://github.com/ryanoasis/nerd-fonts/releases/download/v${Version}/${FontName}.zip"
                $zipFilePath = "$env:TEMP\${FontName}.zip"
                $extractPath = "$env:TEMP\${FontName}"

                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFileAsync((New-Object System.Uri($fontZipUrl)), $zipFilePath)
                while ($webClient.IsBusy) {
                    Start-Sleep -Seconds 2
                }

                Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force
                $destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
                Get-ChildItem -Path $extractPath -Recurse -Filter "*.ttf" | ForEach-Object {
                    if (-not(Test-Path "C:\Windows\Fonts\$($_.Name)")) {
                        $destination.CopyHere($_.FullName, 0x10)
                    }
                }
                Remove-Item -Path $extractPath -Recurse -Force
                Remove-Item -Path $zipFilePath -Force
            } else {
                Write-Host "Font $FontDisplayName already installed"
            }
        } elseif ($IsMacOS) {
            # Use Homebrew to install the correct Nerd Font cask for macOS
            /opt/homebrew/bin/brew install --cask font-cascadia-code-nf
            Write-Host "✅ font-cascadia-code-nf installed."
        }
    } catch {
        Write-Error "Failed to download or install $FontDisplayName font. Error: $_"
    }
}

# Check for internet connectivity before proceeding
if (-not (Test-InternetConnection)) {
    break
}

# Profile creation or update (platform independent)
if (!(Test-Path -Path $PROFILE -PathType Leaf)) {
    try {
        $profileDir = Split-Path -Parent $PROFILE
        if (!(Test-Path -Path $profileDir)) {
            New-Item -Path $profileDir -ItemType "directory"
        }

        Invoke-RestMethod https://github.com/jorgeasaurus/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE
        Write-Host "The profile @ [$PROFILE] has been created."
        Write-Host "If you want to make personal customizations, please edit the file in [$profileDir]."
    } catch {
        Write-Error "Failed to create or update the profile. Error: $_"
    }
} else {
    try {
        Get-Item -Path $PROFILE | Move-Item -Destination "oldprofile.ps1" -Force
        Invoke-RestMethod https://github.com/jorgeasaurus/powershell-profile/raw/main/Microsoft.PowerShell_profile.ps1 -OutFile $PROFILE
        Write-Host "The profile @ [$PROFILE] has been created and the old profile moved to oldprofile.ps1."
        Write-Host "Please back up any persistent components from the old profile in [$HOME/Documents/PowerShell] if needed."
    } catch {
        Write-Error "Failed to backup and update the profile. Error: $_"
    }
}

# Oh My Posh Installation
if ($IsWindows) {
    try {
        winget install -e --accept-source-agreements --accept-package-agreements JanDeDobbeleer.OhMyPosh
    } catch {
        Write-Error "Failed to install Oh My Posh. Error: $_"
    }
} elseif ($IsMacOS) {
    try {
        /opt/homebrew/bin/brew install oh-my-posh
        Write-Host "Oh My Posh installed successfully."
    } catch {
        Write-Error "Failed to install Oh My Posh on macOS. Error: $_"
    }
}

# Font Install
Install-NerdFonts -FontName "CascadiaCode" -FontDisplayName "CaskaydiaCove NF"

# Final check and message to the user
if ($IsWindows) {
    try {
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        $fontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families.Name
        if ((Test-Path -Path $PROFILE) -and (winget list --name "OhMyPosh" -e) -and ($fontFamilies -contains "CaskaydiaCove NF")) {
            Write-Host "Setup completed successfully. Please restart your PowerShell session to apply changes."
        } else {
            Write-Warning "Setup completed with errors. Please check the error messages above."
        }
    } catch {
        Write-Warning "Setup completed with errors. Please verify installations."
    }
} elseif ($IsMacOS) {
    if (Test-Path -Path $PROFILE) {
        Write-Host "Setup completed successfully for macOS. Please restart your PowerShell session to apply changes."
    } else {
        Write-Warning "Setup completed with errors. Please check the error messages above."
    }
}

# Chocolatey Installation (Windows only)
if ($IsWindows) {
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } catch {
        Write-Error "Failed to install Chocolatey. Error: $_"
    }
} else {
    Write-Host "Skipping Chocolatey installation on non-Windows platform."
}

# Terminal Icons Installation (should work on both platforms)
try {
    Install-Module -Name Terminal-Icons -Repository PSGallery -Force
} catch {
    Write-Error "Failed to install Terminal Icons module. Error: $_"
}

# zoxide Installation
if ($IsWindows) {
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully."
    } catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
} elseif ($IsMacOS) {
    try {
        /opt/homebrew/bin/brew install zoxide
        Write-Host "zoxide installed successfully on macOS."
    } catch {
        Write-Error "Failed to install zoxide on macOS. Error: $_"
    }
}