### PowerShell Profile Refactor
### Version 1.04 - Simplified

$debug = $false

# Light mode: Set $env:PROFILE_LIGHT=1 to skip network calls, neofetch, and module checks
# Useful for non-interactive shells, scripts, or constrained environments
$script:LightMode = $env:PROFILE_LIGHT -eq '1'

# Skip neofetch on startup (set to $true to disable system info display)
$script:SkipNeofetch = $false

# Define the update interval in days, set to -1 to always check
$updateInterval = 7

if ($debug) {
    Write-Host "#######################################" -ForegroundColor Red
    Write-Host "#           Debug mode enabled        #" -ForegroundColor Red
    Write-Host "#          ONLY FOR DEVELOPMENT       #" -ForegroundColor Red
    Write-Host "#                                     #" -ForegroundColor Red
    Write-Host "#       IF YOU ARE NOT DEVELOPING     #" -ForegroundColor Red
    Write-Host "#       JUST RUN \`Update-Profile\`   #" -ForegroundColor Red
    Write-Host "#        to discard all changes       #" -ForegroundColor Red
    Write-Host "#   and update to the latest profile  #" -ForegroundColor Red
    Write-Host "#               version               #" -ForegroundColor Red
    Write-Host "#######################################" -ForegroundColor Red
}


#################################################################################################################################
############                                                                                                         ############
############                                          !!!   WARNING:   !!!                                           ############
############                                                                                                         ############
############                DO NOT MODIFY THIS FILE. THIS FILE IS HASHED AND UPDATED AUTOMATICALLY.                  ############
############                    ANY CHANGES MADE TO THIS FILE WILL BE OVERWRITTEN BY COMMITS TO                      ############
############                       https://github.com/jorgeasaurus/powershell-profile.git.                         ############
############                                                                                                         ############
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
############                                                                                                         ############
############                      IF YOU WANT TO MAKE CHANGES, USE THE Edit-Profile FUNCTION                         ############
############                              AND SAVE YOUR CHANGES IN THE FILE CREATED.                                 ############
############                                                                                                         ############
#################################################################################################################################

$UserProfile = $HOME
# Ensure $Onedrive variable is defined (if not, set it)

if (Test-Path ~/Library/CloudStorage/OneDrive-Personal) {
    Set-Variable -Name Onedrive -Value "~/Library/CloudStorage/OneDrive-Personal" -Scope Global
} else {
    Set-Variable -Name Onedrive -Value "$UserProfile/OneDrive" -Scope Global
}

# Oh My Posh theme configuration
$OhMyPoshTheme = "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/quick-term.omp.json"

# Extra: Price tracking configuration
$UserStockSymbol = "AAPL"  # Change this to your preferred stock symbol (e.g., "TSLA", "MSFT", "GOOGL")

# Platform-specific initialization
if ($IsWindows) {
    # Admin Check
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Opt-out of telemetry if running as Administrator (not SYSTEM)
    if ($isAdmin) {
        try {
            [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
        } catch {
            # May fail without elevation - silently ignore
        }
    }
} else {
    $env:USERPROFILE = $HOME
}

# Define the path to the file that stores the last execution time
$timeFilePath = "$env:USERPROFILE\Documents\PowerShell\LastExecutionTime.txt"
if (-not (Test-Path $timeFilePath)) {
    # Create the file if it doesn't exist
    New-Item -Path $timeFilePath -ItemType File -Force | Out-Null
    $currentTime = Get-Date -Format 'yyyy-MM-dd'
    $currentTime | Out-File -FilePath $timeFilePath -Force
}

# Define local profile image path and download from GitHub if needed
$localProfileImage = "$env:USERPROFILE\Documents\PowerShell\profilepic.jpeg"
$profileImageUrl = "https://github.com/jorgeasaurus/powershell-profile/raw/main/profilepic.jpeg"

if (-not (Test-Path $localProfileImage)) {
    try {
        Invoke-RestMethod -Uri $profileImageUrl -OutFile $localProfileImage -ErrorAction Stop
    } catch {
        # Silently ignore if download fails
    }
}

# Consolidated module initialization function
function Initialize-ProfileModules {
    <#
    .SYNOPSIS
        Initializes required PowerShell modules for the profile.
    .DESCRIPTION
        Checks for and optionally installs required modules: Terminal-Icons, PSpreworkout, and PwshSpectreConsole.
        By default, only imports modules if they're already installed. Use -Install to install missing modules.
    .PARAMETER Install
        If specified, installs any missing modules from PSGallery.
    .EXAMPLE
        Initialize-ProfileModules
        Imports modules if available, warns if missing.
    .EXAMPLE
        Initialize-ProfileModules -Install
        Installs missing modules and then imports them.
    #>
    [CmdletBinding()]
    param(
        [switch]$Install
    )

    $requiredModules = @(
        @{ Name = 'Terminal-Icons'; Required = $true; MinVersion = $null }
        @{ Name = 'PSpreworkout'; Required = $true; MinVersion = $null }
        @{ Name = 'PwshSpectreConsole'; Required = $false; MinVersion = $null; PS7Only = $true }
    )

    $missingModules = @()
    $global:SpectreAvailable = $false

    foreach ($module in $requiredModules) {
        # Skip PS7-only modules if running PS5
        if ($module.PS7Only -and $PSVersionTable.PSVersion.Major -lt 7) {
            continue
        }

        $installed = Get-Module -ListAvailable -Name $module.Name -ErrorAction SilentlyContinue

        if (-not $installed) {
            if ($Install) {
                Write-Host "Installing module: $($module.Name)..." -ForegroundColor Cyan
                try {
                    Install-Module -Name $module.Name -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
                    Write-Host "  ✓ $($module.Name) installed successfully" -ForegroundColor Green
                    $installed = $true
                } catch {
                    Write-Warning "Failed to install $($module.Name): $_"
                    if ($module.Required) {
                        $missingModules += $module.Name
                    }
                    continue
                }
            } else {
                if ($module.Required) {
                    $missingModules += $module.Name
                }
                continue
            }
        }

        # Import the module
        try {
            Import-Module -Name $module.Name -ErrorAction Stop
            if ($module.Name -eq 'PwshSpectreConsole') {
                $global:SpectreAvailable = $true
            }
        } catch {
            Write-Warning "Failed to import $($module.Name): $_"
        }
    }

    # Warn about missing required modules
    if ($missingModules.Count -gt 0) {
        Write-Warning @"
Missing required modules: $($missingModules -join ', ')
Run 'Initialize-ProfileModules -Install' to install them, or install manually:
    Install-Module -Name $($missingModules -join ',') -Scope CurrentUser
"@
    }
}

# Initialize modules (import only, no auto-install) - skip in light mode
if (-not $script:LightMode) {
    Initialize-ProfileModules
}

# Windows-specific functions
if ($IsWindows) {
    function Invoke-WindowsPowerShellUpgrade {
        try {
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command winget upgrade Microsoft.PowerShell --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow
            return $true
        } catch {
            Write-Error "Failed to trigger PowerShell update via winget: $_"
            return $false
        }
    }

    function Clear-WindowsCache {
        Write-Host "Detected Windows system" -ForegroundColor Yellow

        Write-Host "Clearing Windows Prefetch..." -ForegroundColor Yellow
        Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue

        Write-Host "Clearing Windows Temp..." -ForegroundColor Yellow
        Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "Clearing User Temp..." -ForegroundColor Yellow
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "Clearing Internet Explorer Cache..." -ForegroundColor Yellow
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    }

    function winutil {
        <#
        .SYNOPSIS
            Launches the Chris Titus Tech Windows Utility (stable release)
        .DESCRIPTION
            Downloads and runs the WinUtil script in a new elevated PowerShell window
            for security isolation. The script is NOT executed in the current session.
        #>
        [CmdletBinding()]
        param()

        Write-Warning "This will download and execute a remote script in an elevated window."
        Write-Warning "Source: https://christitus.com/win"
        $confirm = Read-Host "Continue? (y/N)"
        if ($confirm -ne 'y') {
            Write-Host "Cancelled." -ForegroundColor Yellow
            return
        }

        # Run in isolated elevated process - not in current session
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-Command", "irm https://christitus.com/win | iex; Read-Host 'Press Enter to close'"
        )
    }
    function admin {
        if ($args.Count -gt 0) {
            $argList = $args -join ' '
            Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
        } else {
            Start-Process wt -Verb runAs
        }
    }

    function uptime {
        try {
            $lastBootStr = $null

            if ($PSVersionTable.PSVersion.Major -eq 5) {
                $lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
                $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)
                $lastBootStr = $bootTime.ToString()
            } else {
                # Use Get-CimInstance for PowerShell 7+ (cross-platform compatible)
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                if ($os) {
                    $bootTime = $os.LastBootUpTime
                    $lastBootStr = $bootTime.ToString()
                } else {
                    # Fallback to net statistics for older systems
                    $lastBootStr = net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }

                    if (-not $lastBootStr) {
                        throw "Unable to determine system boot time"
                    }

                    $dateFormat = $null
                    if ($lastBootStr -match '^\d{2}/\d{2}/\d{4}') {
                        $dateFormat = 'dd/MM/yyyy'
                    } elseif ($lastBootStr -match '^\d{2}-\d{2}-\d{4}') {
                        $dateFormat = 'dd-MM-yyyy'
                    } elseif ($lastBootStr -match '^\d{4}/\d{2}/\d{2}') {
                        $dateFormat = 'yyyy/MM/dd'
                    } elseif ($lastBootStr -match '^\d{4}-\d{2}-\d{2}') {
                        $dateFormat = 'yyyy-MM-dd'
                    } elseif ($lastBootStr -match '^\d{2}\.\d{2}\.\d{4}') {
                        $dateFormat = 'dd.MM.yyyy'
                    }

                    if (-not $dateFormat) {
                        throw "Unable to parse date format from: $lastBootStr"
                    }

                    if ($lastBootStr -match '\bAM\b' -or $lastBootStr -match '\bPM\b') {
                        $timeFormat = 'h:mm:ss tt'
                    } else {
                        $timeFormat = 'HH:mm:ss'
                    }

                    $bootTime = [System.DateTime]::ParseExact($lastBootStr, "$dateFormat $timeFormat", [System.Globalization.CultureInfo]::InvariantCulture)
                }
            }

            $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) + " [$lastBootStr]"
            Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray

            $uptime = (Get-Date) - $bootTime

            $days = $uptime.Days
            $hours = $uptime.Hours
            $minutes = $uptime.Minutes
            $seconds = $uptime.Seconds

            Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $days, $hours, $minutes, $seconds) -ForegroundColor Blue
        } catch {
            Write-Error "An error occurred while retrieving system uptime."
        }
    }

    function sys {
        if (-not (Get-Command PsExec -ErrorAction SilentlyContinue)) {
            Write-Warning "PsExec not found. Please download PsExec from https://docs.microsoft.com/en-us/sysinternals/downloads/psexec and place it in a folder included in your PATH."
            return
        }
        Start-Process -FilePath cmd.exe -Verb Runas -ArgumentList '/k PsExec -i -accepteula -s powershell.exe'
    }

    function Search-RegistryUninstallKey {
        param(
            [Parameter(Mandatory = $true)]
            [string]$SearchFor,
            [switch]$Wow6432Node
        )

        $results = @()
        $registryPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        foreach ($path in $registryPaths) {
            $keys = Get-ChildItem $path -ErrorAction SilentlyContinue
            foreach ($key in $keys) {
                $result = [PSCustomObject]@{
                    GUID            = $key.PSChildName
                    Publisher       = $key.GetValue('Publisher')
                    DisplayName     = $key.GetValue('DisplayName')
                    DisplayVersion  = $key.GetValue('DisplayVersion')
                    InstallLocation = $key.GetValue('InstallLocation')
                    UninstallString = $key.GetValue('UninstallString')
                    EstimatedSizeMB = if ($key.GetValue('EstimatedSize')) { [math]::Round($key.GetValue('EstimatedSize') / 1024, 2) } else { $null }
                    InstallDate     = $key.GetValue('InstallDate')
                    RegistryPath    = $key.PSPath
                }

                if ($result.DisplayName -and $result.DisplayName -match $SearchFor) {
                    $results += $result
                }
            }
        }

        if ($Wow6432Node) {
            $wow6432Path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            $wow6432Keys = Get-ChildItem $wow6432Path -ErrorAction SilentlyContinue
            foreach ($key in $wow6432Keys) {
                $result = [PSCustomObject]@{
                    GUID            = $key.PSChildName
                    Publisher       = $key.GetValue('Publisher')
                    DisplayName     = $key.GetValue('DisplayName')
                    DisplayVersion  = $key.GetValue('DisplayVersion')
                    InstallLocation = $key.GetValue('InstallLocation')
                    UninstallString = $key.GetValue('UninstallString')
                    EstimatedSizeMB = if ($key.GetValue('EstimatedSize')) { [math]::Round($key.GetValue('EstimatedSize') / 1024, 2) } else { $null }
                    InstallDate     = $key.GetValue('InstallDate')
                    RegistryPath    = $key.PSPath
                }

                if ($result.DisplayName -and $result.DisplayName -match $SearchFor) {
                    $results += $result
                }
            }
        }

        return $results
    }

    function Test-WindowsFont {
        param ([string]$FontName)
        $fontsFolder = [System.Environment]::GetFolderPath('Fonts')
        foreach ($ext in @('.ttf', '.otf')) {
            if (Test-Path (Join-Path $fontsFolder "$FontName$ext")) { return $true }
        }

        $fontReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
        return (Get-ItemProperty -Path $fontReg -ErrorAction SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -like "*$FontName*" } | Select-Object -First 1
    }
}

# macOS-specific functions
if ($IsMacOS) {
    function Invoke-MacPowerShellUpgrade {
        if (-not (Get-Command brew -ErrorAction SilentlyContinue)) {
            Write-Warning "Homebrew is not installed. Please install Homebrew first: /bin/bash -c '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'"
            return $false
        }

        try {
            brew update
            brew upgrade powershell --cask
            return $true
        } catch {
            Write-Error "Failed to update PowerShell via Homebrew: $_"
            return $false
        }
    }
    function Clear-MacCache {
        Write-Host "Detected macOS system" -ForegroundColor Yellow

        Write-Host "Clearing System Cache..." -ForegroundColor Yellow
        sudo rm -rf /Library/Caches/* 2>$null

        Write-Host "Clearing User Cache..." -ForegroundColor Yellow
        Remove-Item -Path "$HOME/Library/Caches/*" -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "Clearing DNS Cache..." -ForegroundColor Yellow
        sudo dscacheutil -flushcache
        sudo killall -HUP mDNSResponder

        Write-Host "Clearing Font Cache..." -ForegroundColor Yellow
        sudo atsutil databases -remove
        atsutil server -shutdown
        atsutil server -ping
    }

    function Test-MacFont {
        param ([string]$FontName)
        $fontDirs = @("~/Library/Fonts", "/Library/Fonts", "/System/Library/Fonts")
        foreach ($dir in $fontDirs) {
            $realDir = $dir.Replace("~", $HOME)
            if (Get-ChildItem -Path $realDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*$FontName*" -and ($_.Extension -in @('.ttf', '.otf')) }) {
                return $true
            }
        }

        if ($FontName -like "*cascadia*") {
            $brewList = brew list --cask font-cascadia-code-nerd-font 2>$null
            return $null -ne $brewList
        }
        return $false
    }
}

# OS-agnostic functions

# Check for Profile Updates
function Update-Profile {
    try {
        # Use platform-appropriate temp directory without modifying $env:temp
        $tempDir = if ($IsWindows) {
            $env:TEMP
        } else {
            "$HOME/.cache"
        }

        # Ensure temp directory exists
        if (-not (Test-Path $tempDir)) {
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        }

        $url = "https://raw.githubusercontent.com/jorgeasaurus/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        $tempProfilePath = Join-Path $tempDir "Microsoft.PowerShell_profile.ps1"

        $oldhash = Get-FileHash $PROFILE
        Invoke-RestMethod $url -OutFile $tempProfilePath
        $newhash = Get-FileHash $tempProfilePath
        if ($newhash.Hash -ne $oldhash.Hash) {
            Copy-Item -Path $tempProfilePath -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Profile is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Unable to check for `$profile updates: $_"
    } finally {
        Remove-Item $tempProfilePath -ErrorAction SilentlyContinue
    }
}

function Test-UpdateDue {
    <#
    .SYNOPSIS
        Checks if an update is due based on the last execution time
    .PARAMETER TimeFilePath
        Path to the file storing the last execution timestamp
    .PARAMETER IntervalDays
        Number of days between updates. Use -1 to always return true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TimeFilePath,

        [Parameter(Mandatory)]
        [int]$IntervalDays
    )

    if ($IntervalDays -eq -1) { return $true }
    if (-not (Test-Path $TimeFilePath)) { return $true }

    try {
        $lastCheck = [datetime]::ParseExact((Get-Content -Path $TimeFilePath), 'yyyy-MM-dd', $null)
        return ((Get-Date).Date - $lastCheck.Date).TotalDays -gt $IntervalDays
    } catch {
        return $true
    }
}

function Save-UpdateTimestamp {
    <#
    .SYNOPSIS
        Saves the current date as the last update timestamp
    .PARAMETER TimeFilePath
        Path to the file storing the last execution timestamp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TimeFilePath
    )

    (Get-Date -Format 'yyyy-MM-dd') | Out-File -FilePath $TimeFilePath -Force
}

# Check for profile and PowerShell updates (single interval gate) - skip in light mode
if (-not $script:LightMode -and -not $debug -and (Test-UpdateDue -TimeFilePath $timeFilePath -IntervalDays $updateInterval)) {
    Update-Profile
    Update-PowerShell
    Save-UpdateTimestamp -TimeFilePath $timeFilePath
} elseif ($script:LightMode) {
    # Silent in light mode
} elseif (-not $debug) {
    Write-Warning "Profile/PowerShell update skipped. Last update check was within the last $updateInterval day(s)."
} else {
    Write-Warning "Skipping profile/PowerShell update check in debug mode"
}

function Update-PowerShell {
    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ([Version]$currentVersion -lt [Version]$latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            $updated = $false
            if ($IsWindows) {
                $updated = Invoke-WindowsPowerShellUpgrade
            } elseif ($IsMacOS) {
                $updated = Invoke-MacPowerShellUpgrade
            } else {
                Write-Warning "Automatic PowerShell updates are not supported on this operating system."
            }

            if ($updated) {
                Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
            }
        } else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}

function Clear-Cache {
    Write-Host "Clearing cache..." -ForegroundColor Cyan

    if ($IsWindows) {
        Clear-WindowsCache
    } elseif ($IsMacOS) {
        Clear-MacCache
    } else {
        Write-Host "Unsupported operating system" -ForegroundColor Red
        return
    }

    Write-Host "Cache clearing completed." -ForegroundColor Green
}


# OS-agnostic Utility Functions

# Quick Access to Editing the Profile
function Edit-Profile {
    code $PROFILE
}
Set-Alias -Name ep -Value Edit-Profile

# Network Utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

function reload-profile {
    & $profile
}

# Enhanced Listing
function ll { Get-ChildItem -Path . -Force | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function gcl { git clone "$args" }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}

# Quick Access to System Information
# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

# Enhanced PowerShell Experience
# Enhanced PSReadLine Configuration
# Import PSReadLine module
if ($IsWindows) {
    try { Import-Module PSReadLine }
    catch {
        Write-Warning "$_"
    }
}

if (Get-Command Set-PSReadLineOption -ErrorAction SilentlyContinue) {

    # options common to PSReadLine v1+ (PowerShell 5 and Core)
    $commonOpts = @{
        EditMode                      = 'Windows'
        HistoryNoDuplicates           = $true
        HistorySearchCursorMovesToEnd = $true
        Colors                        = @{
            Command   = '#87CEEB'  # SkyBlue
            Parameter = '#98FB98'  # PaleGreen
            Operator  = '#FFB6C1'  # LightPink
            Variable  = '#DDA0DD'  # Plum
            String    = '#FFDAB9'  # PeachPuff
            Number    = '#B0E0E6'  # PowderBlue
            Type      = '#F0E68C'  # Khaki
            Comment   = '#D3D3D3'  # LightGray
            Keyword   = '#8367c7'  # Violet
            Error     = '#FF6347'  # Tomato
        }
        BellStyle                     = 'Visual'
    }

    Set-PSReadLineOption @commonOpts
}

# Custom key handlers
# Define key handler mappings
$keyHandlers = @{
    UpArrow          = 'HistorySearchBackward'
    DownArrow        = 'HistorySearchForward'
    Tab              = 'MenuComplete'
    'Ctrl+d'         = 'DeleteChar'
    'Ctrl+w'         = 'BackwardDeleteWord'
    'Alt+d'          = 'DeleteWord'
    'Ctrl+LeftArrow' = 'BackwardWord'
    'Ctrl+RightArrow'= 'ForwardWord'
    'Ctrl+z'         = 'Undo'
    'Ctrl+y'         = 'Redo'
}

# Apply all key handlers
foreach ($key in $keyHandlers.GetEnumerator()) {
    $params = @{
        Key      = $key.Name
        Function = $key.Value
    }
    Set-PSReadLineKeyHandler @params
}

# Custom functions for PSReadLine
Set-PSReadLineOption -AddToHistoryHandler {
    param($line)
    $sensitive = @('password', 'secret', 'token', 'apikey', 'connectionstring')
    $hasSensitive = $sensitive | Where-Object { $line -match $_ }
    return ($null -eq $hasSensitive)
}

# Improved prediction settings (PS5/Core compatible)
if ((Get-Command Set-PSReadLineOption -ErrorAction SilentlyContinue).Parameters.ContainsKey('PredictionSource')) {
    $psrl = (Get-Module PSReadLine).Version
    $source = if ($psrl -ge [Version]'2.1') { 'HistoryAndPlugin' } else { 'History' }
    Set-PSReadLineOption -PredictionSource $source -PredictionViewStyle ListView
}
Set-PSReadLineOption -MaximumHistoryCount 10000

# Custom completion for common commands
$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $customCompletions = @{
        'git'  = @('status', 'add', 'commit', 'push', 'pull', 'clone', 'checkout')
        'npm'  = @('install', 'start', 'run', 'test', 'build')
        'deno' = @('run', 'compile', 'bundle', 'test', 'lint', 'fmt', 'cache', 'info', 'doc', 'upgrade')
    }

    $command = $commandAst.CommandElements[0].Value
    if ($customCompletions.ContainsKey($command)) {
        $customCompletions[$command] | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $scriptblock

$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    dotnet complete --position $cursorPosition $commandAst.ToString() |
    ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock

# Initialize Oh My Posh theme
function Get-Theme {
    # Output the prompt theme using Oh My Posh
    Write-Host "Using Oh My Posh theme from $OhMyPoshTheme" -ForegroundColor Cyan
    if ($IsMacOS) {
        $OhMyPoshCommand = "/opt/homebrew/bin/oh-my-posh"
    } elseif ($IsWindows) {
        $OhMyPoshCommand = (Get-Command -Name 'oh-my-posh.exe' -ErrorAction SilentlyContinue).Source
    }

    if ($OhMyPoshCommand -and (Test-Path $OhMyPoshCommand -ErrorAction SilentlyContinue)) {
        & $OhMyPoshCommand init pwsh --config $OhMyPoshTheme | Invoke-Expression
    } else {
        Write-Warning "Oh My Posh not found. Skipping theme initialization."
    }
}

# Check and install Homebrew on macOS
if ($IsMacOS) {
    if (-not (Test-Path /opt/homebrew/bin)) {
        Write-Host "Homebrew not found. Installing Homebrew..." -ForegroundColor Yellow
        try {
            bash -c '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            # Add Homebrew to PATH
            $homebrewPath = "/opt/homebrew/bin"
            if ($env:PATH -notlike "*$homebrewPath*") {
                $env:PATH = "$homebrewPath" + ":" + "$env:PATH"
            }

            Write-Host "Homebrew installed successfully!" -ForegroundColor Green
        } catch {
            Write-Error "Failed to install Homebrew: $_"
        }
    } else {
        # Ensure Homebrew is in PATH
        $homebrewPath = "/opt/homebrew/bin"
        if ($env:PATH -notlike "*$homebrewPath*") {
            $env:PATH = "$homebrewPath" + ":" + "$env:PATH"
        }
        Set-Alias brew /opt/homebrew/bin/brew
        Write-Host "Homebrew found at $homebrewPath" -ForegroundColor Green
    }

    # Install Mole cleanup tool if not present
    function Install-Mole {
        <#
        .SYNOPSIS
            Installs Mole - a macOS tool to clean and organize files.
        .DESCRIPTION
            Checks if Mole is installed and installs it via Homebrew if not present.
            Mole is a native macOS application for cleaning unnecessary files and organizing storage.
        .EXAMPLE
            Install-Mole
        .LINK
            https://github.com/tw93/Mole
        #>
        [CmdletBinding()]
        param()

        if (-not $IsMacOS) {
            Write-Warning "Mole is only available for macOS"
            return $false
        }

        if (-not (Get-Command brew -ErrorAction SilentlyContinue)) {
            Write-Warning "Homebrew is required to install Mole. Please install Homebrew first."
            return $false
        }

        # Check if Mole.app exists
        $moleAppPath = "/Applications/Mole.app"
        if (Test-Path $moleAppPath) {
            Write-Host "Mole is already installed at $moleAppPath" -ForegroundColor Green
            return $true
        }

        Write-Host "Installing Mole via Homebrew..." -ForegroundColor Cyan
        try {
            brew install --cask mole
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ Mole installed successfully" -ForegroundColor Green
                Write-Host "  Location: $moleAppPath" -ForegroundColor Gray
                Write-Host "  Launch from Applications or use 'Open-Mole'" -ForegroundColor Gray
                return $true
            } else {
                Write-Warning "Mole installation completed with exit code $LASTEXITCODE"
                return $false
            }
        } catch {
            Write-Error "Failed to install Mole: $_"
            return $false
        }
    }

    # Helper function to open Mole
    function Open-Mole {
        <#
        .SYNOPSIS
            Opens the Mole cleanup application.
        .DESCRIPTION
            Launches Mole to clean unnecessary files and organize storage on macOS.
        .EXAMPLE
            Open-Mole
            Opens the Mole application
        #>
        [CmdletBinding()]
        param()

        $moleAppPath = "/Applications/Mole.app"
        if (-not (Test-Path $moleAppPath)) {
            Write-Warning "Mole is not installed. Run 'Install-Mole' to install it."
            return
        }

        Write-Host "Opening Mole..." -ForegroundColor Cyan
        try {
            open -a Mole
        } catch {
            Write-Error "Failed to open Mole: $_"
        }
    }

    # Convenient alias
    Set-Alias -Name mole -Value Open-Mole -Description "Open Mole cleanup tool"
}

## Final Line to set prompt
Get-Theme

# Generic font detection that defers to platform-specific functions
function Test-FontInstalled {
    param ([string]$FontName)
    if ($IsWindows) {
        return Test-WindowsFont -FontName $FontName
    } elseif ($IsMacOS) {
        return Test-MacFont -FontName $FontName
    }
    return $false
}


function Search-YouTube {
    <#
    .SYNOPSIS
        Opens a YouTube search in the default browser
    .DESCRIPTION
        Constructs a YouTube search URL from the provided search terms and opens it
        in the default web browser.
    .PARAMETER SearchTerms
        The search terms to query on YouTube
    .EXAMPLE
        Search-YouTube powershell tutorial
    .EXAMPLE
        yt how to code
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments)]
        [string[]]$SearchTerms
    )

    if (-not $SearchTerms -or $SearchTerms.Count -eq 0) {
        Write-Warning "No search terms provided. Usage: yt <search terms>"
        return
    }

    $baseUrl = 'https://www.youtube.com/results?search_query='
    $encodedQuery = [System.Uri]::EscapeDataString($SearchTerms -join ' ')
    $url = "$baseUrl$encodedQuery"

    Write-Host "Searching YouTube for: $($SearchTerms -join ' ')" -ForegroundColor Cyan
    Write-Host "URL: $url" -ForegroundColor DarkGray
    Start-Process $url
}

# Alias for backward compatibility
Set-Alias -Name yt -Value Search-YouTube

function Get-InstalledModuleFast {
    param(
        #Modules to filter for. Wildcards are supported.
        [string]$Name,
        #Path(s) to search for modules. Defaults to your PSModulePath paths
        [string[]]$ModulePath = ($env:PSModulePath -split [System.IO.Path]::PathSeparator),
        #Return all installed modules and not just the latest versions
        [switch]$All
    )

    $allModules = foreach ($pathItem in $ModulePath) {
        #Skip paths that don't exist
        if (-not (Test-Path $pathItem)) { continue }

        Get-ChildItem -Path $pathItem -Filter "*.psd1" -Recurse -ErrorAction SilentlyContinue
        | ForEach-Object {
            $manifestPath = $_
            $manifestName = (Split-Path -ea 0 $_ -Leaf) -replace "\.psd1$"
            if ($Name -and $ManifestName -notlike $Name) { return }
            $versionPath = Split-Path -ea 0 $_
            [Version]$versionRoot = ( $versionPath | Split-Path -ea 0 -Leaf) -as [Version]

            if (-not $versionRoot) {
                # Try for a non-versioned module by resetting the search
                $versionPath = $_
            }

            $moduleRootName = (Split-Path -ea 0 $versionPath | Split-Path -ea 0 -Leaf)
            if ($moduleRootName -ne $manifestName) {
                Write-Verbose "$manifestPath doesnt match a module folder, not a module manifest. skipping..."
                return
            }

            try {
                $fullInfo = Import-PowerShellDataFile -Path $_ -Ea Stop
            } catch {
                Write-Warning "Failed to import module manifest for $manifestPath. Skipping for now..."
                return
            }

            if (-not $fullInfo) { return }
            $manifestVersion = $fullInfo.ModuleVersion -as [Version]
            if (-not $manifestVersion) { Write-Warning "$manifestPath has an invalid or missing ModuleVersion in the manifest. You should fix this. Skipping for now..."; return }

            if ($versionRoot -and $versionRoot -ne $manifestVersion) { Write-Warning "$_ has a different version in the manifest ($manifestVersion) than the folder name ($versionRoot). You should fix this. Skipping for now..."; return }

            #Add prerelease info if present
            if ($fullInfo.PrivateData.PSData.Prerelease) {
                $manifestVersion = [Management.Automation.SemanticVersion]"$manifestVersion-$($fullInfo.PrivateData.PSData.Prerelease)"
            }

            [PSCustomObject][ordered]@{
                Name    = $moduleRootName
                Version = $manifestVersion
                Path    = $_.FullName
            }
        }
    }

    $modulesProcessed = @{}

    $allModules
    | Sort-Object -Property Name, @{Expression = 'Version'; Descending = $true }
    | ForEach-Object {
        if ($All) { return $_ }
        if (-not $modulesProcessed.($_.Name)) {
            $modulesProcessed.($_.Name) = $true
            return $_
        }
    }
}
function Update-Modules {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [switch]$AllowPrerelease, # Include prerelease versions in updates
        [string]$Name = '*', # Module name filter, '*' for all modules
        [int]$ThrottleLimit = 20   # Control parallel execution limit
    )

    # Initialize by getting all installed modules matching the name filter
    Write-Host ("Retrieving all installed modules ...") -ForegroundColor Green
    [array]$CurrentModules = Get-InstalledModuleFast -Name $Name -ErrorAction SilentlyContinue |
    Select-Object Name, Version |
    Sort-Object Name

    # Exit if no modules are found
    if (-not $CurrentModules) {
        Write-Host ("No modules found.") -ForegroundColor Gray
        return
    }

    # Display initial status
    Write-Host ("{0} modules found." -f $CurrentModules.Count) -ForegroundColor Gray
    Write-Host ("Updating installed modules to the latest {0} version ..." -f $(if ($AllowPrerelease) { "PreRelease" } else { "Production" })) -ForegroundColor Green

    # Store original versions for comparison in summary
    $script:OldVersions = @{}
    foreach ($Module in $CurrentModules) {
        $script:OldVersions[$Module.Name] = $Module.Version
    }

    # Capture WhatIf preference before parallel execution
    $WhatIfEnabled = $WhatIfPreference.IsPresent

    # Process updates in parallel for better performance
    $CurrentModules | ForEach-Object -Parallel {
        $Module = $_
        $AllowPrerelease = $using:AllowPrerelease
        $WhatIf = $using:WhatIfEnabled

        try {
            # Find the latest available version
            $findParams = @{
                Name            = $Module.Name
                AllowPrerelease = $AllowPrerelease
                ErrorAction     = 'Stop'
            }

            $latest = Find-Module @findParams | Select-Object -First 1

            # Update only if a newer version is available
            if ($latest.Version -and $Module.Version -and ([version]$latest.Version -gt [version]$Module.Version)) {
                $updateParams = @{
                    Name            = $Module.Name
                    AllowPrerelease = $AllowPrerelease
                    AcceptLicense   = $true
                    Force           = $true
                    WhatIf          = $WhatIf
                    ErrorAction     = 'Stop'
                }

                Update-Module @updateParams
                Write-Host ("Updated {0} from version {1} to {2}" -f $Module.Name, $Module.Version, $latest.Version) -ForegroundColor Yellow

                # Remove older versions to save disk space
                if (-not $WhatIf) {
                    $AllVersions = Get-InstalledModule -Name $Module.Name -AllVersions | Sort-Object PublishedDate -Descending
                    foreach ($Version in $AllVersions | Select-Object -Skip 1) {
                        try {
                            Uninstall-Module -Name $Module.Name -RequiredVersion $Version.Version -Force -ErrorAction Stop
                            Write-Host ("Uninstalled older version {0} of {1}" -f $Version.Version, $Module.Name) -ForegroundColor Gray
                        } catch {
                            Write-Warning ("Failed to uninstall version {0} of {1}: {2}" -f $Version.Version, $Module.Name, $_.Exception.Message)
                        }
                    }
                }
            } else {
                Write-Host ("{0} is up to date (version {1})" -f $Module.Name, $Module.Version) -ForegroundColor Cyan
            }
        } catch {
            Write-Warning ("{0}: {1}" -f $Module.Name, $_.Exception.Message)
        }
    } -ThrottleLimit $ThrottleLimit

    # Generate summary report of all updates
    if (-not $WhatIfEnabled) {
        $NewModules = Get-InstalledModule -Name $Name -ErrorAction SilentlyContinue |
        Select-Object Name, Version |
        Sort-Object Name

        # Compare new versions with original versions
        $UpdatedModules = $NewModules | Where-Object {
            $script:OldVersions[$_.Name] -ne $_.Version
        }

        # Display summary of changes
        if ($UpdatedModules) {
            Write-Host "`nUpdated modules:" -ForegroundColor Green
            foreach ($Module in $UpdatedModules) {
                Write-Host ("- {0}: {1} -> {2}" -f $Module.Name, $script:OldVersions[$Module.Name], $Module.Version) -ForegroundColor Green
            }
        } else {
            Write-Host "`nNo modules were updated." -ForegroundColor Gray
        }
    }
}
function Install-LatestModule {
    <#
    .SYNOPSIS
        Removes all existing versions of a module and installs the latest version.

    .DESCRIPTION
        This function uninstalls all existing versions of specified modules and then
        installs the latest version from the PowerShell Gallery. Useful when you get
        warnings about side-by-side installations.

    .PARAMETER Name
        The name of the module(s) to reinstall. Accepts wildcards and pipeline input.

    .PARAMETER AllowPrerelease
        Include prerelease versions when finding the latest version.

    .PARAMETER Force
        Skip confirmation prompts.

    .EXAMPLE
        Install-LatestModule -Name Pester
        Removes all versions of Pester and installs the latest.

    .EXAMPLE
        'PSReadLine', 'Pester' | Install-LatestModule -Force
        Reinstalls both modules without prompts.

    .EXAMPLE
        ls ~/.local/share/powershell/Modules | Install-LatestModule
        Reinstalls all modules in the user modules directory.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ModuleName', 'PSChildName')]
        [string[]]$Name,

        [switch]$AllowPrerelease,

        [switch]$Force
    )

    begin {
        Write-Host "Installing latest versions of modules..." -ForegroundColor Green
    }

    process {
        foreach ($ModuleName in $Name) {
            try {
                # Get all installed versions
                $installedVersions = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction SilentlyContinue

                if (-not $installedVersions) {
                    Write-Warning "Module '$ModuleName' is not installed via PowerShellGet. Attempting to install..."

                    # Try to install if not found
                    $installParams = @{
                        Name            = $ModuleName
                        AllowPrerelease = $AllowPrerelease
                        AcceptLicense   = $true
                        Force           = $true
                        ErrorAction     = 'Stop'
                    }

                    if ($PSCmdlet.ShouldProcess($ModuleName, "Install latest version")) {
                        Install-Module @installParams
                        Write-Host "Installed $ModuleName" -ForegroundColor Green
                    }
                    continue
                }

                # Find the latest version available
                $findParams = @{
                    Name            = $ModuleName
                    AllowPrerelease = $AllowPrerelease
                    ErrorAction     = 'Stop'
                }

                $latest = Find-Module @findParams | Select-Object -First 1
                $currentVersions = $installedVersions.Version -join ', '

                # Check if already at latest version and only one version installed
                if ($installedVersions.Count -eq 1 -and $installedVersions[0].Version -eq $latest.Version) {
                    Write-Host "`nModule: $ModuleName" -ForegroundColor Cyan
                    Write-Host "  Already at latest version $($latest.Version)" -ForegroundColor Green
                    continue
                }

                Write-Host "`nModule: $ModuleName" -ForegroundColor Cyan
                Write-Host "  Current versions: $currentVersions" -ForegroundColor Gray
                Write-Host "  Latest version: $($latest.Version)" -ForegroundColor Yellow

                # Determine if we should proceed
                $shouldProceed = $Force -or $PSCmdlet.ShouldProcess(
                    "$ModuleName (uninstall $($installedVersions.Count) version(s) and install $($latest.Version))",
                    "Remove all versions and install latest"
                )

                if ($shouldProceed) {
                    # Uninstall all existing versions
                    foreach ($version in $installedVersions) {
                        try {
                            Uninstall-Module -Name $ModuleName -RequiredVersion $version.Version -Force -ErrorAction Stop
                            Write-Host "  Uninstalled version $($version.Version)" -ForegroundColor Gray
                        } catch {
                            # If Uninstall-Module fails, try manual removal
                            Write-Warning "Failed to uninstall $ModuleName version $($version.Version): $($_.Exception.Message)"
                            Write-Host "  Attempting manual removal..." -ForegroundColor Yellow

                            try {
                                # Try to get the module installation path from InstalledLocation first
                                $modulePath = $version.InstalledLocation

                                # If InstalledLocation is not available, construct the path manually
                                if (-not $modulePath -or -not (Test-Path $modulePath)) {
                                    # Try common module paths
                                    $possiblePaths = @(
                                        (Join-Path $HOME ".local/share/powershell/Modules/$ModuleName/$($version.Version)")
                                        (Join-Path $env:ProgramFiles "PowerShell/Modules/$ModuleName/$($version.Version)")
                                        (Join-Path ([Environment]::GetFolderPath('MyDocuments')) "PowerShell/Modules/$ModuleName/$($version.Version)")
                                    )

                                    $modulePath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
                                }

                                if ($modulePath -and (Test-Path $modulePath)) {
                                    Remove-Item -Path $modulePath -Recurse -Force -ErrorAction Stop
                                    Write-Host "  Manually removed version $($version.Version) from $modulePath" -ForegroundColor Gray
                                } else {
                                    Write-Warning "Could not find installation path for $ModuleName version $($version.Version)"
                                }
                            } catch {
                                Write-Warning "Manual removal also failed: $($_.Exception.Message)"
                            }
                        }
                    }

                    # Install the latest version
                    $installParams = @{
                        Name            = $ModuleName
                        AllowPrerelease = $AllowPrerelease
                        AcceptLicense   = $true
                        Force           = $true
                        ErrorAction     = 'Stop'
                    }

                    Install-Module @installParams
                    Write-Host "  Installed version $($latest.Version)" -ForegroundColor Green
                }
            } catch {
                Write-Error "Failed to process module '$ModuleName': $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Host "`nModule reinstallation complete." -ForegroundColor Green
    }
}
function Show-Tree {
    [CmdletBinding(DefaultParameterSetName = 'Dirs')]
    param(
        [Parameter(Position = 0)]
        [string]$Path = '.',

        [Parameter(Position = 1)]
        [int]$Depth = [int]::MaxValue,

        [Parameter(ParameterSetName = 'Files')]
        [switch]$ShowFiles
    )

    begin {
        try {
            $rootItem = Get-Item -LiteralPath $Path -ErrorAction Stop
        } catch {
            Write-Error "Path not found: $Path"
            return
        }

        function Invoke-Tree {
            param(
                [IO.FileSystemInfo]$Item,
                [string]$Prefix = '',
                [int]   $CurrentDepth = 1
            )

            if ($CurrentDepth -gt $Depth) { return }

            $children = Get-ChildItem -LiteralPath $Item.FullName -Force -ErrorAction SilentlyContinue |
            Where-Object { $ShowFiles.IsPresent -or $_.PSIsContainer }

            for ($i = 0; $i -lt $children.Count; $i++) {
                $child = $children[$i]
                $isLast = ($i -eq $children.Count - 1)
                $branch = if ($isLast) { '└── ' } else { '├── ' }
                Write-Output "$Prefix$branch$($child.Name)"

                if ($child.PSIsContainer) {
                    $nextPrefix = $Prefix + $(if ($isLast) { '    ' } else { '│   ' })
                    Invoke-Tree -Item $child -Prefix $nextPrefix -CurrentDepth ($CurrentDepth + 1)
                }
            }
        }
    }

    process {
        Write-Output $rootItem.FullName
        Invoke-Tree -Item $rootItem
    }
}

Set-Alias tree Show-Tree

function Get-StoicQuote {
    <#
    .SYNOPSIS
        Retrieves a random stoic quote from an API and displays it in a formatted manner.

    .DESCRIPTION
        This function queries the stoic-quotes.com API to fetch a random quote from famous
        Stoic philosophers like Marcus Aurelius, Seneca, and Epictetus. The quote is then
        displayed in a nicely formatted output with the author attribution.

    .PARAMETER Raw
        Returns the raw JSON object instead of formatted text output.

    .EXAMPLE
        Get-StoicQuote
        Displays a formatted stoic quote.

    .EXAMPLE
        Get-StoicQuote -Raw
        Returns the raw JSON response from the API.

    .NOTES
        This function requires an internet connection to query the API.
        API endpoint: https://stoic-quotes.com/api/quote
    #>

    [CmdletBinding()]
    param(
        [switch]$Raw
    )

    try {
        # API endpoint for random stoic quotes
        $apiUrl = "https://stoic-quotes.com/api/quote"

        # Make the API request
        Write-Verbose "Fetching quote from: $apiUrl"
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -ErrorAction Stop

        if ($Raw) {
            # Return raw JSON response
            return $response
        } else {
            # Format and display the quote nicely
            $quote = $response.text
            $author = $response.author

            # Create a formatted output
            Write-Host ""
            Write-Host "💭 " -ForegroundColor Yellow -NoNewline
            Write-Host "Stoic Wisdom" -ForegroundColor Cyan
            Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
            Write-Host ""

            # Word wrap the quote if it's too long
            $maxWidth = 70
            if ($quote.Length -gt $maxWidth) {
                $words = $quote -split '\s+'
                $currentLine = ""

                foreach ($word in $words) {
                    if (($currentLine + $word).Length -gt $maxWidth) {
                        Write-Host "  $currentLine" -ForegroundColor White
                        $currentLine = $word + " "
                    } else {
                        $currentLine += $word + " "
                    }
                }
                if ($currentLine.Trim()) {
                    Write-Host "  $($currentLine.Trim())" -ForegroundColor White
                }
            } else {
                Write-Host "  $quote" -ForegroundColor White
            }

            Write-Host ""
            Write-Host "  - $author" -ForegroundColor Green
            Write-Host ""
        }
    } catch {
        Write-Error "Failed to retrieve stoic quote: $($_.Exception.Message)"

        # Fallback to a hardcoded quote if API fails
        Write-Host ""
        Write-Host "💭 " -ForegroundColor Yellow -NoNewline
        Write-Host "Stoic Wisdom (Offline)" -ForegroundColor Cyan
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  You have power over your mind - not outside events." -ForegroundColor White
        Write-Host "  Realize this, and you will find strength." -ForegroundColor White
        Write-Host ""
        Write-Host "  - Marcus Aurelius" -ForegroundColor Green
        Write-Host ""
    }
}
function Get-CredentialsFromKeyVault {
    <#
    .SYNOPSIS
        Retrieves application credentials from Azure Key Vault as SecureStrings
    .PARAMETER KeyVaultName
        The name of the Azure Key Vault containing the credentials
    .OUTPUTS
        Hashtable with ClientId, ClientSecret (SecureString), and TenantId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyVaultName
    )

    try {
        $clientId = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "app-client-id" -AsPlainText -ErrorAction Stop
        $clientSecretSecure = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "app-client-secret" -ErrorAction Stop).SecretValue
        $tenantId = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "tenant-id" -AsPlainText -ErrorAction Stop

        return @{
            ClientId           = $clientId
            ClientSecretSecure = $clientSecretSecure
            TenantId           = $tenantId
        }
    } catch {
        throw "Failed to retrieve credentials from Key Vault '$KeyVaultName': $($_.Exception.Message)"
    }
}
function Connect-GraphSession {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using Azure Key Vault credentials
    .DESCRIPTION
        Securely retrieves credentials from Azure Key Vault and establishes
        a Microsoft Graph connection using Azure.Identity ClientSecretCredential.
        Credentials are cleaned up after use.
    .PARAMETER KeyVaultName
        The name of the Azure Key Vault. Defaults to 'jrgsrs-keyvault'.
    .EXAMPLE
        Connect-GraphSession
    .EXAMPLE
        Connect-GraphSession -KeyVaultName "mycompany-keyvault"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$KeyVaultName = "jrgsrs-keyvault"
    )

    $clientSecretCredential = $null

    try {
        # Check if Azure.Identity is available
        if (-not ([System.Management.Automation.PSTypeName]'Azure.Identity.ClientSecretCredential').Type) {
            # Try to load the assembly
            try {
                Add-Type -AssemblyName "Azure.Identity" -ErrorAction Stop
            } catch {
                throw "Azure.Identity assembly not found. Install the Microsoft.Graph module or Azure.Identity package."
            }
        }

        # Connect to Azure if needed
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Host "Connecting to Azure..." -ForegroundColor Cyan
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }

        # Retrieve credentials
        Write-Host "Retrieving credentials from Key Vault..." -ForegroundColor Cyan
        $creds = Get-CredentialsFromKeyVault -KeyVaultName $KeyVaultName

        # Convert SecureString to plain text for Azure.Identity
        $clientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($creds.ClientSecretSecure)
        )

        # Build Azure.Identity ClientSecretCredential (required by Connect-MgGraph)
        $clientSecretCredential = [Azure.Identity.ClientSecretCredential]::new(
            $creds.TenantId,
            $creds.ClientId,
            $clientSecretPlain
        )

        # Clear plain text secret immediately
        $clientSecretPlain = $null

        # Connect to Graph using proper credential type
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -ClientSecretCredential $clientSecretCredential -TenantId $creds.TenantId -NoWelcome -ErrorAction Stop

        # Verify connection
        $context = Get-MgContext
        if ($context) {
            Write-Host "Connected to Microsoft Graph successfully as $($context.AppName)" -ForegroundColor Green
        } else {
            throw "Graph context is null after connection"
        }
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    } finally {
        # Clean up sensitive data from memory
        if ($creds) {
            $creds.ClientSecretSecure = $null
            $creds = $null
        }
        if ($clientSecretCredential) {
            $clientSecretCredential = $null
        }
        [System.GC]::Collect()
    }
}
# Create an alias for easier access
Set-Alias -Name "stoic" -Value "Get-StoicQuote" -Description "Get a random stoic quote"
# Optional: Display a quote when the profile loads (uncomment the line below)
#Get-StoicQuote
function Update-NpmPackage {
    <#
    .SYNOPSIS
    Updates an npm package globally while handling ENOTEMPTY errors

    .DESCRIPTION
    This function forcibly removes and reinstalls a global npm package to avoid
    ENOTEMPTY errors that can occur during updates. It manually removes directories
    and handles permission issues that prevent npm from properly cleaning up.

    .PARAMETER PackageName
    The name of the npm package to update (e.g., "@anthropic-ai/claude-code")

    .PARAMETER Force
    Force the operation even if warnings are encountered

    .EXAMPLE
    Update-NpmPackage -PackageName "@anthropic-ai/claude-code"

    .EXAMPLE
    Update-NpmPackage -PackageName "@anthropic-ai/claude-code" -Force
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [switch]$Force
    )

    try {
        Write-Host "Updating npm package: $PackageName" -ForegroundColor Green

        # Step 1: Get npm global directory
        Write-Host "Finding npm global directory..." -ForegroundColor Yellow
        $npmGlobalDir = npm root -g
        if ($LASTEXITCODE -ne 0) {
            throw "Could not determine npm global directory"
        }
        Write-Host "Global directory: $npmGlobalDir" -ForegroundColor Cyan

        # Step 2: Check if package is currently installed and get its path
        Write-Host "Checking current installation..." -ForegroundColor Yellow
        $packagePath = Join-Path $npmGlobalDir $PackageName
        $packageExists = Test-Path $packagePath

        if ($packageExists) {
            Write-Host "Package found at: $packagePath" -ForegroundColor Cyan
        } else {
            Write-Host "Package not currently installed globally" -ForegroundColor Yellow
        }

        # Step 3: Force uninstall the package
        Write-Host "Force removing existing package via npm..." -ForegroundColor Yellow
        npm uninstall -g $PackageName --force 2>$null

        # Step 4: Manually remove the directory if it still exists
        if (Test-Path $packagePath) {
            Write-Host "Package directory still exists, manually removing..." -ForegroundColor Yellow

            # Try to remove with PowerShell first
            try {
                Remove-Item -Path $packagePath -Recurse -Force -ErrorAction Stop
                Write-Host "Successfully removed directory with PowerShell" -ForegroundColor Green
            } catch {
                Write-Host "PowerShell removal failed, trying with system commands..." -ForegroundColor Yellow

                # Try with rm command (works on macOS/Linux)
                if ($IsMacOS -or $IsLinux) {
                    $rmResult = Remove-Item -Path $packagePath -Recurse -Force -ErrorAction SilentlyContinue 2>&1
                    if ($?) {
                        Write-Host "Successfully removed directory with Remove-Item command" -ForegroundColor Green
                    } else {
                        Write-Warning "Remove-Item command failed: $rmResult"
                    }
                }
            }
        }

        # Step 5: Clear npm cache
        Write-Host "Clearing npm cache..." -ForegroundColor Yellow
        npm cache clean --force

        # Step 6: Wait a moment for filesystem to settle
        Start-Sleep -Seconds 2

        # Step 7: Install the package fresh
        Write-Host "Installing package..." -ForegroundColor Yellow
        if ($Force) {
            $result = npm install -g $PackageName --force 2>&1
        } else {
            $result = npm install -g $PackageName 2>&1
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully updated $PackageName" -ForegroundColor Green

            # Show the new version
            $newVersion = npm list -g $PackageName --depth=0 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "New installation:" -ForegroundColor Cyan
                Write-Host $newVersion -ForegroundColor White
            }
        } else {
            Write-Error "Failed to install $PackageName. Exit code: $LASTEXITCODE"
            Write-Host "npm output:" -ForegroundColor Red
            Write-Host ($result | Out-String) -ForegroundColor Red

            # Additional troubleshooting info
            Write-Host "`nTroubleshooting information:" -ForegroundColor Yellow
            Write-Host "Package path: $packagePath" -ForegroundColor White
            Write-Host "Directory exists: $(Test-Path $packagePath)" -ForegroundColor White

            if (Test-Path $packagePath) {
                Write-Host "Directory contents:" -ForegroundColor White
                Get-ChildItem $packagePath -Force | Format-Table Name, Length, LastWriteTime
            }
        }

    } catch {
        Write-Error "An error occurred while updating the package: $($_.Exception.Message)"
    }
}

# Helper function for common packages
function Update-ClaudeCode {
    <#
    .SYNOPSIS
    Shortcut function specifically for updating @anthropic-ai/claude-code

    .EXAMPLE
    Update-ClaudeCode
    #>
    Update-NpmPackage -PackageName "@anthropic-ai/claude-code"
}

function Get-ColoredText {
    param(
        [string]$Text,
        [string]$Color
    )

    if ($NoColor) {
        return $Text
    }
    return "$($script:Colors[$Color])$Text$($script:Colors.Reset)"
}

function Get-DotJustifiedLine {
    param(
        [string]$Key,
        [string]$Value,
        [int]$TargetWidth = 80
    )

    $keyLen = $Key.Length + 1 # +1 for colon
    $valueLen = $Value.Length
    $dotsNeeded = $TargetWidth - $keyLen - $valueLen - 2

    if ($dotsNeeded -lt 1) { $dotsNeeded = 1 }

    return "." * $dotsNeeded
}

function Get-SystemInfo {
    [CmdletBinding()]
    param(
        [int]$CacheMinutes = 60,
        [switch]$NoCache
    )

    # Cache file location - use platform-appropriate temp directory
    $cacheFile = if ($IsWindows) {
        "$env:TEMP\PSProfile_SystemInfo_Cache.json"
    } else {
        "$HOME/.cache/powershell/PSProfile_SystemInfo_Cache.json"
    }

    # Ensure cache directory exists on non-Windows platforms
    if (-not $IsWindows) {
        $cacheDir = Split-Path $cacheFile -Parent
        if (-not (Test-Path $cacheDir)) {
            New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
        }
    }

    # Try to load from cache if not forced to skip
    if (-not $NoCache -and (Test-Path $cacheFile)) {
        try {
            $cacheData = Get-Content $cacheFile -Raw | ConvertFrom-Json
            $cacheTime = [DateTime]$cacheData.CacheTime

            # Check if cache is still valid
            if ((Get-Date) -lt $cacheTime.AddMinutes($CacheMinutes)) {
                # Update dynamic fields and return cached data
                $info = @{}
                $cacheData.PSObject.Properties | Where-Object { $_.Name -ne 'CacheTime' } | ForEach-Object {
                    $info[$_.Name] = $_.Value
                }

                # Refresh only dynamic fields (uptime, disk, battery)
                if ($IsWindows) {
                    # Uptime
                    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                    $days = $uptime.Days
                    $hours = $uptime.Hours
                    $mins = $uptime.Minutes
                    $uptimeStr = ""
                    if ($days -gt 0) { $uptimeStr += "$days day$($days -ne 1 ? 's' : ''), " }
                    if ($hours -gt 0) { $uptimeStr += "$hours hour$($hours -ne 1 ? 's' : ''), " }
                    $uptimeStr += "$mins min$($mins -ne 1 ? 's' : '')"
                    $info.Uptime = $uptimeStr

                    # Disk Usage
                    $disk = Get-PSDrive -Name C
                    if ($disk) {
                        $usedGB = [math]::Round(($disk.Used / 1GB), 1)
                        $totalGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 1)
                        $info.Disk = "${usedGB}G / ${totalGB}G"
                    }

                    # Battery (if laptop)
                    try {
                        $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
                        if ($battery) {
                            $info.Battery = "$($battery.EstimatedChargeRemaining)%"
                        }
                    } catch { }
                } elseif ($IsMacOS) {
                    # Uptime
                    try {
                        $uptime = Get-Uptime
                        $days = $uptime.Days
                        $hours = $uptime.Hours
                        $mins = $uptime.Minutes
                        $uptimeStr = ""
                        if ($days -gt 0) { $uptimeStr += "$days day$($days -ne 1 ? 's' : ''), " }
                        if ($hours -gt 0) { $uptimeStr += "$hours hour$($hours -ne 1 ? 's' : ''), " }
                        $uptimeStr += "$mins min$($mins -ne 1 ? 's' : '')"
                        $info.Uptime = $uptimeStr
                    } catch {
                        $info.Uptime = "Unknown"
                    }

                    # Disk Usage
                    $diskInfo = df -h / | Select-Object -Skip 1
                    if ($diskInfo) {
                        $diskParts = $diskInfo -split '\s+'
                        $used = $diskParts[2]
                        $total = $diskParts[1]
                        $info.Disk = "$used / $total"
                    }

                    # Battery (if laptop)
                    try {
                        $batteryInfo = pmset -g batt 2>/dev/null
                        if ($batteryInfo -and $batteryInfo -notmatch "No battery available") {
                            $batteryMatch = $batteryInfo | Select-String -Pattern '(\d+)%'
                            if ($batteryMatch) {
                                $info.Battery = "$($batteryMatch.Matches[0].Groups[1].Value)%"
                            }
                        }
                    } catch { }
                }

                return $info
            }
        } catch {
            # Cache read failed, continue with full collection
        }
    }

    # Full system info collection
    $info = @{}

    try {

        if ($IsWindows) {
            # Windows Information
            $computerInfo = Get-ComputerInfo

            # OS Information
            $info.OS = $computerInfo.OsName

            # Kernel
            $info.Kernel = "Windows NT $($computerInfo.WindowsVersion)"

            # Uptime
            $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $days = $uptime.Days
            $hours = $uptime.Hours
            $mins = $uptime.Minutes
            $uptimeStr = ""
            if ($days -gt 0) { $uptimeStr += "$days day$($days -ne 1 ? 's' : ''), " }
            if ($hours -gt 0) { $uptimeStr += "$hours hour$($hours -ne 1 ? 's' : ''), " }
            $uptimeStr += "$mins min$($mins -ne 1 ? 's' : '')"
            $info.Uptime = $uptimeStr

            # Host and User
            $info.Host = $env:COMPUTERNAME
            $info.User = $env:USERNAME

            # Shell
            $shellName = $PSVersionTable.PSEdition -eq "Core" ? "PowerShell Core" : "PowerShell Desktop"
            $poshVersion = $env:POSH_SHELL_VERSION ? " v$($env:POSH_SHELL_VERSION)" : ""
            $info.Shell = "$shellName$poshVersion"

            # CPU
            $cpu = Get-CimInstance Win32_Processor
            $info.CPU = $cpu.Name

            # Model
            $info.Model = "$($computerInfo.CsManufacturer) $($computerInfo.CsModel)".Trim()

            # Memory
            $totalMemGB = [math]::Round($computerInfo.CsTotalPhysicalMemory / 1GB, 1)
            $info.Memory = "$totalMemGB GB"

            # Disk Usage
            $disk = Get-PSDrive -Name C
            if ($disk) {
                $usedGB = [math]::Round(($disk.Used / 1GB), 1)
                $totalGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 1)
                $info.Disk = "${usedGB}G / ${totalGB}G"
            } else {
                $info.Disk = "Unknown"
            }

            # Terminal
            $terminalName = $env:WT_SESSION ? "Windows Terminal" : ($env:TERM_PROGRAM ? $env:TERM_PROGRAM : "Command Prompt")
            $terminalVersion = $env:TERM_PROGRAM_VERSION ? " v$($env:TERM_PROGRAM_VERSION)" : ""
            $info.Terminal = "$terminalName$terminalVersion"

            # Resolution
            try {
                $display = Get-CimInstance -ClassName Win32_VideoController | Select-Object -First 1
                if ($display) {
                    $info.Resolution = "$($display.CurrentHorizontalResolution) x $($display.CurrentVerticalResolution)"
                } else {
                    $info.Resolution = "Unknown"
                }
            } catch {
                $info.Resolution = "Unknown"
            }

            # Battery (if laptop)
            try {
                $battery = Get-CimInstance Win32_Battery
                if ($battery) {
                    $info.Battery = "$($battery.EstimatedChargeRemaining)%"
                }
            } catch {
                # No battery info available (desktop)
            }

            # Admin Status
            $info.Admin = [bool](([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) ? "Yes" : "No"

            # OneDrive Location
            $userProfile = $env:USERPROFILE
            $oneDrivePath = "$userProfile\OneDrive"
            if (Test-Path "$userProfile\OneDrive - *") {
                $oneDrivePath = Get-ChildItem "$userProfile\OneDrive - *" | Select-Object -First 1 -ExpandProperty FullName
            }
            $info.OneDrive = $oneDrivePath

            # Oh My Posh
            try {
                $ohMyPoshCommand = (Get-Command -Name 'oh-my-posh.exe' -ErrorAction Stop).Source
                $ohMyPoshVersion = & $ohMyPoshCommand --version 2>$null
                $info.OhMyPosh = $ohMyPoshVersion ? "v$ohMyPoshVersion" : "Installed"
            } catch {
                $info.OhMyPosh = "Not Found"
            }

            # PSReadLine History
            $psReadLineHistory = [System.IO.Path]::Combine($oneDrivePath, 'PSReadLine', 'PSReadLineHistory.txt')
            $info.PSReadLineHistory = if (Test-Path $psReadLineHistory) { "OneDrive" } else { "Local" }

        } elseif ($IsMacOS) {
            # macOS Information
            # OS Information
            $osInfo = sw_vers
            $info.OS = "$($osInfo | Where-Object { $_ -match 'ProductName' } | ForEach-Object { $_ -replace 'ProductName:\s*', '' }) $($osInfo | Where-Object { $_ -match 'ProductVersion' } | ForEach-Object { $_ -replace 'ProductVersion:\s*', '' })"

            # Kernel
            $kernelInfo = sysctl -n kern.version
            $kernelMatch = $kernelInfo | Select-String -Pattern 'Darwin Kernel Version (\d+\.\d+\.\d+)'
            if ($kernelMatch) {
                $info.Kernel = "Darwin $($kernelMatch.Matches[0].Groups[1].Value)"
            } else {
                $info.Kernel = "Darwin $(sysctl -n kern.osrelease)"
            }

            # Uptime
            try {
                $uptime = Get-Uptime
                $days = $uptime.Days
                $hours = $uptime.Hours
                $mins = $uptime.Minutes
                $uptimeStr = ""
                if ($days -gt 0) { $uptimeStr += "$days day$($days -ne 1 ? 's' : ''), " }
                if ($hours -gt 0) { $uptimeStr += "$hours hour$($hours -ne 1 ? 's' : ''), " }
                $uptimeStr += "$mins min$($mins -ne 1 ? 's' : '')"
                $info.Uptime = $uptimeStr
            } catch {
                $info.Uptime = "Unknown"
            }

            # Host
            $info.Host = hostname

            # User
            $info.User = whoami

            # Shell
            $shellName = $PSVersionTable.PSEdition -eq "Core" ? "PowerShell Core" : "PowerShell Desktop"
            $poshVersion = $env:POSH_SHELL_VERSION ? " v$($env:POSH_SHELL_VERSION)" : ""
            $info.Shell = "$shellName$poshVersion"

            # CPU
            $cpuInfo = sysctl -n machdep.cpu.brand_string
            if ($cpuInfo) {
                $info.CPU = $cpuInfo
            } else {
                $info.CPU = "Unknown"
            }

            # Model (macOS)
            try {
                $modelInfo = system_profiler SPHardwareDataType | Select-String -Pattern 'Model Name:' | ForEach-Object { $_ -replace '.*Model Name:\s*', '' }
                $modelIdentifier = system_profiler SPHardwareDataType | Select-String -Pattern 'Model Identifier:' | ForEach-Object { $_ -replace '.*Model Identifier:\s*', '' }
                if ($modelInfo) {
                    $info.Model = $modelInfo.Trim()
                } elseif ($modelIdentifier) {
                    $info.Model = $modelIdentifier.Trim()
                } else {
                    $info.Model = "Unknown"
                }
            } catch {
                $info.Model = "Unknown"
            }

            # Memory
            $memInfo = sysctl -n hw.memsize
            if ($memInfo) {
                $totalMemGB = [math]::Round($memInfo / 1GB, 1)
                $info.Memory = "$totalMemGB GB"
            } else {
                $info.Memory = "Unknown"
            }

            # Disk Usage
            $diskInfo = df -h / | Select-Object -Skip 1
            if ($diskInfo) {
                $diskParts = $diskInfo -split '\s+'
                $used = $diskParts[2]
                $total = $diskParts[1]
                $info.Disk = "$used / $total"
            } else {
                $info.Disk = "Unknown"
            }

            # Terminal
            $terminalName = $env:TERM_PROGRAM ? $env:TERM_PROGRAM : "Unknown"
            $terminalVersion = $env:TERM_PROGRAM_VERSION ? " v$($env:TERM_PROGRAM_VERSION)" : ""
            $info.Terminal = "$terminalName$terminalVersion"

            # Resolution (if available)
            try {
                $displayInfo = system_profiler SPDisplaysDataType | Select-String -Pattern 'Resolution: (\d+ x \d+)'
                if ($displayInfo) {
                    $info.Resolution = $displayInfo.Matches[0].Groups[1].Value
                } else {
                    $info.Resolution = "Unknown"
                }
            } catch {
                $info.Resolution = "Unknown"
            }

            # Battery (if laptop)
            try {
                $batteryInfo = pmset -g batt 2>/dev/null
                if ($batteryInfo -and $batteryInfo -notmatch "No battery available") {
                    $batteryMatch = $batteryInfo | Select-String -Pattern '(\d+)%'
                    if ($batteryMatch) {
                        $info.Battery = "$($batteryMatch.Matches[0].Groups[1].Value)%"
                    }
                }
            } catch {
                # No battery info available (desktop)
            }

            # Admin Status (macOS)
            $info.Admin = "No" # macOS PowerShell typically runs as user

            # OneDrive Location (macOS)
            $oneDrivePath = "$HOME/Library/CloudStorage/OneDrive-Personal"
            if (Test-Path "$HOME/Library/CloudStorage/OneDrive-*") {
                $oneDrivePath = Get-ChildItem "$HOME/Library/CloudStorage/OneDrive-*" | Select-Object -First 1 -ExpandProperty FullName
            }
            $info.OneDrive = $oneDrivePath

            # Oh My Posh (macOS)
            try {
                $ohMyPoshCommand = (Get-Command -Name 'oh-my-posh' -ErrorAction Stop).Source
                if (-not $ohMyPoshCommand) {
                    $ohMyPoshCommand = '/opt/homebrew/bin/oh-my-posh'
                }
                if (Test-Path $ohMyPoshCommand) {
                    $ohMyPoshVersion = & $ohMyPoshCommand --version 2>$null
                    $info.OhMyPosh = $ohMyPoshVersion ? "v$ohMyPoshVersion" : "Installed"
                } else {
                    $info.OhMyPosh = "Not Found"
                }
            } catch {
                $info.OhMyPosh = "Not Found"
            }

            # PSReadLine History (macOS)
            $psReadLineHistory = "$oneDrivePath/PSReadLine/PSReadLineHistory.txt"
            $info.PSReadLineHistory = if (Test-Path $psReadLineHistory) { "OneDrive" } else { "Local" }


        } else {
            # Linux or other Unix-like systems
            $info.OS = "Linux/Unix (Generic)"
            $info.Kernel = uname -r
            $info.Uptime = Get-Uptime | ForEach-Object { $_ -replace '^.*up\s+([^,]+).*$', '$1' }
            $info.Host = hostname
            $info.User = whoami
            $info.Shell = $PSVersionTable.PSEdition -eq "Core" ? "PowerShell Core" : "PowerShell Desktop"
            $info.CPU = "Unknown"
            $info.Memory = "Unknown"
            $info.Disk = "Unknown"
            $info.Terminal = $env.TERM ? $env.TERM : "Unknown"
            $info.Resolution = "Unknown"

        }

    } catch {
        Write-Warning "Error gathering system information: $_"
    }

    # Save to cache
    if (-not $NoCache) {
        try {
            $cacheData = $info.Clone()
            $cacheData['CacheTime'] = (Get-Date).ToString('o')
            $cacheData | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Force
        } catch {
            # Cache save failed, continue without caching
        }
    }

    return $info
}

function Get-DefaultAsciiArt {
    return @(
        "-----------------------------------"
        "-------------.---------------------"
        "------------.........---.----------"
        "-----------................--------"
        "---------...................-------"
        "--------...-+###+++---......-------"
        "-------..+#########+++--....--++---"
        "-------.+##########+++----...-++++-"
        "-------+###########+++----...-+++++"
        "-------+############++----...-+++++"
        "---++-+############+++-----.-++++++"
        "-++++++##+-----++--......----++++++"
        "+++++++#+---..-+#+........----+++++"
        "+++++++###++++###+-------------++--"
        "+++++#+##########+--++++----.--+++-"
        "++++++++#######++---+++----..-+++++"
        "+++++##+#######--...------..-++++++"
        "+++++++-+####+-......----..-###++++"
        "+++++++--++-..-----........-#####++"
        "++++++++-.-..---.............-####+"
        "+++++++-......-................-###"
        "++++++-.........................+##"
        "+++++............................##"
        "++++.....-+-.....................-+"
        "+++......-###-....................."
    )
}

function Show-SystemNeofetch {
    [CmdletBinding()]
    param(
        [switch]$NoColor,
        [string]$CustomAscii,
        [string]$ProfileImage = "$env:USERPROFILE\Documents\PowerShell\profilepic.jpeg"
    )

    Clear-Host

    # ANSI color codes
    $script:Colors = @{
        Reset  = "`e[0m"
        Bold   = "`e[1m"
        # Foreground
        Orange = "`e[38;5;214m"
        Blue   = "`e[38;5;117m"
        Green  = "`e[38;5;114m"
        Red    = "`e[38;5;203m"
        Gray   = "`e[38;5;244m"
        White  = "`e[38;5;255m"
        Cyan   = "`e[38;5;81m"
        Yellow = "`e[38;5;227m"
        Purple = "`e[38;5;141m"
    }

    # Get system information
    $sysInfo = Get-SystemInfo

    # Determine whether to use Spectre image or ASCII art
    $useSpectreImage = $false
    if ($global:SpectreAvailable -and (Test-Path $ProfileImage) -and -not $NoColor) {
        $useSpectreImage = $true
    }

    # Get ASCII art (fallback)
    $asciiLines = if ($CustomAscii -and (Test-Path $CustomAscii)) {
        Get-Content $CustomAscii
    } else {
        Get-DefaultAsciiArt
    }

    # Build info lines
    $infoLines = @()

    # Adjust width based on whether we're using image or ASCII art
    # With image on left (35 cols), we can use up to ~90 cols for info (terminal width ~125)
    $infoWidth = if ($useSpectreImage) { 90 } else { 80 }

    # Header with user@host
    $separator = "-" * $infoWidth
    $userHost = "$($sysInfo.User)@$($sysInfo.Host)"
    $infoLines += "$(Get-ColoredText $userHost 'Cyan')"
    $infoLines += Get-ColoredText $separator 'Gray'

    # System Information
    $systemInfo = [ordered]@{
        "OS"       = $sysInfo.OS
        "Kernel"   = $sysInfo.Kernel
        "Uptime"   = $sysInfo.Uptime
        "Shell"    = $sysInfo.Shell
        "Terminal" = $sysInfo.Terminal
    }

    # Add additional info if available
    if ($sysInfo.Admin) {
        $systemInfo["Admin"] = $sysInfo.Admin
    }
    if ($sysInfo.OhMyPosh) {
        $systemInfo["OhMyPosh"] = $sysInfo.OhMyPosh
    }
    if ($sysInfo.OneDrive) {
        $systemInfo["OneDrive"] = $sysInfo.OneDrive
    }
    if ($sysInfo.PSReadLineHistory) {
        $systemInfo["PSReadLine"] = $sysInfo.PSReadLineHistory
    }

    foreach ($key in $systemInfo.Keys) {
        $value = $systemInfo[$key]
        if ($value) {
            $dots = Get-DotJustifiedLine -Key $key -Value $value -TargetWidth $infoWidth
            $coloredKey = Get-ColoredText $key 'Orange'
            $coloredDots = Get-ColoredText " $dots " 'Gray'
            $coloredValue = Get-ColoredText $value 'Blue'
            $infoLines += "$coloredKey`:$coloredDots$coloredValue"
        }
    }

    # Hardware Information
    $infoLines += ""
    $hardwareSepDashes = '-' * ($infoWidth - 11)  # 11 = "- Hardware " length
    $infoLines += Get-ColoredText "- Hardware $hardwareSepDashes" 'White'

    $hardwareInfo = [ordered]@{
        "CPU"    = $sysInfo.CPU
        "Memory" = $sysInfo.Memory
        "Disk"   = $sysInfo.Disk
    }

    if ($sysInfo.Model -and $sysInfo.Model -ne "Unknown") {
        $hardwareInfo["Model"] = $sysInfo.Model
    }

    if ($sysInfo.Resolution -and $sysInfo.Resolution -ne "Unknown") {
        $hardwareInfo["Resolution"] = $sysInfo.Resolution
    }

    if ($sysInfo.Battery) {
        $hardwareInfo["Battery"] = $sysInfo.Battery
    }

    foreach ($key in $hardwareInfo.Keys) {
        $value = $hardwareInfo[$key]
        if ($value) {
            $dots = Get-DotJustifiedLine -Key $key -Value $value -TargetWidth $infoWidth
            $coloredKey = Get-ColoredText $key 'Orange'
            $coloredDots = Get-ColoredText " $dots " 'Gray'
            $coloredValue = Get-ColoredText $value 'Blue'
            $infoLines += "$coloredKey`:$coloredDots$coloredValue"
        }
    }

    # Extra: Price Information
    $infoLines += ""
    $extraSepDashes = '-' * ($infoWidth - 8)  # 8 = "- Extra " length
    $infoLines += Get-ColoredText "- Extra $extraSepDashes" 'White'

    # Fetch prices with error handling
    try {
        $cryptoPrices = Get-CryptoPrice -Symbol BTC, ETH -ErrorAction SilentlyContinue
        $stockPrices = Get-StockPrice -Symbol $UserStockSymbol -ErrorAction SilentlyContinue

        foreach ($crypto in $cryptoPrices) {
            $changeSymbol = if ($crypto.Change24h -ge 0) { '▲' } else { '▼' }
            $changeColor = if ($crypto.Change24h -ge 0) { 'Green' } else { 'Red' }
            $changeSign = if ($crypto.Change24h -ge 0) { '+' } else { '' }
            $value = "`${0:N2} {1} {2}{3:N2}%" -f $crypto.Price, $changeSymbol, $changeSign, $crypto.Change24h
            $dots = Get-DotJustifiedLine -Key $crypto.Symbol -Value $value -TargetWidth $infoWidth
            $coloredKey = Get-ColoredText $crypto.Symbol 'Orange'
            $coloredDots = Get-ColoredText " $dots " 'Gray'
            $coloredValue = Get-ColoredText $value $changeColor
            $infoLines += "$coloredKey`:$coloredDots$coloredValue"
        }

        foreach ($stock in $stockPrices) {
            $changeSymbol = if ($stock.Change -ge 0) { '▲' } else { '▼' }
            $changeColor = if ($stock.Change -ge 0) { 'Green' } else { 'Red' }
            $changeSign = if ($stock.Change -ge 0) { '+' } else { '' }
            $value = "`${0:N2} {1} {2}{3:N2}%" -f $stock.Price, $changeSymbol, $changeSign, $stock.ChangePercent
            $dots = Get-DotJustifiedLine -Key $stock.Symbol -Value $value -TargetWidth $infoWidth
            $coloredKey = Get-ColoredText $stock.Symbol 'Orange'
            $coloredDots = Get-ColoredText " $dots " 'Gray'
            $coloredValue = Get-ColoredText $value $changeColor
            $infoLines += "$coloredKey`:$coloredDots$coloredValue"
        }
    } catch {
        # Silently skip if price fetching fails (e.g., no internet)
    }

    # Color palette line
    $infoLines += ""
    $palette = ""
    foreach ($i in 0..7) {
        $palette += "`e[48;5;${i}m "
    }
    $palette += "`e[0m"
    $infoLines += $palette

    # Display image or ASCII art with info
    Write-Host ""

    if ($useSpectreImage) {
        # Use Spectre.Console image rendering
        try {
            # Check if we're in an interactive console that supports cursor positioning
            if ([Console]::IsOutputRedirected -or [Console]::WindowHeight -eq 0) {
                throw "Console does not support cursor positioning"
            }

            # Display image on the left, then move cursor and display info
            # Save current cursor position
            $startLine = [Console]::CursorTop

            # Render the Spectre image (this writes directly to console)
            $spectreImageParams = @{
                ImagePath = $ProfileImage
                MaxWidth  = 40
            }
            if ($IsMacOS){
                $spectreImageParams.MaxWidth = 70
            }
             Get-SpectreImage @spectreImageParams

            # Calculate how many lines the image took
            $endLine = [Console]::CursorTop
            $imageHeight = $endLine - $startLine

            # Now position cursor to display info on the right side
            # The image is rendered at MaxWidth 25, but with padding/spacing
            # we need to start the info further right. Column 35 should work.
            $infoStartColumn = 52

            # Go back to start and write info lines
            $linesToWrite = [Math]::Max($imageHeight, $infoLines.Count)

            for ($i = 0; $i -lt $infoLines.Count; $i++) {
                # Position cursor at the right column for this line
                $targetLine = $startLine + $i

                # Make sure we don't go past the buffer
                if ($targetLine -lt [Console]::BufferHeight) {
                    [Console]::SetCursorPosition($infoStartColumn, $targetLine)
                    # Write without newline to prevent cursor moving
                    [Console]::Write($infoLines[$i])
                }
            }

            # Move cursor to the end
            [Console]::SetCursorPosition(0, $startLine + $linesToWrite)
            Write-Host ""  # Add final newline

        } catch {
            # Fall back to ASCII art if Spectre image fails
            $useSpectreImage = $false
        }
    }

    if (-not $useSpectreImage) {
        # Use traditional ASCII art
        $maxAsciiWidth = ($asciiLines | Measure-Object -Property Length -Maximum).Maximum
        $padding = 4 # Space between ASCII and info

        $totalLines = [Math]::Max($asciiLines.Count, $infoLines.Count)

        for ($i = 0; $i -lt $totalLines; $i++) {
            $asciiLine = if ($i -lt $asciiLines.Count) { $asciiLines[$i] } else { "" }
            $infoLine = if ($i -lt $infoLines.Count) { $infoLines[$i] } else { "" }

            # Colorize ASCII art (using cyan for the art)
            $coloredAscii = if ($NoColor) {
                $asciiLine.PadRight($maxAsciiWidth)
            } else {
                $asciiLine = $asciiLine -replace 'M', "$(Get-ColoredText 'M' 'Cyan')"
                $asciiLine = $asciiLine -replace '\.', "$(Get-ColoredText '.' 'Blue')"
                # Pad to align
                $rawLen = ($asciiLines[$i] ?? "").Length
                $padNeeded = $maxAsciiWidth - $rawLen
                $asciiLine + (" " * [Math]::Max(0, $padNeeded))
            }

            Write-Host "$coloredAscii$(' ' * $padding)$infoLine"
        }
    }

    Write-Host ""
}

#################################################################################################################################
############                                                                                                         ############
############                                            EXTRA SECTION                                                ############
############                                     Live Price Tracking Functions                                       ############
############                                                                                                         ############
#################################################################################################################################

function Get-CryptoPrice {
    <#
    .SYNOPSIS
        Gets current cryptocurrency prices from CoinGecko API.

    .DESCRIPTION
        Retrieves real-time price data for cryptocurrencies including current price,
        24-hour change, and market cap from the CoinGecko API.

    .PARAMETER Symbol
        Cryptocurrency symbol(s) to query (e.g., BTC, ETH, SOL).

    .EXAMPLE
        Get-CryptoPrice -Symbol BTC
        Gets Bitcoin price.

    .EXAMPLE
        Get-CryptoPrice -Symbol BTC, ETH, SOL
        Gets multiple cryptocurrency prices.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string[]]$Symbol = @('BTC', 'ETH')
    )

    begin {
        $results = @()
    }

    process {
        foreach ($coin in $Symbol) {
            try {
                # Map common symbols to CoinGecko IDs
                $coinMap = @{
                    'BTC'   = 'bitcoin'
                    'ETH'   = 'ethereum'
                    'SOL'   = 'solana'
                    'ADA'   = 'cardano'
                    'DOT'   = 'polkadot'
                    'MATIC' = 'matic-network'
                    'AVAX'  = 'avalanche-2'
                    'LINK'  = 'chainlink'
                    'UNI'   = 'uniswap'
                    'DOGE'  = 'dogecoin'
                }

                $coinId = if ($coinMap.ContainsKey($coin.ToUpper())) {
                    $coinMap[$coin.ToUpper()]
                } else {
                    $coin.ToLower()
                }

                $url = "https://api.coingecko.com/api/v3/simple/price?ids=$coinId&vs_currencies=usd&include_24hr_change=true&include_market_cap=true"
                $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5 -ErrorAction Stop

                if ($response.$coinId) {
                    $results += [PSCustomObject]@{
                        Symbol    = $coin.ToUpper()
                        Price     = $response.$coinId.usd
                        Change24h = $response.$coinId.usd_24h_change
                        MarketCap = $response.$coinId.usd_market_cap
                    }
                }
            } catch {
                Write-Warning "Failed to fetch price for $coin`: $($_.Exception.Message)"
            }
        }
    }

    end {
        return $results
    }
}

function Get-StockPrice {
    <#
    .SYNOPSIS
        Gets current stock price from Yahoo Finance.

    .DESCRIPTION
        Retrieves real-time stock price data including current price, change,
        and percent change from Yahoo Finance API.

    .PARAMETER Symbol
        Stock symbol(s) to query (e.g., AAPL, TSLA, MSFT).

    .EXAMPLE
        Get-StockPrice -Symbol AAPL
        Gets Apple stock price.

    .EXAMPLE
        Get-StockPrice -Symbol AAPL, TSLA, MSFT
        Gets multiple stock prices.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string[]]$Symbol = $UserStockSymbol
    )

    begin {
        $results = @()
    }

    process {
        foreach ($stock in $Symbol) {
            try {
                $url = "https://query1.finance.yahoo.com/v8/finance/chart/$($stock.ToUpper())?interval=1d&range=1d"
                $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5 -ErrorAction Stop

                if ($response.chart.result) {
                    $data = $response.chart.result[0]
                    $quote = $data.meta
                    $currentPrice = $quote.regularMarketPrice
                    $previousClose = $quote.previousClose

                    # Calculate change safely
                    $change = if ($previousClose -and $previousClose -ne 0) {
                        $currentPrice - $previousClose
                    } else {
                        0
                    }

                    # Calculate percent change safely
                    $changePercent = if ($previousClose -and $previousClose -ne 0) {
                        (($currentPrice - $previousClose) / $previousClose) * 100
                    } else {
                        0
                    }

                    $results += [PSCustomObject]@{
                        Symbol        = $stock.ToUpper()
                        Price         = $currentPrice
                        Change        = $change
                        ChangePercent = $changePercent
                        MarketState   = $quote.marketState
                    }
                }
            } catch {
                Write-Warning "Failed to fetch price for $stock`: $($_.Exception.Message)"
            }
        }
    }

    end {
        return $results
    }
}

function Show-PriceSnapshot {
    <#
    .SYNOPSIS
        Displays a formatted snapshot of cryptocurrency and stock prices.

    .DESCRIPTION
        Shows live prices for BTC, ETH, and a user-configured stock symbol
        in a clean, formatted table with color-coded changes.

    .PARAMETER StockSymbol
        Optional stock symbol to override the default from $UserStockSymbol.

    .EXAMPLE
        Show-PriceSnapshot
        Shows default price snapshot.

    .EXAMPLE
        Show-PriceSnapshot -StockSymbol TSLA
        Shows prices with Tesla stock instead of default.
    #>
    [CmdletBinding()]
    param (
        [string]$StockSymbol = $UserStockSymbol
    )

    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "              LIVE PRICE SNAPSHOT" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

    # Get crypto prices
    Write-Host "`n  Cryptocurrencies:" -ForegroundColor Yellow
    $cryptoPrices = Get-CryptoPrice -Symbol BTC, ETH

    foreach ($crypto in $cryptoPrices) {
        $priceFormatted = "{0:N2}" -f $crypto.Price
        $changeColor = if ($crypto.Change24h -ge 0) { 'Green' } else { 'Red' }
        $changeSymbol = if ($crypto.Change24h -ge 0) { '▲' } else { '▼' }
        $changeSign = if ($crypto.Change24h -ge 0) { '+' } else { '' }

        Write-Host "    $($crypto.Symbol.PadRight(6))" -NoNewline -ForegroundColor Cyan
        Write-Host "$" -NoNewline
        Write-Host $priceFormatted.PadLeft(12) -NoNewline -ForegroundColor White
        Write-Host "  $changeSymbol " -NoNewline -ForegroundColor $changeColor
        Write-Host ("{0}{1:N2}%" -f $changeSign, $crypto.Change24h).PadLeft(8) -ForegroundColor $changeColor
    }

    # Get stock price
    Write-Host "`n  Stocks:" -ForegroundColor Yellow
    $stockPrices = Get-StockPrice -Symbol $StockSymbol

    foreach ($stock in $stockPrices) {
        $priceFormatted = "{0:N2}" -f $stock.Price
        $changeColor = if ($stock.Change -ge 0) { 'Green' } else { 'Red' }
        $changeSymbol = if ($stock.Change -ge 0) { '▲' } else { '▼' }
        $changeSign = if ($stock.Change -ge 0) { '+' } else { '' }

        Write-Host "    $($stock.Symbol.PadRight(6))" -NoNewline -ForegroundColor Cyan
        Write-Host "$" -NoNewline
        Write-Host $priceFormatted.PadLeft(12) -NoNewline -ForegroundColor White
        Write-Host "  $changeSymbol " -NoNewline -ForegroundColor $changeColor
        Write-Host ("{0}{1:N2} ({2}{3:N2}%)" -f $changeSign, $stock.Change, $changeSign, $stock.ChangePercent).PadLeft(18) -ForegroundColor $changeColor
    }

    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "  Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor DarkGray
}
# Display neofetch on startup (respects light mode and skip flags)
$isVSCode = ($env:TERM_PROGRAM -eq 'vscode')
if (-not $script:LightMode -and -not $script:SkipNeofetch -and -not $isVSCode) {
    Clear-Host
    Show-SystemNeofetch
}


