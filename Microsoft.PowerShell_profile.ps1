### PowerShell Profile Refactor
### Version 1.03 - Refactored

$debug = $false

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
$OhMyPoshTheme = "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/powerlevel10k_rainbow.omp.json"

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

# Initial GitHub.com connectivity check with 1 second timeout
# Initial GitHub.com connectivity check (compatible with PowerShell 5.x and Core)
try {
    $ping = [System.Net.NetworkInformation.Ping]::new()
    $reply = $ping.Send('github.com', 1000)
    $global:canConnectToGitHub = $reply.Status -eq 'Success'
} catch {
    $global:canConnectToGitHub = $false
}

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
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

    function winutildev {
        <#
        .SYNOPSIS
            Launches the Chris Titus Tech Windows Utility (dev/pre-release)
        .DESCRIPTION
            Downloads and runs the WinUtil dev script in a new elevated PowerShell window
            for security isolation. The script is NOT executed in the current session.
        #>
        [CmdletBinding()]
        param()

        Write-Warning "This will download and execute a remote PRE-RELEASE script in an elevated window."
        Write-Warning "Source: https://christitus.com/windev"
        $confirm = Read-Host "Continue? (y/N)"
        if ($confirm -ne 'y') {
            Write-Host "Cancelled." -ForegroundColor Yellow
            return
        }

        # Run in isolated elevated process - not in current session
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-Command", "irm https://christitus.com/windev | iex; Read-Host 'Press Enter to close'"
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

    function df {
        Get-Volume
    }

    function which($name) {
        Get-Command $name | Select-Object -ExpandProperty Definition
    }

    function trash($path) {
        $fullPath = (Resolve-Path -Path $path).Path

        if (Test-Path $fullPath) {
            $item = Get-Item $fullPath

            if ($item.PSIsContainer) {
                $parentPath = $item.Parent.FullName
            } else {
                $parentPath = $item.DirectoryName
            }

            $shell = New-Object -ComObject 'Shell.Application'
            $shellItem = $shell.NameSpace($parentPath).ParseName($item.Name)

            if ($item) {
                $shellItem.InvokeVerb('delete')
                Write-Host "Item '$fullPath' has been moved to the Recycle Bin."
            } else {
                Write-Host "Error: Could not find the item '$fullPath' to trash."
            }
        } else {
            Write-Host "Error: Item '$fullPath' does not exist."
        }
    }

    function sysinfo {
        Get-ComputerInfo
    }

    function flushdns {
        Clear-DnsClientCache
        Write-Host "DNS has been flushed"
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

# Check for profile updates
if (-not $debug -and (Test-UpdateDue -TimeFilePath $timeFilePath -IntervalDays $updateInterval)) {
    Update-Profile
    Save-UpdateTimestamp -TimeFilePath $timeFilePath
} elseif (-not $debug) {
    Write-Warning "Profile update skipped. Last update check was within the last $updateInterval day(s)."
} else {
    Write-Warning "Skipping profile update check in debug mode"
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

# Check for PowerShell updates
if (-not $debug -and (Test-UpdateDue -TimeFilePath $timeFilePath -IntervalDays $updateInterval)) {
    Update-PowerShell
    Save-UpdateTimestamp -TimeFilePath $timeFilePath
} elseif (-not $debug) {
    Write-Warning "PowerShell update skipped. Last update check was within the last $updateInterval day(s)."
} else {
    Write-Warning "Skipping PowerShell update in debug mode"
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

function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -Recurse -Filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

# Network Utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

function reload-profile {
    & $profile
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }

    $FilePath = $args[0]

    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    } else {
        Write-Error "File path does not exist."
        return
    }

    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Set-Clipboard $url
        Write-Output $url
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | Select-String $regex
        return
    }
    $input | Select-String $regex
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function export($name, $value) {
    Set-Item -Force -Path "env:$name" -Value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name
}

function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

function tail {
    param($Path, $n = 10, [switch]$f = $false)
    Get-Content $Path -Tail $n -Wait:$f
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs {
    $docs = if (([Environment]::GetFolderPath("MyDocuments"))) { ([Environment]::GetFolderPath("MyDocuments")) } else { $HOME + "\Documents" }
    Set-Location -Path $docs
}

function dtop {
    $dtop = if ([Environment]::GetFolderPath("Desktop")) { [Environment]::GetFolderPath("Desktop") } else { $HOME + "\Documents" }
    Set-Location -Path $dtop
}

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

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

# ensure PSReadLine is available
try { Import-Module PSReadLine -ErrorAction Stop } catch {}

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

    # prediction options only on PSReadLine v2.1+ (PSReadLine versions with prediction support)
    $psrl = (Get-Module PSReadLine).Version
    if ($psrl -ge [Version]'2.1' -and (Get-Command Set-PSReadLineOption).Parameters.ContainsKey('PredictionSource')) {
        Set-PSReadLineOption -PredictionSource History -PredictionViewStyle ListView
    }
}

# Custom key handlers
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteChar
Set-PSReadLineKeyHandler -Chord 'Ctrl+w' -Function BackwardDeleteWord
Set-PSReadLineKeyHandler -Chord 'Alt+d' -Function DeleteWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow' -Function BackwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo

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
    if ($IsMacOS) {
        $OhMyPoshCommand = "/opt/homebrew/bin/oh-my-posh"
    } elseif ($IsWindows) {
        $OhMyPoshCommand = (Get-Command -Name 'oh-my-posh.exe' -ErrorAction SilentlyContinue).Source
    }

    if ($OhMyPoshCommand -and (Test-Path $OhMyPoshCommand -ErrorAction SilentlyContinue)) {
        & $OhMyPoshCommand --init --config $OhMyPoshTheme | Invoke-Expression
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
}

## Final Line to set prompt
Get-Theme

function Test-CommandExist {
    param ([string]$command)
    try { return $null -ne (Get-Command $command -ErrorAction Stop) } catch { return $false }
}

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

# Help Function
function Show-Help {
    $helpText = @"
$($PSStyle.Foreground.Cyan)PowerShell Profile Help$($PSStyle.Reset)
$($PSStyle.Foreground.Yellow)=======================$($PSStyle.Reset)

$($PSStyle.Foreground.Green)Update-Profile$($PSStyle.Reset) - Checks for profile updates from a remote repository and updates if necessary.

$($PSStyle.Foreground.Green)Update-PowerShell$($PSStyle.Reset) - Checks for the latest PowerShell release and updates if a new version is available.

$($PSStyle.Foreground.Green)Edit-Profile$($PSStyle.Reset) - Opens the current user's profile for editing using the configured editor.

$($PSStyle.Foreground.Green)touch$($PSStyle.Reset) <file> - Creates a new empty file.

$($PSStyle.Foreground.Green)ff$($PSStyle.Reset) <name> - Finds files recursively with the specified name.

$($PSStyle.Foreground.Green)Get-PubIP$($PSStyle.Reset) - Retrieves the public IP address of the machine.

$($PSStyle.Foreground.Green)winutil$($PSStyle.Reset) - Runs the latest WinUtil full-release script from Chris Titus Tech.

$($PSStyle.Foreground.Green)winutildev$($PSStyle.Reset) - Runs the latest WinUtil pre-release script from Chris Titus Tech.

$($PSStyle.Foreground.Green)uptime$($PSStyle.Reset) - Displays the system uptime.

$($PSStyle.Foreground.Green)reload-profile$($PSStyle.Reset) - Reloads the current user's PowerShell profile.

$($PSStyle.Foreground.Green)unzip$($PSStyle.Reset) <file> - Extracts a zip file to the current directory.

$($PSStyle.Foreground.Green)hb$($PSStyle.Reset) <file> - Uploads the specified file's content to a hastebin-like service and returns the URL.

$($PSStyle.Foreground.Green)grep$($PSStyle.Reset) <regex> [dir] - Searches for a regex pattern in files within the specified directory or from the pipeline input.

$($PSStyle.Foreground.Green)df$($PSStyle.Reset) - Displays information about volumes.

$($PSStyle.Foreground.Green)sed$($PSStyle.Reset) <file> <find> <replace> - Replaces text in a file.

$($PSStyle.Foreground.Green)which$($PSStyle.Reset) <name> - Shows the path of the command.

$($PSStyle.Foreground.Green)export$($PSStyle.Reset) <name> <value> - Sets an environment variable.

$($PSStyle.Foreground.Green)pkill$($PSStyle.Reset) <name> - Kills processes by name.

$($PSStyle.Foreground.Green)pgrep$($PSStyle.Reset) <name> - Lists processes by name.

$($PSStyle.Foreground.Green)head$($PSStyle.Reset) <path> [n] - Displays the first n lines of a file (default 10).

$($PSStyle.Foreground.Green)tail$($PSStyle.Reset) <path> [n] - Displays the last n lines of a file (default 10).

$($PSStyle.Foreground.Green)nf$($PSStyle.Reset) <name> - Creates a new file with the specified name.

$($PSStyle.Foreground.Green)mkcd$($PSStyle.Reset) <dir> - Creates and changes to a new directory.

$($PSStyle.Foreground.Green)docs$($PSStyle.Reset) - Changes the current directory to the user's Documents folder.

$($PSStyle.Foreground.Green)dtop$($PSStyle.Reset) - Changes the current directory to the user's Desktop folder.

$($PSStyle.Foreground.Green)ep$($PSStyle.Reset) - Opens the profile for editing.

$($PSStyle.Foreground.Green)k9$($PSStyle.Reset) <name> - Kills a process by name.

$($PSStyle.Foreground.Green)la$($PSStyle.Reset) - Lists all files in the current directory with detailed formatting.

$($PSStyle.Foreground.Green)ll$($PSStyle.Reset) - Lists all files, including hidden, in the current directory with detailed formatting.

$($PSStyle.Foreground.Green)gs$($PSStyle.Reset) - Shortcut for 'git status'.

$($PSStyle.Foreground.Green)ga$($PSStyle.Reset) - Shortcut for 'git add .'.

$($PSStyle.Foreground.Green)gc$($PSStyle.Reset) <message> - Shortcut for 'git commit -m'.

$($PSStyle.Foreground.Green)gp$($PSStyle.Reset) - Shortcut for 'git push'.

$($PSStyle.Foreground.Green)g$($PSStyle.Reset) - Changes to the GitHub directory.

$($PSStyle.Foreground.Green)gcom$($PSStyle.Reset) <message> - Adds all changes and commits with the specified message.

$($PSStyle.Foreground.Green)lazyg$($PSStyle.Reset) <message> - Adds all changes, commits with the specified message, and pushes to the remote repository.

$($PSStyle.Foreground.Green)sysinfo$($PSStyle.Reset) - Displays detailed system information.

$($PSStyle.Foreground.Green)flushdns$($PSStyle.Reset) - Clears the DNS cache.

$($PSStyle.Foreground.Green)cpy$($PSStyle.Reset) <text> - Copies the specified text to the clipboard.

$($PSStyle.Foreground.Green)pst$($PSStyle.Reset) - Retrieves text from the clipboard.

Use '$($PSStyle.Foreground.Magenta)Show-Help$($PSStyle.Reset)' to display this help message.
"@
    Write-Host $helpText
}

# Load custom user profile if it exists (dot-sourced for security - no Invoke-Expression)
$customProfilePath = Join-Path $PSScriptRoot "CTTcustom.ps1"
if (Test-Path $customProfilePath) {
    try {
        . $customProfilePath
    } catch {
        Write-Warning "Failed to load custom profile '$customProfilePath': $($_.Exception.Message)"
    }
}

Write-Host "$($PSStyle.Foreground.Yellow)Use 'Show-Help' to display help$($PSStyle.Reset)"

function Invoke-Spongebob {
    [cmdletbinding()]
    param(
        [Parameter(HelpMessage = "provide string" , Mandatory = $true)]
        [string]$Message
    )
    $charArray = $Message.ToCharArray()

    foreach ($char in $charArray) {
        $Var = $(Get-Random) % 2
        if ($var -eq 0) {
            $string = $char.ToString()
            $Upper = $string.ToUpper()
            $output = $output + $Upper
        } else {
            $lower = $char.ToString()
            $output = $output + $lower
        }
    }
    $output
    $output = $null
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
function Update-Module {
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

    # Process updates in parallel for better performance
    $CurrentModules | ForEach-Object -Parallel {
        $Module = $_
        $AllowPrerelease = $using:AllowPrerelease
        $WhatIf = $using:WhatIf

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
    if (-not $WhatIf) {
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
            Write-Host "  — $author" -ForegroundColor Green
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
        Write-Host "  — Marcus Aurelius" -ForegroundColor Green
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
        a Microsoft Graph connection. Credentials are cleaned up after use.
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

    try {
        # Connect to Azure if needed
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $azContext) {
            Write-Host "Connecting to Azure..." -ForegroundColor Cyan
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }

        # Retrieve credentials
        Write-Host "Retrieving credentials from Key Vault..." -ForegroundColor Cyan
        $creds = Get-CredentialsFromKeyVault -KeyVaultName $KeyVaultName

        # Build PSCredential for Graph connection
        $credential = [PSCredential]::new($creds.ClientId, $creds.ClientSecretSecure)

        # Connect to Graph using client credentials (no env vars needed)
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $creds.TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop

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
        if ($credential) {
            $credential = $null
        }
        [System.GC]::Collect()
    }
}
# Backward compatibility alias
function graph {
    Write-Warning "The 'graph' function is deprecated. Use 'Connect-GraphSession' instead."
    Connect-GraphSession
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
                    $rmResult = & Remove-Item -rf $packagePath 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Successfully removed directory with rm command" -ForegroundColor Green
                    } else {
                        Write-Warning "rm command failed: $rmResult"
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
            $uptimeOutput = Get-Uptime
            $uptimeMatch = $uptimeOutput | Select-String -Pattern 'up\s+([^,]+)'
            if ($uptimeMatch) {
                $info.Uptime = $uptimeMatch.Matches[0].Groups[1].Value.Trim()
            } else {
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
        [string]$CustomAscii
    )

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

    # Get ASCII art
    $asciiLines = if ($CustomAscii -and (Test-Path $CustomAscii)) {
        Get-Content $CustomAscii
    } else {
        Get-DefaultAsciiArt
    }

    # Build info lines
    $infoLines = @()

    # Header with user@host
    $separator = "-" * 80
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
            $dots = Get-DotJustifiedLine -Key $key -Value $value
            $coloredKey = Get-ColoredText $key 'Orange'
            $coloredDots = Get-ColoredText " $dots " 'Gray'
            $coloredValue = Get-ColoredText $value 'Blue'
            $infoLines += "$coloredKey`:$coloredDots$coloredValue"
        }
    }

    # Hardware Information
    $infoLines += ""
    $infoLines += Get-ColoredText "- Hardware $('-' * 69)" 'White'

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
            $dots = Get-DotJustifiedLine -Key $key -Value $value
            $coloredKey = Get-ColoredText $key 'Orange'
            $coloredDots = Get-ColoredText " $dots " 'Gray'
            $coloredValue = Get-ColoredText $value 'Blue'
            $infoLines += "$coloredKey`:$coloredDots$coloredValue"
        }
    }


    # Color palette line
    $infoLines += ""
    $palette = ""
    foreach ($i in 0..7) {
        $palette += "`e[48;5;${i}m "
    }
    $palette += "`e[0m"
    $infoLines += $palette

    # Combine ASCII art with info
    $maxAsciiWidth = ($asciiLines | Measure-Object -Property Length -Maximum).Maximum
    $padding = 4 # Space between ASCII and info

    $totalLines = [Math]::Max($asciiLines.Count, $infoLines.Count)

    Write-Host ""
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
    Write-Host ""
}

Show-SystemNeofetch