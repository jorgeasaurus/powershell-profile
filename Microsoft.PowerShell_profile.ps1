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
    Write-Host "#       JUST RUN \`Update-Profile\`     #" -ForegroundColor Red
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

# Set the Oh My Posh theme based on platform
if ($IsWindows) {
    $OhMyPoshConfig = $Config.OhMyPosh.Windows.Theme
    Write-Host "✅ PowerShell on Windows - PSVersion $($PSVersionTable.PSVersion)" -ForegroundColor Green
    #opt-out of telemetry before doing anything, only if PowerShell is run as admin
    if ([bool]([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem) {
        [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
    }
    # Admin Check and Prompt Customization
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

} else {
    $OhMyPoshConfig = $Config.OhMyPosh.Unix.Theme
    $env:USERPROFILE = $HOME
    Write-Host "✅ PowerShell on Mac - PSVersion $($PSVersionTable.PSVersion)" -ForegroundColor Green
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
$global:canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

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

# Check for Profile Updates
function Update-Profile {
    try {
        $env:temp = switch ($PSVersionTable.Platform) {
            'Win32NT' { "$env:temp" }
            'Unix' { "$HOME/.cache" }
            default { "$HOME/.cache" }
        }
        $url = "https://raw.githubusercontent.com/jorgeasaurus/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        $oldhash = Get-FileHash $PROFILE
        Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
        $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
        if ($newhash.Hash -ne $oldhash.Hash) {
            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Profile is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Unable to check for `$profile updates: $_"
    } finally {
        Remove-Item "$env:temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
    }
}

# Check if not in debug mode AND (updateInterval is -1 OR file doesn't exist OR time difference is greater than the update interval)
if (-not $debug -and `
    ($updateInterval -eq -1 -or `
            -not (Test-Path $timeFilePath) -or `
        ((Get-Date) - [datetime]::ParseExact((Get-Content -Path $timeFilePath), 'yyyy-MM-dd', $null)).TotalDays -gt $updateInterval)) {

    Update-Profile
    $currentTime = Get-Date -Format 'yyyy-MM-dd'
    $currentTime | Out-File -FilePath $timeFilePath -Force

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
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            if ($IsWindows) {
                Start-Process powershell.exe -ArgumentList "-NoProfile -Command winget upgrade Microsoft.PowerShell --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow
            } elseif ($IsMacOS) {
                if (Get-Command brew -ErrorAction SilentlyContinue) {
                    brew update
                    brew upgrade powershell --cask
                } else {
                    Write-Warning "Homebrew is not installed. Please install Homebrew first: /bin/bash -c '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'"
                    return
                }
            }
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}

# skip in debug mode
# Check if not in debug mode AND (updateInterval is -1 OR file doesn't exist OR time difference is greater than the update interval)
if (-not $debug -and `
    ($updateInterval -eq -1 -or `
            -not (Test-Path $timeFilePath) -or `
        ((Get-Date).Date - [datetime]::ParseExact((Get-Content -Path $timeFilePath), 'yyyy-MM-dd', $null).Date).TotalDays -gt $updateInterval)) {

    Update-PowerShell
    $currentTime = Get-Date -Format 'yyyy-MM-dd'
    $currentTime | Out-File -FilePath $timeFilePath -Force
} elseif (-not $debug) {
    Write-Warning "PowerShell update skipped. Last update check was within the last $updateInterval day(s)."
} else {
    Write-Warning "Skipping PowerShell update in debug mode"
}

function Clear-Cache {
    Write-Host "Clearing cache..." -ForegroundColor Cyan

    if ($IsWindows) {
        # Windows cache clearing
        Write-Host "Detected Windows system" -ForegroundColor Yellow

        # Clear Windows Prefetch
        Write-Host "Clearing Windows Prefetch..." -ForegroundColor Yellow
        Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue

        # Clear Windows Temp
        Write-Host "Clearing Windows Temp..." -ForegroundColor Yellow
        Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

        # Clear User Temp
        Write-Host "Clearing User Temp..." -ForegroundColor Yellow
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

        # Clear Internet Explorer Cache
        Write-Host "Clearing Internet Explorer Cache..." -ForegroundColor Yellow
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue

    } elseif ($IsMacOS) {
        # macOS cache clearing
        Write-Host "Detected macOS system" -ForegroundColor Yellow

        # Clear System Cache
        Write-Host "Clearing System Cache..." -ForegroundColor Yellow
        sudo rm -rf /Library/Caches/* 2>$null

        # Clear User Cache
        Write-Host "Clearing User Cache..." -ForegroundColor Yellow
        Remove-Item -rf ~/Library/Caches/* 2>$null

        # Clear DNS Cache
        Write-Host "Clearing DNS Cache..." -ForegroundColor Yellow
        sudo dscacheutil -flushcache
        sudo killall -HUP mDNSResponder

        # Clear Font Cache
        Write-Host "Clearing Font Cache..." -ForegroundColor Yellow
        sudo atsutil databases -remove
        atsutil server -shutdown
        atsutil server -ping

    } else {
        Write-Host "Unsupported operating system" -ForegroundColor Red
        return
    }

    Write-Host "Cache clearing completed." -ForegroundColor Green
}


# Utility Functions

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

# Open WinUtil full-release
function winutil {
    Invoke-RestMethod https://christitus.com/win | Invoke-Expression
}

# Open WinUtil pre-release
function winutildev {
    Invoke-RestMethod https://christitus.com/windev | Invoke-Expression
}

# System Utilities
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
        # check powershell version
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)
        } else {
            $lastBootStr = net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
            # check date format
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

            # check time format
            if ($lastBootStr -match '\bAM\b' -or $lastBootStr -match '\bPM\b') {
                $timeFormat = 'h:mm:ss tt'
            } else {
                $timeFormat = 'HH:mm:ss'
            }

            $bootTime = [System.DateTime]::ParseExact($lastBootStr, "$dateFormat $timeFormat", [System.Globalization.CultureInfo]::InvariantCulture)
        }

        # Format the start time
        ### $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) + " [$lastBootStr]"
        Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray

        # calculate uptime
        $uptime = (Get-Date) - $bootTime

        # Uptime in days, hours, minutes, and seconds
        $days = $uptime.Days
        $hours = $uptime.Hours
        $minutes = $uptime.Minutes
        $seconds = $uptime.Seconds

        # Uptime output
        Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $days, $hours, $minutes, $seconds) -ForegroundColor Blue


    } catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}

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

function df {
    Get-Volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

if ($IsWindows) {
    function which($name) {
        Get-Command $name | Select-Object -ExpandProperty Definition
    }
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

function trash($path) {
    $fullPath = (Resolve-Path -Path $path).Path

    if (Test-Path $fullPath) {
        $item = Get-Item $fullPath

        if ($item.PSIsContainer) {
            # Handle directory
            $parentPath = $item.Parent.FullName
        } else {
            # Handle file
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
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns {
    Clear-DnsClientCache
    Write-Host "DNS has been flushed"
}

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

$PSReadLineOptions = @{
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    Colors                        = @{
        Command   = '#87CEEB'  # SkyBlue (pastel)
        Parameter = '#98FB98'  # PaleGreen (pastel)
        Operator  = '#FFB6C1'  # LightPink (pastel)
        Variable  = '#DDA0DD'  # Plum (pastel)
        String    = '#FFDAB9'  # PeachPuff (pastel)
        Number    = '#B0E0E6'  # PowderBlue (pastel)
        Type      = '#F0E68C'  # Khaki (pastel)
        Comment   = '#D3D3D3'  # LightGray (pastel)
        Keyword   = '#8367c7'  # Violet (pastel)
        Error     = '#FF6347'  # Tomato (keeping it close to red for visibility)
    }
    PredictionSource              = 'History'
    PredictionViewStyle           = 'ListView'
    BellStyle                     = 'Visual'
}
Set-PSReadLineOption @PSReadLineOptions

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

# Improved prediction settings
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
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

# Get theme from profile.ps1 or use a default theme
function Get-Theme {
    if ($isMacOS) {
        $OhMyPoshCommand = "/opt/homebrew/bin/oh-my-posh"
    } elseif ($IsWindows) {
        $OhMyPoshCommand = (Get-Command -Name 'oh-my-posh.exe' -ea 0).Source
    }
    & $OhMyPoshCommand --init --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/powerlevel10k_rainbow.omp.json | Invoke-Expression
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

function Test-CommandExists {
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

function Test-WindowsFont {
    param ([string]$FontName)
    $fontsFolder = [System.Environment]::GetFolderPath('Fonts')
    foreach ($ext in @('.ttf', '.otf')) {
        if (Test-Path (Join-Path $fontsFolder "$FontName$ext")) { return $true }
    }
    # Fallback: check registry for font presence
    $fontReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
    return (Get-ItemProperty -Path $fontReg -ErrorAction SilentlyContinue).PSObject.Properties |
    Where-Object { $_.Name -like "*$FontName*" } | Select-Object -First 1
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
    # Check Homebrew installation for known fonts
    if ($FontName -like "*cascadia*") {
        $brewList = brew list --cask font-cascadia-code-nerd-font 2>$null
        return $brewList -ne $null
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

if (Test-Path "$PSScriptRoot\CTTcustom.ps1") {
    Invoke-Expression -Command "& `"$PSScriptRoot\CTTcustom.ps1`""
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
function yt {

    Begin {
        $query = 'https://www.youtube.com/results?search_query='
    }
    Process {
        Write-Host $args.Count, "Arguments detected"
        "Parsing out Arguments: $args"
        for ($i = 0; $i -le $args.Count; $i++) {
            $args | ForEach-Object { "Arg $i `t $_ `t Length `t" + $_.Length, " characters"; $i++ }
        }

        $args | ForEach-Object { $query = $query + "$_+" }
        $url = "$query"
    }
    End {
        $url.Substring(0, $url.Length - 1)
        "Final Search will be $url"
        "Invoking..."
        Start-Process "$url"
    }
}

# Splat parameters for Join-Path
$joinParams = @{
    Path              = $Onedrive
    ChildPath         = '10-19 Personal Projects/14 Scripts/14.01 Configs'
    AdditionalChildPath = 'PsAiConfig.ps1'
}
$envPath = Join-Path @joinParams
if (Test-Path $envPath) {
    . $envPath
    Write-Host "PSAI Env Config file loaded." -ForegroundColor Green
}

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
		| Foreach-Object {
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
			}
			catch {
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
				Name = $moduleRootName
				Version = $manifestVersion
				Path = $_.FullName
			}
		}
	}

	$modulesProcessed = @{}

	$allModules
	| Sort-Object -Property Name, @{Expression='Version';Descending=$true}
	| ForEach-Object {
		if ($All) {return $_}
		if (-not $modulesProcessed.($_.Name)) {
			$modulesProcessed.($_.Name) = $true
			return $_
		}
	}
}

function Update-Modules {
    param (
        [switch]$AllowPrerelease, # Include prerelease versions in updates
        [string]$Name = '*', # Module name filter, '*' for all modules
        [switch]$WhatIf, # Preview changes without applying them
        [int]$ThrottleLimit = 5   # Control parallel execution limit
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
    [CmdletBinding(DefaultParameterSetName='Dirs')]
    param(
        [Parameter(Position=0)]
        [string]$Path = '.',

        [Parameter(Position=1)]
        [int]$Depth = [int]::MaxValue,

        [Parameter(ParameterSetName='Files')]
        [switch]$ShowFiles
    )

    begin {
        try {
            $rootItem = Get-Item -LiteralPath $Path -ErrorAction Stop
        }
        catch {
            Write-Error "Path not found: $Path"
            return
        }

        function Invoke-Tree {
            param(
                [IO.FileSystemInfo]$Item,
                [string]$Prefix       = '',
                [int]   $CurrentDepth = 1
            )

            if ($CurrentDepth -gt $Depth) { return }

            $children = Get-ChildItem -LiteralPath $Item.FullName -Force -ErrorAction SilentlyContinue |
                        Where-Object { $ShowFiles.IsPresent -or $_.PSIsContainer }

            for ($i = 0; $i -lt $children.Count; $i++) {
                $child  = $children[$i]
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