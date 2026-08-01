### PowerShell Profile Refactor
### Version 1.04 - Simplified
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$debug = $false

# Light mode: Set $env:PROFILE_LIGHT=1 to skip network calls and module imports
# Useful for non-interactive shells, scripts, or constrained environments
$script:LightMode = $env:PROFILE_LIGHT -eq '1'

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

# Default symbol for Get-StockPrice.
$UserStockSymbol = "SPCX"

# Platform-specific initialization
if ($IsWindows) {
    # Admin Check
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Opt-out of telemetry if running as Administrator (not SYSTEM)
    if ($isAdmin) {
        try {
            [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
        } catch {
            Write-Verbose "Unable to set machine PowerShell telemetry opt-out: $($_.Exception.Message)"
        }
    }
} else {
    $env:USERPROFILE = $HOME
}

$powerShellDocumentsPath = [IO.Path]::Combine($env:USERPROFILE, 'Documents', 'PowerShell')
$timeFilePath = [IO.Path]::Combine($powerShellDocumentsPath, 'LastExecutionTime.txt')
if (-not (Test-Path $timeFilePath)) {
    New-Item -Path $powerShellDocumentsPath -ItemType Directory -Force | Out-Null
    (Get-Date -Format 'yyyy-MM-dd') | Out-File -FilePath $timeFilePath -Force
}


# Import optional profile modules without installing packages during startup.
if (-not $script:LightMode) {
    Import-Module Terminal-Icons -ErrorAction SilentlyContinue
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

        $registryPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        if ($Wow6432Node) {
            $registryPaths += 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        }

        foreach ($path in $registryPaths) {
            foreach ($key in Get-ChildItem $path -ErrorAction SilentlyContinue) {
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
                    $result
                }
            }
        }
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
}

# OS-agnostic functions

# Check for Profile Updates
function Update-Profile {
    [CmdletBinding(SupportsShouldProcess)]
    param()

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
            if ($PSCmdlet.ShouldProcess($PROFILE, "Replace profile with latest version")) {
                Copy-Item -Path $tempProfilePath -Destination $PROFILE -Force
                Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
            }
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

function Update-PowerShell {
    [CmdletBinding(SupportsShouldProcess)]
    param()

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
            if ($PSCmdlet.ShouldProcess("PowerShell $currentVersion", "Update to $latestVersion")) {
                if ($IsWindows) {
                    $updated = Invoke-WindowsPowerShellUpgrade
                } elseif ($IsMacOS) {
                    $updated = Invoke-MacPowerShellUpgrade
                } else {
                    Write-Warning "Automatic PowerShell updates are not supported on this operating system."
                }
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

# OS-agnostic Utility Functions

# Quick Access to Editing the Profile
function Edit-Profile {
    code $PROFILE
}
Set-Alias -Name ep -Value Edit-Profile

# Network Utilities
function Get-PubIP { (Invoke-WebRequest https://ifconfig.me/ip).Content.Trim() }

function Convert-MkvToMp4 {
    <#
    .SYNOPSIS
        Converts an MKV video to an MP4 using ffmpeg.

    .DESCRIPTION
        Creates an H.264/AAC MP4 that is broadly compatible with media players.
        By default, the MP4 is created beside the source MKV with the same base name.

    .PARAMETER Path
        The MKV file to convert. Accepts pipeline input and FileInfo objects.

    .PARAMETER OutputPath
        Optional destination MP4 path.

    .PARAMETER Force
        Overwrites an existing destination MP4.

    .EXAMPLE
        Convert-MkvToMp4 -Path .\movie.mkv

    .EXAMPLE
        Get-ChildItem *.mkv | Convert-MkvToMp4
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$Path,

        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [switch]$Force
    )

    process {
        if ([IO.Path]::GetExtension($Path) -ine '.mkv') {
            throw "Input file must have an .mkv extension: $Path"
        }

        $ffmpeg = Get-Command -Name ffmpeg -CommandType Application -ErrorAction SilentlyContinue
        if (-not $ffmpeg) {
            throw 'ffmpeg was not found on PATH. Install ffmpeg and try again.'
        }

        $inputFile = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (-not $OutputPath) {
            $OutputPath = [IO.Path]::ChangeExtension($inputFile.FullName, 'mp4')
        }

        if ([IO.Path]::GetExtension($OutputPath) -ine '.mp4') {
            throw "OutputPath must have an .mp4 extension: $OutputPath"
        }

        if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
            throw "Output file already exists: $OutputPath. Use -Force to overwrite it."
        }

        if ($PSCmdlet.ShouldProcess($OutputPath, "Convert '$($inputFile.Name)' to MP4")) {
            $ffmpegArguments = @(
                '-hide_banner'
                $(if ($Force) { '-y' } else { '-n' })
                '-i', $inputFile.FullName
                '-map', '0:v:0'
                '-map', '0:a?'
                '-c:v', 'libx264'
                '-c:a', 'aac'
                '-movflags', '+faststart'
                $OutputPath
            )

            & $ffmpeg.Source @ffmpegArguments
            if ($LASTEXITCODE -ne 0) {
                throw "ffmpeg failed to convert '$($inputFile.FullName)' (exit code $LASTEXITCODE)."
            }

            Get-Item -LiteralPath $OutputPath
        }
    }
}

function Import-Profile {
    . $PROFILE
}
Set-Alias -Name reload-profile -Value Import-Profile

Set-Alias -Name uptime -Value Get-Uptime

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

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

function Get-StockPrice {
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
                $ticker = $stock.ToUpperInvariant()
                $url = "https://query1.finance.yahoo.com/v8/finance/chart/$ticker`?interval=1d&range=1d"
                $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5 -ErrorAction Stop

                if ($response.chart.result) {
                    $quote = $response.chart.result[0].meta
                    $currentPrice = $quote.regularMarketPrice
                    $previousClose = $quote.previousClose
                    $change = if ($previousClose) { $currentPrice - $previousClose } else { $null }
                    $changePercent = if ($previousClose) { ($change / $previousClose) * 100 } else { $null }

                    $results += [PSCustomObject]@{
                        Symbol        = $ticker
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
        $results
    }
}

function Get-InstalledModuleFast {
    param(
        # Modules to filter for. Wildcards are supported.
        [string]$Name,

        # Paths to search. Defaults to PSModulePath entries.
        [string[]]$ModulePath = ($env:PSModulePath -split [System.IO.Path]::PathSeparator),

        # Return all installed versions, not just the latest version per module.
        [switch]$All
    )

    $allModules = foreach ($pathItem in $ModulePath) {
        if (-not (Test-Path $pathItem)) { continue }

        Get-ChildItem -Path $pathItem -Filter "*.psd1" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $manifestPath = $_
            $manifestName = (Split-Path -Path $_ -Leaf) -replace "\.psd1$"
            if ($Name -and $manifestName -notlike $Name) { return }

            $versionPath = Split-Path -Path $_
            [Version]$versionRoot = (Split-Path -Path $versionPath -Leaf) -as [Version]

            if (-not $versionRoot) {
                $versionPath = $_
            }

            $moduleRootName = Split-Path -Path (Split-Path -Path $versionPath) -Leaf
            if ($moduleRootName -ne $manifestName) {
                Write-Verbose "$manifestPath does not match a module folder, skipping."
                return
            }

            try {
                $fullInfo = Import-PowerShellDataFile -Path $_ -ErrorAction Stop
            } catch {
                Write-Warning "Failed to import module manifest for $manifestPath. Skipping."
                return
            }

            if (-not $fullInfo) { return }

            $manifestVersion = $fullInfo.ModuleVersion -as [Version]
            if (-not $manifestVersion) {
                Write-Warning "$manifestPath has an invalid or missing ModuleVersion. Skipping."
                return
            }

            if ($versionRoot -and $versionRoot -ne $manifestVersion) {
                Write-Warning "$_ has manifest version $manifestVersion but folder version $versionRoot. Skipping."
                return
            }

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

    $allModules |
    Sort-Object -Property Name, @{Expression = 'Version'; Descending = $true } |
    ForEach-Object {
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
        [switch]$AllowPrerelease,
        [string]$Name = '*',
        [int]$ThrottleLimit = 20
    )

    Write-Host "Retrieving installed modules ..." -ForegroundColor Green
    [array]$CurrentModules = Get-InstalledModuleFast -Name $Name -ErrorAction SilentlyContinue |
    Select-Object Name, Version |
    Sort-Object Name

    if (-not $CurrentModules) {
        Write-Host "No modules found." -ForegroundColor Gray
        return
    }

    Write-Host ("{0} modules found." -f $CurrentModules.Count) -ForegroundColor Gray
    Write-Host ("Checking for latest {0} versions ..." -f $(if ($AllowPrerelease) { "prerelease" } else { "production" })) -ForegroundColor Green

    $DiscoveryResults = $CurrentModules | ForEach-Object -Parallel {
        $Module = $_
        $AllowPrerelease = $using:AllowPrerelease

        Import-Module PowerShellGet -ErrorAction SilentlyContinue

        try {
            $findParams = @{
                Name            = $Module.Name
                AllowPrerelease = $AllowPrerelease
                ErrorAction     = 'Stop'
            }

            $latest = Find-Module @findParams | Select-Object -First 1

            [PSCustomObject]@{
                Name           = $Module.Name
                CurrentVersion = $Module.Version
                LatestVersion  = $latest.Version
                NeedsUpdate    = ($latest.Version -and $Module.Version -and ([version]$latest.Version -gt [version]$Module.Version))
            }
        } catch {
            Write-Warning ("{0}: {1}" -f $Module.Name, $_.Exception.Message)
        }
    } -ThrottleLimit $ThrottleLimit

    $DiscoveryResults | Where-Object { -not $_.NeedsUpdate } | ForEach-Object {
        Write-Host ("{0} is up to date (version {1})" -f $_.Name, $_.CurrentVersion) -ForegroundColor Cyan
    }

    $ModulesToUpdate = @($DiscoveryResults | Where-Object { $_.NeedsUpdate })

    if (-not $ModulesToUpdate) {
        Write-Host "`nNo modules need updating." -ForegroundColor Gray
        return
    }

    Write-Host ("`n{0} module(s) to update." -f $ModulesToUpdate.Count) -ForegroundColor Green

    foreach ($Module in $ModulesToUpdate) {
        if ($PSCmdlet.ShouldProcess($Module.Name, "Update from $($Module.CurrentVersion) to $($Module.LatestVersion)")) {
            try {
                Update-Module -Name $Module.Name -AllowPrerelease:$AllowPrerelease -Force -ErrorAction Stop
                Write-Host ("Updated {0} from version {1} to {2}" -f $Module.Name, $Module.CurrentVersion, $Module.LatestVersion) -ForegroundColor Yellow

                $allVersions = Get-InstalledModule -Name $Module.Name -AllVersions | Sort-Object PublishedDate -Descending
                foreach ($version in $allVersions | Select-Object -Skip 1) {
                    try {
                        Uninstall-Module -Name $Module.Name -RequiredVersion $version.Version -Force -ErrorAction Stop
                        Write-Host ("Uninstalled older version {0} of {1}" -f $version.Version, $Module.Name) -ForegroundColor Gray
                    } catch {
                        Write-Warning ("Failed to uninstall version {0} of {1}: {2}" -f $version.Version, $Module.Name, $_.Exception.Message)
                    }
                }
            } catch {
                Write-Warning ("{0}: {1}" -f $Module.Name, $_.Exception.Message)
            }
        }
    }

    Write-Host "`nSummary:" -ForegroundColor Green
    foreach ($Module in $ModulesToUpdate) {
        Write-Host ("- {0}: {1} -> {2}" -f $Module.Name, $Module.CurrentVersion, $Module.LatestVersion) -ForegroundColor Green
    }
}

# PSReadLine Configuration
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

    $keyHandlers = @{
        UpArrow           = 'HistorySearchBackward'
        DownArrow         = 'HistorySearchForward'
        Tab               = 'MenuComplete'
        'Ctrl+d'          = 'DeleteChar'
        'Ctrl+w'          = 'BackwardDeleteWord'
        'Alt+d'           = 'DeleteWord'
        'Ctrl+LeftArrow'  = 'BackwardWord'
        'Ctrl+RightArrow' = 'ForwardWord'
        'Ctrl+z'          = 'Undo'
        'Ctrl+y'          = 'Redo'
    }

    foreach ($key in $keyHandlers.GetEnumerator()) {
        Set-PSReadLineKeyHandler -Key $key.Name -Function $key.Value
    }

    Set-PSReadLineOption -AddToHistoryHandler {
        param($line)
        $sensitive = @('password', 'secret', 'token', 'apikey', 'connectionstring')
        $hasSensitive = $sensitive | Where-Object { $line -match $_ }
        return ($null -eq $hasSensitive)
    }

    if ((Get-Command Set-PSReadLineOption).Parameters.ContainsKey('PredictionSource')) {
        $psrl = (Get-Module PSReadLine).Version
        $source = if ($psrl -ge [Version]'2.1') { 'HistoryAndPlugin' } else { 'History' }
        $predictionOptions = @{ PredictionSource = $source }
        if ([Console]::WindowWidth -ge 50 -and [Console]::WindowHeight -ge 5) {
            $predictionOptions.PredictionViewStyle = 'ListView'
        }
        Set-PSReadLineOption @predictionOptions
    }

    Set-PSReadLineOption -MaximumHistoryCount 10000
}

$commonNativeCompletions = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $null = $cursorPosition

    $customCompletions = @{
        git  = @('status', 'add', 'commit', 'push', 'pull', 'clone', 'checkout')
        npm  = @('install', 'start', 'run', 'test', 'build')
        deno = @('run', 'compile', 'bundle', 'test', 'lint', 'fmt', 'cache', 'info', 'doc', 'upgrade')
    }

    $command = $commandAst.CommandElements[0].Value
    if ($customCompletions.ContainsKey($command)) {
        $customCompletions[$command] |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $commonNativeCompletions

if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $scriptblock = {
        param($wordToComplete, $commandAst, $cursorPosition)
        $null = $wordToComplete

        dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
    Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock
}

function Get-Theme {
    $ohMyPosh = Get-Command -Name "oh-my-posh" -ErrorAction SilentlyContinue
    if (-not $ohMyPosh) {
        Write-Warning "Oh My Posh not found. Skipping theme initialization."
        return
    }

    & $ohMyPosh.Source init pwsh --config $OhMyPoshTheme | Invoke-Expression
}

Get-Theme
