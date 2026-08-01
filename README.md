# PowerShell Profile

Cross-platform PowerShell profile for Windows and macOS. Startup stays focused on prompt setup, Terminal-Icons, PSReadLine preferences, update checks, native completions, and a small set of shell helpers.

## Install

Run in an elevated PowerShell session on Windows:

```powershell
irm "https://github.com/jorgeasaurus/powershell-profile/raw/main/setup.ps1" | iex
```

Manual install:

```powershell
git clone https://github.com/jorgeasaurus/powershell-profile.git
cd powershell-profile
.\setup.ps1
```

The installer sets up PowerShell 7 when needed, Oh My Posh, CaskaydiaCove Nerd Font, Terminal-Icons, the profile file, and Windows Terminal defaults on Windows.

## Configuration

Edit these values in `Microsoft.PowerShell_profile.ps1`:

```powershell
$updateInterval = 7
$OhMyPoshTheme = "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/quick-term.omp.json"
```

Set light mode for scripts or constrained shells:

```powershell
$env:PROFILE_LIGHT = "1"
```

Light mode skips startup update checks and module imports.

## Commands

Profile management:

```powershell
Update-Profile
Update-PowerShell
reload-profile
ep
```

Module maintenance:

```powershell
Update-Modules
Update-Modules -Name Pester
Update-Modules -AllowPrerelease -WhatIf
```

`Update-Modules` checks installed modules, reports current/latest versions, supports prerelease checks, and removes older side-by-side versions after successful updates.

Shell helpers:

```powershell
ll
uptime
Get-PubIP
cpy "text"
pst
```

Stock lookup:

```powershell
Get-StockPrice
Get-StockPrice -Symbol MSFT
```

`Get-StockPrice` defaults to `SPCX` and only calls the finance API when you run it.

Git shortcuts:

```powershell
gs
ga
gc "message"
gp
gcl https://github.com/user/repo
gcom "message"
lazyg "message"
```

Windows-only helpers:

```powershell
admin
sys
winutil
Search-RegistryUninstallKey -SearchFor "PowerShell"
```

Interactive shell behavior:

- PSReadLine colors, history de-duplication, key handlers, prediction source, and secret filtering stay enabled when PSReadLine is available.
- Native argument completions are registered for `git`, `npm`, `deno`, and `dotnet` when applicable.

## Development

Parse scripts without loading the profile:

```powershell
pwsh -NoProfile -Command '$files = "Microsoft.PowerShell_profile.ps1","setup.ps1"; foreach ($file in $files) { $tokens = $null; $errors = $null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $file), [ref]$tokens, [ref]$errors) | Out-Null; if ($errors) { $errors; exit 1 } }'
```

Run PSScriptAnalyzer when available:

```powershell
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path . -Recurse"
```

## Notes

- `Microsoft.PowerShell_profile.ps1` is the source profile copied to `$PROFILE`.
- Personal aliases and machine-specific functions belong in a separate local profile.
- Startup should stay free of optional app installers, automatic finance API calls, screenshots, and workstation bootstrap logic.
