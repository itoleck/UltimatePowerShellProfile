#The Ultimate PowerShell profile. Sets up environment for Windows PowerShell (5) and PowerShell 7+ profiles.
#Copies itself to the default PowerShell folders from Github URL in the $script:psprofile_link variable.
#Will measure it's own performance and skip parts like looking for new module versions if the profile is taking too long it load.
#Adds some shortcuts for Linux-Like terminal operation in Windows.
#Only runs admin functions when the console is run as admin.

#2023 Chad Schultz
#https://github.com/itoleck/UltimatePowerShellProfile

#--------------------------------------------------------------------------------------
#Start tracking the time that the script is running
$script:stopwatch = [system.diagnostics.stopwatch]::StartNew()

#Set the maximum time in seconds to determine if the profile should look to install modules that are not available in the profile
$script:max_profileload_seconds = 5

#PowerShell profile URL
#You can copy the code in this script and create a Github. Update the link below.
$script:psprofile_link = "https://raw.githubusercontent.com/itoleck/UltimatePowerShellProfile/main/Microsoft.PowerShell_profile.ps1"

#Which modules to load in this profile based on if the environment is admin(scope global) or user(scope local).
$script:global_modules = 'Az','AzureAD','MSOnline','Az.CostManagement','Microsoft.Graph'
$script:modules = 'Terminal-Icons','Carbon','CredentialManager','PnP.PowerShell','ImportExcel','WifiTools','ExchangeOnlineManagement','MicrosoftTeams','PSScriptAnalyzer','AzureSaveMoney'

#Check if documents folder is saved to OneDrive or local. Ugly but needed so the profile is copied to the right folder.
#Is OneDrive installed
$script:is_onedrive = (Test-Path -Path $env:ONEDRIVE)

#Now check the documents folder is backed up in Onedrive. Set is_onedrive back to false if the documents folder is not backed up. Maybe that OneDrive is not Logged in or the specific folder is not backed up.
If ($script:is_onedrive) {
    if ((Get-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\" -Name "Personal").Personal -like "*OneDrive*") {
    } else {
        $script:is_onedrive = $false
    }
}
#--------------------------------------------------------------------------------------

#Create this profile from GH if it does not exist
if (! (Test-Path -Path $PROFILE)) {
    try {
        Invoke-WebRequest -Uri $script:psprofile_link -OutFile "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1"
        Write-Output "Downloaded profile from $script:psprofile_link"
        if ($script:is_onedrive) {
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:ONEDRIVE\Documents\WindowsPowerShell\" -Force -Verbose
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:ONEDRIVE\Documents\PowerShell\" -Force -Verbose
        } else {
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:USERPROFILE\Documents\WindowsPowerShell\" -Force -Verbose
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:USERPROFILE\Documents\PowerShell\" -Force -Verbose
        }
    } catch {
        Write-Output "Error downloading profile from $script:psprofile_link"
    }
} else {
    Write-Output "Profile already exists. Run Install-Profile to reinstall PS profiles from $script:psprofile_link"
}

# Set up command window title
$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()

#--------------------------------------------------------------------------------------
#Set variables for user and admin status
$script:identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:principal = New-Object Security.Principal.WindowsPrincipal $script:identity
$script:isAdmin = $script:principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Run commands only in admin terminals
if ($script:isAdmin) {
    Function edithosts {notepad.exe "$env:SystemRoot\System32\drivers\etc\hosts"}
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Set PowerShell Gallery as a trusted source for module installation
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Setup PSReadLine
if ($host.Name -eq 'ConsoleHost') {
    if (-not(Get-Module -ListAvailable -Name PSReadLine)) {
        Install-Module PSReadLine -Scope CurrentUser -AllowPrerelease
        Import-Module PSReadLine -Scope Local -AllowPrerelease
        Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
        Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
    } else {
        Write-Output ("PSReadLine {0}" -f (Get-Module PSReadLine).Version.ToString())
    }
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Oh-my-posh setup
if (Get-Command oh-my-posh) {
    If ($PSVersionTable.PSVersion.Major -eq 5 ) {
        oh-my-posh.exe prompt init powershell --config $env:APPDATA\Local\Programs\oh-my-posh\themes\agnoster.omp | Invoke-Expression
        Enable-PoshTransientPrompt
        Write-Output "Enabled oh-my-posh for Windows PowerShell"
    } 
    IF ($PSVersionTable.PSVersion.Major -eq 7 ) {
        oh-my-posh.exe prompt init pwsh --config $env:APPDATA\Local\Programs\oh-my-posh\themes\agnoster.omp | Invoke-Expression
        Enable-PoshTransientPrompt
        Write-Output "Enabled oh-my-posh for Windows PowerShell 7"
    }
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
# Set Directory traversal functions
Function cd... { Set-Location ..\.. }
Function cd.... { Set-Location ..\..\.. }
Function cddrivers {Set-Location -Path $env:SystemRoot\System32\Drivers}
Function cdwpt {Set-Location -Path "${env:ProgramFiles(x86)}\Windows Kits\10\Windows Performance Toolkit\"}
Function cdrepos {Set-Location -Path $env:USERPROFILE\source\repos\}
Function cdtemp {Set-Location -Path c:\temp}
Function cdusertemp {Set-Location -Path $env:TEMP}
Function cduser {Set-Location -Path $env:USERPROFILE\}
Function cddesktop {Set-Location -Path $env:USERPROFILE\Desktop}
Function cddownloads {Set-Location -Path $env:USERPROFILE\Downloads}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Other usefull functions
Function uptime {
If ($PSVersionTable.PSVersion.Major -eq 5 ) {
		Get-WmiObject win32_operatingsystem |
        Select-Object @{EXPRESSION={ $_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
	} Else {
        net statistics workstation | Select-String "since" | foreach-object {$_.ToString().Replace('Statistics since ', '')}
    }
}
Function Get-PubIP {
    (Invoke-WebRequest http://ifconfig.me/ip ).Content
}
# Compute file hashes - useful for checking successful downloads 
Function md5 { Get-FileHash -Algorithm MD5 $args }
Function sha1 { Get-FileHash -Algorithm SHA1 $args }
Function sha256 { Get-FileHash -Algorithm SHA256 $args }
# Quick shortcut to start notepad
Function n { notepad $args }
# Drive shortcuts
Function HKLM: { Set-Location HKLM: }
Function HKCU: { Set-Location HKCU: }
Function Env: { Set-Location Env: }
# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
Function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    } else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}
Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}
Function find-file($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}
# Simple Function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
Function admin {
    If ($PSVersionTable.PSVersion.Major -eq 5 ) {
        if ($args.Count -gt 0) {   
            $argList = "& '" + $args + "'"
            Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
        } else {
            Start-Process "$psHome\powershell.exe" -Verb runAs
        }
    } else {
        if ($args.Count -gt 0) {   
            $argList = "& '" + $args + "'"
            Start-Process "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argList
        } else {
            Start-Process "$psHome\pwsh.exe" -Verb runAs
        }
    }
}

#--------------------------------------------------------------------------------------
#Commands to manage this profile
# Make it easy to edit this profile once it's installed
Function Install-Profile {
    if (Test-Path -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1") {
        try {
            Remove-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Force
            Write-Host "Removed previous profile download. $env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1"
        } catch {
            Write-Host "Error removing profile. $env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1"
        }
    }
    try {
        Invoke-WebRequest -Uri $script:psprofile_link -OutFile "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1"
        Write-Output "Downloaded profile from $script:psprofile_link"
        if ($script:is_onedrive) {
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:ONEDRIVE\Documents\WindowsPowerShell\" -Force -Verbose
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:ONEDRIVE\Documents\PowerShell\" -Force -Verbose
        } else {
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:USERPROFILE\Documents\WindowsPowerShell\" -Force -Verbose
            Copy-Item -Path "$env:USERPROFILE\Downloads\Microsoft.PowerShell_profile.ps1" -Destination "$env:USERPROFILE\Documents\PowerShell\" -Force -Verbose
        }
        reload-profile
    } catch {
        Write-Output "Error downloading profile from $script:psprofile_link"
    }
}
Function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    } else {
        notepad $profile.CurrentUserAllHosts
    }
}
Function Sync-Profile {
    & $profile
}
Set-Alias -Name Restore-Profile -Value Sync-Profile
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Linux-Like functions and commands
# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin
Function touch($file) {
    "" | Out-File $file -Encoding ASCII
}
Function df {
    get-volume
}

Function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}
Function head($f, $rows) {
    Get-Content -Head $rows -Path $f
}
Function tail($f, $rows) {
    Get-Content -Tail $rows -Path $f
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Install PowerShell modules if the script execution time is within limit
#Need to run the global module installs in an administrator PowerShell.

#Check to make sure profile load stays fast. If script has executed > the set limit don't worry about installing modules that are not available
if ($script:stopwatch.ElapsedMilliseconds -lt ($script:max_profileload_seconds * 1000)) {
    if ($script:isAdmin) {
        foreach($global_module in $script:global_modules) {
            if (-not(Get-Module -ListAvailable -Name $global_module)) {
                Write-Output "$global_module loading"
                Install-Module $global_module -Scope AllUsers
                Import-Module $global_module -Scope Global
            } else {
                Write-Output "$global_module already loaded"
            }
        }
    }
    
    foreach($module in $script:modules) {
        if (-not(Get-Module -ListAvailable -Name $module)) {
            Write-Output "$module loading"
            Install-Module $module -Scope CurrentUser
            Import-Module $module -Scope Local
        } else {
            Write-Output "$module already loaded"
        }
    }
} else {
    Write-Output "Skipping module installs as the profile took > $script:max_profileload_seconds seconds to load."
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Remind user which functions are available in the console
Write-Output "The following functions were set by profile:"
Get-ChildItem -Path Function:\ | Where-Object{$_.Source.ToString().Length -lt 1} | Select-Object Name | Format-Wide -AutoSize
#--------------------------------------------------------------------------------------