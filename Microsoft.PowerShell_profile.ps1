#The Ultimate PowerShell Profile. Sets up environment for Windows PowerShell (5) and PowerShell 7+ profiles.
#Copies itself to the default PowerShell folders from Github URL in the $script:UltimatePSProfile.psprofile_link variable.
#Will measure it's own performance and skip parts like looking for new module versions if the profile is taking too long to load.
#Adds some shortcuts for Linux-Like terminal operation in Windows.
#Only runs admin functions when the session is run as admin.

#Inspired by https://github.com/ChrisTitusTech/powershell-profile which was inspired from https://gist.github.com/timsneath/19867b12eee7fd5af2ba
#https://github.com/itoleck/UltimatePowerShellProfile

#--------------------------------------------------------------------------------------
#Setup the initial object to hold all of the script settings. Using object so as not to clutter PS session with variables.
#Most of these can be edited for your local system.

#stopwatch                  Start tracking the time that the script is running

#max_profileload_seconds    Set the maximum time in seconds to determine ifthe profile should look to install modules that are not available in the profile

#psprofile_link             PowerShell profile URL. You can copy the code in this script and create a Github. Update this property.

#psprofile_repo_path        Local repo folder for this Ultimate PowerShell Profile. Used for the Copy-Profile command

#global_modules             Which modules to load in this profile ifthe environment is admin(scope global)
#                           If forking this script and adding your own modules, please set back these defaults when subimitting PR.

#local_modules              Which modules to load in this profile ifthe environment is non-admin user (scope local)
#                           If forking this script and adding your own modules, please set back these defaults when subimitting PR.

$script:UltimatePSProfile = [PSCustomObject]@{
    psprofile_link = "https://raw.githubusercontent.com/itoleck/UltimatePowerShellProfile/main/Microsoft.PowerShell_profile.ps1"
    psprofile_repo_path = ""
    stopwatch = [system.diagnostics.stopwatch]::StartNew()
    max_profileload_seconds = 5
    mydocuments_path = ""
    oh_my_posh_theme = ""
    gh_repo_base_folder = ""
    system_temp = ""
    global_modules = 'Az','Az.Accounts','AzureAD','MSOnline','Az.CostManagement','Microsoft.Graph'
    local_modules = 'Terminal-Icons','Carbon','CredentialManager','PnP.PowerShell','ImportExcel','WifiTools','ExchangeOnlineManagement','MicrosoftTeams','PSScriptAnalyzer','AzureSaveMoney'
}
#--------------------------------------------------------------------------------------

#Set some paths if this session is running in Windows
if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    $script:UltimatePSProfile.psprofile_repo_path = "$env:USERPROFILE\source\repos\itoleck\UltimatePowerShellProfile\"
    $script:UltimatePSProfile.gh_repo_base_folder = "$env:USERPROFILE\source\repos\"
    $script:UltimatePSProfile.system_temp = $env:TEMP + "\"
    $script:UltimatePSProfile.mydocuments_path = [System.Environment]::GetFolderPath('Personal') + "\"
    $script:UltimatePSProfile.oh_my_posh_theme = "$env:APPDATA\Local\Programs\oh-my-posh\themes\agnoster.omp"
}

#Set some paths if this session is running in Linux
if ($IsLinux) {
    $script:UltimatePSProfile.psprofile_repo_path = "$($script:UltimatePSProfile.mydocuments_path)/source/repos/itoleck/UltimatePowerShellProfile/"
    $script:UltimatePSProfile.gh_repo_base_folder = "$($script:UltimatePSProfile.mydocuments_path)/source/repos/"
    $script:UltimatePSProfile.system_temp = "/tmp/"
    $script:UltimatePSProfile.mydocuments_path = [System.Environment]::GetFolderPath('Personal') + "/"
}

#--------------------------------------------------------------------------------------
#Create this profile from GH if it does not exist
if (! (Test-Path -Path $PROFILE)) {
    try {
        #Use My Documents for the download because Downloads path is not available unless you use pinvoke 
        Invoke-WebRequest -Uri $script:UltimatePSProfile.psprofile_link -OutFile "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1"
        Write-Output "Downloaded profile from $($script:UltimatePSProfile.psprofile_link)"
    } catch {
        Write-Output "Error downloading profile from $($script:UltimatePSProfile.psprofile_link)"
    }
    try {
        if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
            Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell" -Force -Verbose
            Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)PowerShell" -Force -Verbose
        } else {
            if ($IsLinux) {
                try {
                    Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$profile" -Force -Verbose
                }
                catch {
                    New-Item -ItemType Directory -Path "$($script:UltimatePSProfile.mydocuments_path).config/powershell/"
                    Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path).config/powershell/" -Force -Verbose
                }
            }
        }
    }
    catch {
        Write-Output "Error copying profile from $($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1 to $($script:UltimatePSProfile.mydocuments_path)\WindowsPowerShell\ or $($script:UltimatePSProfile.mydocuments_path)\PowerShell\"
    }
} else {
    Write-Output "Profile already exists. Run Install-Profile to update Ultimate PowerShell Profile from $($script:UltimatePSProfile.psprofile_link)"
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Setup command window title. Gets overwritten in Windows Terminal.
$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Set some PowerShell settings that can help to reduce module import errors
#https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/5.1/Microsoft.PowerShell.Core/About/about_Preference_Variables.md
if ($PSVersionTable.PSVersion.Major -eq 5 ) {
    $MaximumFunctionCount = 8192
    $MaximumVariableCount = 8192
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Set variables for user and admin status
if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    $script:identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:principal = New-Object Security.Principal.WindowsPrincipal $script:identity
    $script:isAdmin = $script:principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} else {
    if ($IsLinux -and (id -u) -eq 0) {
        $script:isAdmin = $true
    }
}

#Run commands only in admin terminals
if ($script:isAdmin -eq $true) {
    if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
        Function edithosts {notepad.exe "$env:SystemRoot\System32\drivers\etc\hosts"}
    }
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Set PowerShell Gallery as a trusted source for module installation
if (Get-Module -ListAvailable -Name PowerShellGet) {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Write-Output "Set PSGallery source (https://www.powershellgallery.com/) as trusted"
} else {
    Write-Output "PowerShellGet PowerShell module not installed. Run Install-Module -Name PowerShellGet -Scope AllUsers"
}
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
if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    if (Get-Command oh-my-posh) {
        if ($PSVersionTable.PSVersion.Major -eq 5 ) {
            oh-my-posh.exe prompt init powershell --config $script:UltimatePSProfile.oh_my_posh_theme | Invoke-Expression
            Enable-PoshTransientPrompt
            Write-Output "Enabled oh-my-posh for Windows PowerShell"
        } 
        if ($IsWindows -and $PSVersionTable.PSVersion.Major -eq 7 ) {
            oh-my-posh.exe prompt init pwsh --config $script:UltimatePSProfile.oh_my_posh_theme | Invoke-Expression
            Enable-PoshTransientPrompt
            Write-Output "Enabled oh-my-posh for Windows PowerShell 7"
        }
    } else {
        Write-Output "Oh-my-posh not installed. No fancy prompt for you."
    }
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
# Set Windows Directory traversal functions
if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    Function cd... { Set-Location ..\.. }
    Function cd.... { Set-Location ..\..\.. }
    Function cddrivers {Set-Location -Path $env:SystemRoot\System32\Drivers}
    if (Test-Path -Path "${env:ProgramFiles(x86)}\Windows Kits\10\Windows Performance Toolkit\") {
        Function cdwpt {Set-Location -Path "${env:ProgramFiles(x86)}\Windows Kits\10\Windows Performance Toolkit\"}
    }
    Function cdrepos {Set-Location -Path $script:UltimatePSProfile.gh_repo_base_folder}
    Function cdtemp {Set-Location -Path $script:UltimatePSProfile.system_temp}
    Function cduser {Set-Location -Path $env:USERPROFILE}
    Function cddesktop {Set-Location -Path ([System.Environment]::GetFolderPath('Desktop'))}
    Function cddownloads {Set-Location -Path $env:USERPROFILE\Downloads} #Lazy, don't really want to use pinvoke just for this
}
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Other usefull functions
Function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5 ) {
		Get-WmiObject win32_operatingsystem |
        Select-Object @{EXPRESSION={ $_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
	}
    if ($IsWindows -and $PSVersionTable.PSVersion.Major -eq 7 ) {
        net statistics workstation | Select-String "since" | foreach-object {$_.ToString().Replace('Statistics since ', '')}
    }
}
Function Get-PubIP {
    (Invoke-WebRequest http://ifconfig.me/ip ).Content
}

if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    Function n { notepad.exe $args }
    Function n++ {
        $npp=(Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe")
        Start-Process -FilePath ($npp.'(default)') -ArgumentList $args
    }
    Function tm { taskmgr.exe }
}
#Compute file hashes - useful for checking successful downloads 
Function md5 { Get-FileHash -Algorithm MD5 $args }
Function sha1 { Get-FileHash -Algorithm SHA1 $args }
Function sha256 { Get-FileHash -Algorithm SHA256 $args }

if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    #Drive shortcuts
    Function HKLM: { Set-Location HKLM: }
    Function HKCU: { Set-Location HKCU: }
    Function Env: { Set-Location Env: }
}

#Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
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
    try { if(Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}
Function find-file($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        $place_path = $_.directory
        Write-Output "${place_path}\${_}"
    }
}

if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    #Simple Function to start a new elevated process. If arguments are supplied, then 
    #a single command is started with admin rights; if not, then a new admin instance of PowerShell is started.
    Function admin {
        if ($PSVersionTable.PSVersion.Major -eq 5 ) {
            if ($args.Count -gt 0) {   
                $argList = "& '" + $args + "'"
                Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
            } else {
                Start-Process "$psHome\powershell.exe" -Verb runAs
            }
        }
        if ($IsWindows -and $PSVersionTable.PSVersion.Major -eq 7 ) {
            if ($args.Count -gt 0) {   
                $argList = "& '" + $args + "'"
                Start-Process "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argList
            } else {
                Start-Process "$psHome\pwsh.exe" -Verb runAs
            }
        }
    }
}
#--------------------------------------------------------------------------------------
#Commands to manage this profile
#Make it easy to edit this profile once it's installed
Function Install-Profile {
    try {
        #Use My Documents for the download because Downloads path is not available unless you use p/invoke
        Invoke-WebRequest -Uri $script:UltimatePSProfile.psprofile_link -OutFile "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1"
        Write-Output "Downloaded profile from $($script:UltimatePSProfile.psprofile_link)"
    } catch {
        Write-Output "Error downloading profile from $($script:UltimatePSProfile.psprofile_link)"
    }
    try {
        if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
            Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell" -Force -Verbose
            Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)PowerShell" -Force -Verbose
        } else {
            if ($IsLinux) {
                Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$profile.CurrentUserCurrentHost" -Force -Verbose
            }
        }
    }
    catch {
        Write-Output "Error copying profile from $($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1 to $($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell or $($script:UltimatePSProfile.mydocuments_path)PowerShell"
    }
}

#Open this profile in PowerShell ISE or Notepad if ISE is not running
Function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserCurrentHost)
    } else {
        notepad.exe $profile.CurrentUserCurrentHost
    }
}

#Copy this file from a local GitHub repo folder to the Windows PowerShell and PowerShell folders
Function Copy-ProfilesFromLocalRepo {
    try {
        Write-Output "Copying profile to PowerShell folders."
        if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
            Copy-Item -Path "$($script:UltimatePSProfile.psprofile_repo_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell" -Force -Verbose
            Copy-Item -Path "$($script:UltimatePSProfile.psprofile_repo_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)PowerShell" -Force -Verbose
        } else {
            if ($IsLinux) {
                Copy-Item -Path "$($script:UltimatePSProfile.psprofile_repo_path)Microsoft.PowerShell_profile.ps1" -Destination "$profile.CurrentUserCurrentHost" -Force -Verbose
            }
        }
    }
    catch {
        Write-Output "Error copying profile to PowerShell profile folders."
    }
}

#Just reload the profile in the current window
Function Sync-Profile {
    & $profile
}
Set-Alias -Name Restore-Profile -Value Sync-Profile
#--------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------
#Linux-Like functions and commands
#Set UNIX-like aliases for the admin command, so sudo <command> will run the command
#with elevated rights.
if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
    Set-Alias -Name su -Value admin
    Set-Alias -Name sudo -Value admin
    Function touchuni($file) {
        "" | Out-File $file -Encoding unicode
    }
    Function touchutf8($file) {
        "" | Out-File $file -Encoding ascii
    }
    Function df {
        Get-Volume
    }
    Function disks {
        Get-PhysicalDisk
    }
    Function pkill($name) {
        Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    Function head($file, $rows) {
        Get-Content -Head $rows -Path $file
    }
    Function tail($file, $rows) {
        Get-Content -Tail $rows -Path $file
    }
    Function grepstr {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory=$true,ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string] $InputObject,
        [Parameter(Mandatory=$true)]
        [string] $SearchString
        )
        $InputObject | Select-String -Pattern $SearchString -SimpleMatch
    }
    Function grepfile {
        param(
        [Parameter(Mandatory=$true)]
        [string] $Path,
        [Parameter(Mandatory=$true)]
        [string] $SearchString
        )
        Get-Content -Path $Path | Select-String -Pattern $SearchString -SimpleMatch
    }
    Function ipconfig {
        ipconfig.exe /all
    }
    Function cleardns {
        ipconfig.exe /flushdns
    }
}
#--------------------------------------------------------------------------------------

function InstallandLoadModules() {
#--------------------------------------------------------------------------------------
#Install PowerShell modules if the script execution time is within limit
#Need to run the global module installs in an administrator PowerShell.
#Check to make sure profile load stays fast. If script has executed > the set limit don't worry about installing modules that are not available

    #Just bypassing Linux root user/Global modules for now. Load them all in user/local
    if ($IsLinux) {
        foreach($global_module in $script:UltimatePSProfile.global_modules) {
            if (-not(Get-Module -ListAvailable -Name $global_module)) {
                Write-Output "$global_module loading"
                Install-Module $global_module -Scope CurrentUser
                Import-Module $global_module -Scope Local
            } else {
                Write-Output "$global_module already loaded"
            }
        }

        foreach ($module in $script:UltimatePSProfile.local_modules) {
            if (-not(Get-Module -ListAvailable -Name $module)) {
                Write-Output "$module loading"
                Install-Module $module -Scope CurrentUser
                Import-Module $module -Scope Local
            } else {
                Write-Output "$module already loaded"
            }
        }
    } else {
        if ($script:isAdmin -eq $true) {
            foreach($global_module in $script:UltimatePSProfile.global_modules) {
                if (-not(Get-Module -ListAvailable -Name $global_module)) {
                    Write-Output "$global_module loading"
                    Install-Module $global_module -Scope AllUsers
                    Import-Module $global_module -Scope Global
                } else {
                    Write-Output "$global_module already loaded"
                }
            }
        }

        foreach ($module in $script:UltimatePSProfile.local_modules) {
            if (-not(Get-Module -ListAvailable -Name $module)) {
                Write-Output "$module loading"
                Install-Module $module -Scope CurrentUser
                Import-Module $module -Scope Local
            } else {
                Write-Output "$module already loaded"
            }
        }
    }
}
#--------------------------------------------------------------------------------------

if ($script:UltimatePSProfile.stopwatch.ElapsedMilliseconds -lt ($script:UltimatePSProfile.max_profileload_seconds * 1000)) {
    InstallandLoadModules
} else {
    Write-Output "Skipping module installs as the profile took > $($script:UltimatePSProfile.max_profileload_seconds) seconds to load."
}

#--------------------------------------------------------------------------------------

#Remind user which functions are available in the console
Write-Output "The following functions were set by profile:"
Get-ChildItem -Path Function:\ | Where-Object{$_.Source.ToString().Length -lt 1} | Select-Object Name | Format-Wide -AutoSize
#--------------------------------------------------------------------------------------

#Don't forget to stop the stopwatch
$script:UltimatePSProfile.stopwatch.stop()
if ($IsLinux) {
    Write-Output "Loading personal and system profiles took $($script:UltimatePSProfile.stopwatch.ElapsedMilliseconds) ms."
    [Environment]::GetEnvironmentVariable('MOTD_SHOWN')
}