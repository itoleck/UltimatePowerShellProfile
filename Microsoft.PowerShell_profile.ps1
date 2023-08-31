#The Ultimate PowerShell Profile. Sets up environment for Windows PowerShell (5) and PowerShell 7+ profiles on Windows and Linux.
#Copies itself to the default PowerShell folders from GitHub URL in the $script:UltimatePSProfile.psprofile_link variable.
#Will measure it's own performance and skip parts like looking for new module versions if the profile is taking too long to load.
#Adds some shortcuts for Linux-Like terminal operation in Windows.
#Only runs admin functions when the session is run as admin.

#Inspired by https://github.com/ChrisTitusTech/powershell-profile which was inspired from https://gist.github.com/timsneath/19867b12eee7fd5af2ba
#https://github.com/itoleck/UltimatePowerShellProfile

#--------------------------------------------------------------------------------------
#Setup the initial object to hold all of the script settings. Using object so as not to clutter PS session with variables.
#Most of these can be edited for your local system.

#stopwatch                  Start tracking the time that the script is running

#max_profileload_seconds    Set the maximum time in seconds to determine if the profile should look to install modules that are not available in the profile

#psprofile_link             PowerShell profile URL. You can copy the code in this script and create a GitHub. Update this property.

#psprofile_repo_path        Local repo folder for this Ultimate PowerShell Profile. Used for the Copy-Profile command

#global_modules             Which modules to load in this profile if the environment is admin(scope global)
#                           If forking this script and adding your own modules, please set back these defaults when submitting PR.

#local_modules              Which modules to load in this profile if the environment is non-admin user (scope local)
#                           If forking this script and adding your own modules, please set back these defaults when submitting PR.

#profile_editors            A list of text editors, in order of precedence.
Function Private:CreateUltimatePSProfileVars {
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
        local_modules = 'PowerShellGet','Terminal-Icons','Carbon','CredentialManager','PnP.PowerShell','ImportExcel','WifiTools','ExchangeOnlineManagement','MicrosoftTeams','PSScriptAnalyzer','AzureSaveMoney'
        linux_modules = 'PowerShellGet'
        profile_editors = 'code','powershell_ise.exe','notepad++.exe','notepad.exe','nano'
    }
}

#--------------------------------------------------------------------------------------
#Set some paths if this session is running in Windows
Function Private:SetScriptPaths {
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
}

#--------------------------------------------------------------------------------------
#Create this profile from GH if it does not exist
Function Private:CreateProfileIfNotExist {
    if (!(Test-Path -Path $PROFILE)) {
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
                Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1" -Force -Verbose
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
}

#--------------------------------------------------------------------------------------
#Setup command window title. Gets overwritten in Windows Terminal.
Function Private:SetWindowTitle {
    $Host.UI.RawUI.WindowTitle = "PowerShell {0} Running in {1}" -f $PSVersionTable.PSVersion.ToString(), $Host.Name
}

#--------------------------------------------------------------------------------------
#Set some PowerShell settings that can help to reduce module import errors
#https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/reference/5.1/Microsoft.PowerShell.Core/About/about_Preference_Variables.md
Function Private:IncreasePowerShell5Counts {
    if ($PSVersionTable.PSVersion.Major -eq 5 ) {
        $MaximumFunctionCount = 8192
        $MaximumVariableCount = 8192
    }
}

#--------------------------------------------------------------------------------------
#Set variables for user and admin status
Function Private:SetAdminStatus {
    if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
        $script:identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $script:principal = New-Object Security.Principal.WindowsPrincipal $script:identity
        $script:isAdmin = $script:principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } else {
        if ($IsLinux -and (id -u) -eq 0) {
            $script:isAdmin = $true
        }
    }
}

#--------------------------------------------------------------------------------------
#Set PowerShell Gallery as a trusted source for module installation
Function Private:SetPowerShellGalleryTrust {
    if (Get-Module -ListAvailable -Name PowerShellGet) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Write-Output "Set PSGallery source (https://www.powershellgallery.com/) as trusted"
    } else {
        Write-Output "PowerShellGet PowerShell module not installed. Run Install-Module -Name PowerShellGet -Scope AllUsers"
    }
}

#--------------------------------------------------------------------------------------
#Setup PSReadLine
Function Private:StartPSReadLine {
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
}

#--------------------------------------------------------------------------------------
#Oh-my-posh setup
Function Private:StartOhMyPosh {
    if (($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) -and ($host.Name -match "ConsoleHost")) {
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
    } else {
        Write-Output "PowerShell 7+ not running in Windows Console Host. Oh-my-posh not available."
    }
}

#--------------------------------------------------------------------------------------
# Set Windows Directory traversal functions
Function Private:SetWindowsDirTraversal {
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
            Copy-Item -Path "$($script:UltimatePSProfile.mydocuments_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1" -Force -Verbose
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

#--------------------------------------------------------------------------------------
#Open this profile in an editor
Function Edit-Profile {
    #Determine which editor to use
    $isopen = $false

    foreach ($editor in $script:UltimatePSProfile.profile_editors) {
        Write-Output "Trying to open $($profile.CurrentUserCurrentHost) in $editor"
        if (!($isopen) -and ((Get-Command -Name $editor).Length -gt 0)) {
            try {
                Start-Process $editor -ArgumentList ($profile.CurrentUserCurrentHost)
                $isopen = $true
				Write-Output "Opened $($profile.CurrentUserCurrentHost) in $editor"
				break
            }
            catch {
                <#Do this if a terminating exception happens#>
            }
        }
    }

    If ($isopen = $false) {
        Write-Output "Could not find a suitable PowerShell script editor on your machine."
    }
}

#--------------------------------------------------------------------------------------
#Copy this file from a local GitHub repo folder to the Windows PowerShell and PowerShell folders
#Used when developing the script on a machine for fast testing. Run Copy-ProfilesFromLocalRepo, then Sync-Profile
Function Copy-ProfilesFromLocalRepo {
    try {
        Write-Output "Copying profile to PowerShell folders."
        if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
            Copy-Item -Path "$($script:UltimatePSProfile.psprofile_repo_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell" -Force -Verbose
            Copy-Item -Path "$($script:UltimatePSProfile.psprofile_repo_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)PowerShell" -Force -Verbose
            Copy-Item -Path "$($script:UltimatePSProfile.psprofile_repo_path)Microsoft.PowerShell_profile.ps1" -Destination "$($script:UltimatePSProfile.mydocuments_path)WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1" -Force -Verbose
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

#--------------------------------------------------------------------------------------
#Just reload the profile in the current window
Function Sync-Profile {
    & $profile
}
Set-Alias -Name Restore-Profile -Value Sync-Profile

#--------------------------------------------------------------------------------------
#Install PowerShell modules if the script execution time is within limit
#Need to run the global module installs in an administrator PowerShell.
#Check to make sure profile load stays fast. If script has executed > the set limit don't worry about installing modules that are not available
function InstallandLoadModules() {
    #Just bypassing Linux root user/Global modules for now. Load them all in user/local
    if ($IsLinux) {
        $result_str = ""
        foreach ($module in $script:UltimatePSProfile.linux_modules) {
            if (-not(Get-Module -ListAvailable -Name $module)) {
                $result_str = $result_str + "$module(Installing) "
                Install-Module $module -Scope CurrentUser
                Import-Module $module -Scope Local
            } else {
                $result_str = $result_str + "$module(Available) "
            }
        }
        Write-Output $result_str
    } else {
        if ($script:isAdmin -eq $true) { #Maybe check if the global modules are available and if they are not, let user know to run as admin to install
            $result_str = ""
            foreach($global_module in $script:UltimatePSProfile.global_modules) {
                if (-not(Get-Module -ListAvailable -Name $global_module)) {
                    $result_str = $result_str + "$global_module(Installing) "
                    Install-Module $global_module -Scope AllUsers
                    Import-Module $global_module -Scope Global
                } else {
                    $result_str = $result_str + "$global_module(Available) "
                }
            }
        }
        Write-Output $result_str
        $result_str = ""
        foreach ($module in $script:UltimatePSProfile.local_modules) {
            if (-not(Get-Module -ListAvailable -Name $module)) {
                $result_str = $result_str + "$module(Installing) "
                Install-Module $module -Scope CurrentUser
                Import-Module $module -Scope Local
            } else {
                $result_str = $result_str + "$module(Available) "
            }
        }
        Write-Output $result_str
    }
}

#Begin script
CreateUltimatePSProfileVars
SetScriptPaths
CreateProfileIfNotExist
SetWindowTitle
IncreasePowerShell5Counts
SetAdminStatus
SetPowerShellGalleryTrust
StartPSReadLine
StartOhMyPosh
SetWindowsDirTraversal

#--------------------------------------------------------------------------------------
#Install extra functions if the script is still within load time limit
if ($script:UltimatePSProfile.stopwatch.ElapsedMilliseconds -lt ($script:UltimatePSProfile.max_profileload_seconds * 1000)) {
    #Other useful functions
    if ($script:isAdmin -eq $true) {
        if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
            Function edithosts {notepad.exe "$env:SystemRoot\System32\drivers\etc\hosts"}
        } else {
            Function edithosts {nano}
        }
        $Host.UI.RawUI.WindowTitle += " [ADMIN]"
    }
    Function os {
        if ($IsWindows) {
            [System.Environment]::OSVersion
        } else {
            uname -a
        }
    }
    Function Get-PubIP {
        (Invoke-WebRequest http://ifconfig.me/ip ).Content
    }
    #Compute file hashes - useful for checking successful downloads 
    Function md5 { Get-FileHash -Algorithm MD5 $args }
    Function sha1 { Get-FileHash -Algorithm SHA1 $args }
    Function sha256 { Get-FileHash -Algorithm SHA256 $args }

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
    #--------------------------------------------------------------------------------------
    #Functions that only load if a certain OS
    if ($IsWindows -or ($PSVersionTable.PSVersion.Major -eq 5)) {
        #Linux-Like functions and commands
        #Set UNIX-like aliases for the admin command, so sudo <command> will run the command
        #with elevated rights.

        Set-Alias -Name su -Value admin
        Set-Alias -Name sudo -Value admin
        Function uptime {
            if ($PSVersionTable.PSVersion.Major -eq 5 ) {
                Get-WmiObject win32_operatingsystem |
                Select-Object @{EXPRESSION={ $_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
            }
            if ($IsWindows -and $PSVersionTable.PSVersion.Major -eq 7 ) {
                net statistics workstation | Select-String "since" | foreach-object {$_.ToString().Replace('Statistics since ', '')}
            }
        }
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
        Function n { notepad.exe $args }
        Function n++ {
            $npp=(Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe")
            Start-Process -FilePath ($npp.'(default)') -ArgumentList $args
        }
        Function tm { taskmgr.exe }
        #Drive shortcuts
        Function HKLM: { Set-Location HKLM: }
        Function HKCU: { Set-Location HKCU: }
        Function Env: { Set-Location Env: }
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
} else {
    Write-Output "Skipping extra setting up PowerShell functions as the profile took > $($script:UltimatePSProfile.max_profileload_seconds) seconds to load."
}

#--------------------------------------------------------------------------------------
#Install modules if the script is still within load time limit and not already available in session
if ($script:UltimatePSProfile.stopwatch.ElapsedMilliseconds -lt ($script:UltimatePSProfile.max_profileload_seconds * 1000)) {
    InstallandLoadModules
} else {
    Write-Output "Skipping module installs as the profile took > $($script:UltimatePSProfile.max_profileload_seconds) seconds to load."
}

#--------------------------------------------------------------------------------------
#End of script
#Remind user which functions are available in the console
Write-Output "The following functions were set by profile:"
Get-ChildItem -Path Function:\ | Where-Object{$_.Source.ToString().Length -lt 1} | Select-Object Name | Format-Wide -AutoSize

#Don't forget to stop the stopwatch
$script:UltimatePSProfile.stopwatch.stop()
if ($IsLinux) {
    Write-Output "Loading personal and system profiles took $($script:UltimatePSProfile.stopwatch.ElapsedMilliseconds) ms."
    [Environment]::GetEnvironmentVariable('MOTD_SHOWN')
}