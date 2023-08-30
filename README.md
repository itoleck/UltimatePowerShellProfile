# The ultimate PowerShell profile script

I would love to see what cool things others would put inside a PowerShell profile.; while keeping the overall profile load to 5 seconds or less.

This script does not guaranty 5 second profile load, but has a check to skip some components if the profile is taking more then 5 seconds to load.

## First time use

iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/itoleck/UltimatePowerShellProfile/main/Microsoft.PowerShell_profile.ps1'))

Automatically downloads the script and copies to the PowerShell folders for PS5 & PS7

## Script Management Commands

- Install-Profile - Re-download the newest version of the script and update the PowerShell profile

- Edit-Profile - Use PowerShell ISE to edit the current profile

- Sync-Profile or Restore-Profile - rerun the profile script in a session

## Command shortcuts added

- Directory traversal commands: cduser, cddownloads, cddownloads, cdtemp, cdusertemp, cd..., cd.... and more

- Linux/Unix-Like commands: head, tail, df, touch and more

- uptime, Get-PubIP, Open HOSTS file in Notepad (admin)

## Command environment setup

- PSReadLine

- Oh-my-posh
