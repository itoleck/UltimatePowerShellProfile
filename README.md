# The ultimate PowerShell profile script

## First time use

iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/itoleck/VariousScripts/main/Windows/PowerShell/Microsoft.PowerShell_profile.ps1'))

Automatically downloads the script and copies to the PowerShell folders for PS5 & PS7

## Script Management Commands

- Install-Profile - Re-download the newest version of the script and update the PowerShell profile

- Edit-Profile - Use PowerShell ISE to edit the current profile

- Sync-Profile or Restore-Profile - rerun the profile script in a session

## Command shortcuts added

- Directory traversal commands: cduser, cddownloads, cddownloads, cdtemp, cdusertemp, cd..., cd.... and more

- Linux/Unix-Like commands: head, tail, df, touch and more

- uptime, Get-PubIP

## Command environment setup

- PSReadLine

- Oh-my-posh
