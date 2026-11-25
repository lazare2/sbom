<#
.SYNOPSIS
    Removes the SBOM Platform virtual machine from Windows Server. Keeps the data.

.DESCRIPTION
    Shuts the machine down cleanly and removes it from Hyper-V, together with the private
    network, the port forward and the firewall rule the installer created.

    The disks stay in <InstallRoot>\vm: sbom-data.vhdx holds the database, the stored SBOMs
    and the backups. Nothing here deletes them; delete the folder yourself once you are sure
    you no longer need it.

    Run in PowerShell as Administrator:
      .\windows\uninstall-windows.ps1
      .\windows\uninstall-windows.ps1 -InstallRoot D:\SBOM-Platform
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\SBOM-Platform"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)

$vm = Get-VM -Name $SbomVmName -ErrorAction SilentlyContinue
if ($vm) {
    Write-Step "Shutting down and removing the virtual machine $SbomVmName"
    if ($vm.State -ne "Off") { Stop-VM -Name $SbomVmName -Force }
    Remove-VM -Name $SbomVmName -Force
}
else { Write-Note "No virtual machine named $SbomVmName." }

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (Get-NetNat -Name $SbomNatName -ErrorAction SilentlyContinue) {
    if (-not $isAdmin) { Stop-WithError "Removing the private network needs Administrator. Run this again as Administrator." }
    Write-Step "Removing the port forward and the private network"
    Get-NetNatStaticMapping -NatName $SbomNatName -ErrorAction SilentlyContinue | Remove-NetNatStaticMapping -Confirm:$false
    Remove-NetNat -Name $SbomNatName -Confirm:$false
}
if (Get-VMSwitch -Name $SbomSwitchName -ErrorAction SilentlyContinue) { Remove-VMSwitch -Name $SbomSwitchName -Force }
# SBOM-Platform-HTTP for the main port, SBOM-Platform-TCP-<port> for the extra ones (443 ...),
# and SBOM-Platform-HTTPS, the name the 0.5.1 by-hand HTTPS steps used.
foreach ($rule in @(Get-NetFirewallRule -Name "SBOM-Platform-*" -ErrorAction SilentlyContinue)) {
    if ($isAdmin) { Remove-NetFirewallRule -Name $rule.Name }
    else { Write-Note "The firewall rule $($rule.Name) needs Administrator to remove." }
}

Write-Host ""
Write-Ok "Removed. The data is kept."
Write-Note "Disks: $(Join-Path $InstallRoot 'vm')  (sbom-data.vhdx holds the database, SBOMs and backups)"
Write-Note "Install again with install-windows.cmd, or attach sbom-data.vhdx to another Linux machine."
