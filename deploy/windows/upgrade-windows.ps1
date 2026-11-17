<#
.SYNOPSIS
    Upgrades the SBOM Platform virtual machine on Windows Server to the version of this bundle.

.DESCRIPTION
    Nothing is downloaded. This script puts the new bundle on a disc, gives it to the machine
    and runs the Linux upgrade inside it, which:

      1. backs up the database, the stored SBOM files and .env (kept with the nightly backups);
      2. loads the new images and starts the new version;
      3. if the new version does not come up, puts the previous version and the backed-up
         data back by itself and says so.

    The data disk is never replaced, and Hyper-V settings are not changed.

    Run in PowerShell as Administrator (or a member of Hyper-V Administrators), from the
    unpacked NEW bundle:
      .\upgrade-windows.cmd
      .\upgrade-windows.cmd -InstallRoot D:\SBOM-Platform
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\SBOM-Platform"
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$bundle = Split-Path $here -Parent
. (Join-Path $here "common.ps1")

Write-Host ""
Write-Host "SBOM Platform - Windows Server upgrade" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray

# --- preflight --------------------------------------------------------------------------
$state = Join-Path $InstallRoot "state"
$keyFile = Join-Path $state "vm-ssh-key"
$knownHosts = Join-Path $state "known_hosts"
$installInfo = Join-Path $state "install.txt"
if (-not (Test-Path $keyFile) -or -not (Test-Path $installInfo)) {
    Stop-WithError "No installation found in $InstallRoot. Pass -InstallRoot, or install with install-windows.cmd first."
}
$info = @{}
foreach ($line in Get-Content $installInfo) { if ($line -match '^([A-Za-z]+)=(.*)$') { $info[$Matches[1]] = $Matches[2] } }
$address = $info["VmAddress"]
$vm = Get-VM -Name $SbomVmName -ErrorAction SilentlyContinue
if (-not $vm) { Stop-WithError "The virtual machine $SbomVmName was not found." }
if ($vm.State -ne "Running") {
    Write-Step "Starting $SbomVmName"
    Start-VM -Name $SbomVmName
}
# With a DHCP switch the address can change; the machine reports its current one to Hyper-V.
$deadline = (Get-Date).AddMinutes(3)
do {
    $reported = (Get-VMNetworkAdapter -VMName $SbomVmName).IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
    if (-not $reported) { Start-Sleep -Seconds 5 }
} while (-not $reported -and (Get-Date) -lt $deadline)
if ($reported) { $address = $reported }
foreach ($f in @((Join-Path $bundle "images.tar"), (Join-Path $bundle "images.env"), (Join-Path $bundle "linux\upgrade.sh"))) {
    if (-not (Test-Path $f)) { Stop-WithError "$f is missing. Run this from the unpacked new bundle." }
}
$newVersion = ((Get-Content (Join-Path $bundle "images.env")) -match '^APP_VERSION=' | Select-Object -First 1) -replace '^APP_VERSION=', ''
$inner = "http://$($address):8080"
if (-not (Wait-PlatformHealthy -Url $inner -Minutes 10)) {
    Stop-WithError "The platform at $inner does not answer now. Fix that before upgrading (Hyper-V Manager, or ssh in)."
}
if ((Invoke-VmCommand -Address $address -KeyFile $keyFile -KnownHosts $knownHosts -Command "true" -AllowFail) -ne 0) {
    Stop-WithError "Cannot open a shell in the machine at $address with $keyFile."
}

# --- the disc ---------------------------------------------------------------------------
Write-Step "Writing the upgrade disc for $newVersion"
$stage = Join-Path $InstallRoot "upgrade-disc"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Get-ChildItem $bundle -File | Where-Object { $_.Extension -notin @(".cmd", ".ps1") } | ForEach-Object { Copy-Item $_.FullName $stage }
foreach ($dir in @("linux", "ca")) {
    if (Test-Path (Join-Path $bundle $dir)) { Copy-Item (Join-Path $bundle $dir) $stage -Recurse }
}
$iso = Join-Path $InstallRoot "vm\sbom-upgrade.iso"
New-IsoFromFolder -Folder $stage -IsoPath $iso -Label "sbomupgrade"
Remove-Item -Recurse -Force $stage

$dvd = Get-VMDvdDrive -VMName $SbomVmName | Select-Object -First 1
if (-not $dvd) { Stop-WithError "The machine has no DVD drive. Shut it down, add one in Hyper-V Manager, and run this again." }
Set-VMDvdDrive -VMName $SbomVmName -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $iso

# --- upgrade inside the machine -------------------------------------------------------------
Write-Step "Upgrading (backup, new version, automatic rollback on failure)"
$code = 1
try {
    Start-Sleep -Seconds 3
    $code = Invoke-VmCommand -Address $address -KeyFile $keyFile -KnownHosts $knownHosts -AllowFail -Command (
        "sudo mkdir -p /mnt/sbom-upgrade && sudo mount -o ro /dev/sr0 /mnt/sbom-upgrade && " +
        "sudo sh /mnt/sbom-upgrade/linux/upgrade.sh; rc=`$?; sudo umount /mnt/sbom-upgrade; exit `$rc")
}
finally {
    Set-VMDvdDrive -VMName $SbomVmName -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $null
    Remove-Item -Force $iso -ErrorAction SilentlyContinue
}

Write-Host ""
if ($code -eq 0 -and (Wait-PlatformHealthy -Url $inner -Minutes 5)) {
    Write-Ok "Upgraded to $newVersion."
    Write-Note "A backup from just before the upgrade is in the machine: /var/backups/sbom-platform"
    exit 0
}
Write-Host "The upgrade did not complete; the messages above say whether the previous version was put back." -ForegroundColor Red
exit 1
