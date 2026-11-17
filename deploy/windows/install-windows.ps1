<#
.SYNOPSIS
    Installs the SBOM Platform on Windows Server as a Hyper-V virtual machine.

.DESCRIPTION
    Everything comes from this bundle; nothing is downloaded.

      1. Creates a Linux virtual machine (Debian, prepared for this platform) from the disk in
         this folder, with a second disk for the data, and sets it to start with the server.
      2. Gives it a private network: the server forwards one port (8080 by default) to it.
      3. Starts it. On its first start the machine installs the platform from a disc this
         script writes (the same Linux installer as on any Linux server: service, nightly
         backup at 02:30), and, with -MigrateFrom, takes over an existing Docker Desktop
         installation: its data and its secrets, so CI tokens and sign-ins keep working.
         The installation it takes over is only read, never changed or stopped.

    Run in PowerShell as Administrator, from the unpacked bundle:
      .\install-windows.cmd
      .\install-windows.cmd -MigrateFrom C:\sbom
      .\install-windows.cmd -Port 9000 -InstallRoot D:\SBOM-Platform -MemoryGB 16

    Requires the Hyper-V role (on a virtual server, nested virtualization enabled by the host).

.PARAMETER MigrateFrom
    The folder of an installation running on Docker Desktop on this server (the one with its
    .env). Docker Desktop must be running. That installation is left as it is: stop it after
    checking the new one, and keep it until you are satisfied.
#>
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [string]$InstallRoot = "C:\SBOM-Platform",
    [int]$Cpu = 4,
    [int]$MemoryGB = 8,
    [int]$DataDiskGB = 200,
    # The address people will use, if not http://<this server>:<Port>.
    [string]$PublicUrl = "",
    # The outbound proxy, if the server reaches the internet through one: http://proxy:3128
    [string]$Proxy = "",
    [string]$NoProxy = "",
    # Private network between this server and the machine. Change only if it is in use here.
    [string]$Subnet = "192.168.250",
    # Use an existing Hyper-V switch with DHCP instead of the private network and port forward
    # (for example an external switch, so the machine gets its own address on the LAN).
    [string]$SwitchName = "",
    [string]$MigrateFrom = "",
    # The Compose project of the installation named by -MigrateFrom.
    [string]$MigrateProject = "sbom-platform"
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$bundle = Split-Path $here -Parent
. (Join-Path $here "common.ps1")

$useNat = [string]::IsNullOrEmpty($SwitchName)
$vmAddress = "$Subnet.10"
$hostAddress = "$Subnet.1"

Write-Host ""
Write-Host "SBOM Platform - Windows Server installation" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray

# --- preflight --------------------------------------------------------------------------
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($useNat -and -not $isAdmin) { Stop-WithError "Run this as Administrator (right-click PowerShell, Run as administrator)." }
if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    Stop-WithError "Hyper-V is not installed. Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart"
}
try { $null = Get-VMHost } catch { Stop-WithError "Hyper-V is not usable: $($_.Exception.Message)" }
if (Get-VM -Name $SbomVmName -ErrorAction SilentlyContinue) {
    Stop-WithError "A virtual machine named $SbomVmName exists already. To upgrade it use upgrade-windows.cmd."
}
$osImage = Join-Path $here "sbom-vm.vhdx"
foreach ($f in @($osImage, (Join-Path $bundle "images.tar"), (Join-Path $bundle "linux\install.sh"), (Join-Path $bundle "linux\vm-firstboot.sh"))) {
    if (-not (Test-Path $f)) { Stop-WithError "$f is missing. Run this from the unpacked bundle." }
}
foreach ($tool in @("ssh.exe", "ssh-keygen.exe")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Stop-WithError "$tool not found. Add the Windows feature: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
    }
}
if ($useNat) {
    $other = Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $SbomNatName }
    if ($other) {
        Write-Note "Another NAT network exists on this server: $($other.Name) ($($other.InternalIPInterfaceAddressPrefix))."
        Write-Note "Windows allows only one in some versions; if the next step fails, use -SwitchName."
    }
    if (Get-NetNatStaticMapping -ErrorAction SilentlyContinue | Where-Object { $_.ExternalPort -eq $Port -and $_.NatName -ne $SbomNatName }) {
        Stop-WithError "Port $Port is already forwarded by another NAT. Pass -Port."
    }
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
        Stop-WithError "Port $Port is in use on this server (Docker Desktop's installation?). Pass -Port, or stop that first."
    }
}
$freeGB = [math]::Floor((Get-PSDrive -Name ($InstallRoot.Substring(0, 1))).Free / 1GB)
if ($freeGB -lt 40) { Stop-WithError "Only $freeGB GB free on $($InstallRoot.Substring(0, 2)); at least 40 GB is needed." }

if ([string]::IsNullOrEmpty($PublicUrl)) {
    $PublicUrl = if ($useNat) { "http://$($env:COMPUTERNAME.ToLower()):$Port" } else { "" }
}

# --- folders and key ----------------------------------------------------------------------
Write-Step "Preparing $InstallRoot"
$vmDir = Join-Path $InstallRoot "vm"
$state = Get-SbomStateDir $InstallRoot
New-Item -ItemType Directory -Force -Path $vmDir | Out-Null
if ($isAdmin) {
    # Administrators and SYSTEM only: the folder holds the SSH key to the machine and, after a
    # first install, its initial admin password.
    & icacls.exe $InstallRoot /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
}
$keyFile = Join-Path $state "vm-ssh-key"
$knownHosts = Join-Path $state "known_hosts"
if (-not (Test-Path $keyFile)) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & ssh-keygen.exe -q -t ed25519 -N '""' -C "sbom-platform-host" -f $keyFile 2>&1 | Out-Null
    if (-not (Test-Path $keyFile)) { & ssh-keygen.exe -q -t ed25519 -N "" -C "sbom-platform-host" -f $keyFile 2>&1 | Out-Null }
    $ErrorActionPreference = $previous
    if (-not (Test-Path $keyFile)) { Stop-WithError "Could not create the SSH key." }
}
$publicKey = (Get-Content "$keyFile.pub" -Raw).Trim()

# --- the installation being moved ----------------------------------------------------------
$stage = Join-Path $InstallRoot "disc"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path (Join-Path $stage "sbom"), (Join-Path $stage "bundle") | Out-Null

if ($MigrateFrom) {
    Write-Step "Copying the data of the installation in $MigrateFrom (it keeps running)"
    $migrate = Join-Path $stage "migrate"
    New-Item -ItemType Directory -Force -Path $migrate | Out-Null
    $envFile = Join-Path $MigrateFrom ".env"
    if (-not (Test-Path $envFile)) { Stop-WithError "$envFile not found. -MigrateFrom is the folder holding the installation's .env." }
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try {
        & docker info *> $null
        if ($LASTEXITCODE -ne 0) { Stop-WithError "Docker Desktop is not running; start it so the data can be read." }
        $db = (& docker ps --filter "label=com.docker.compose.project=$MigrateProject" --filter "label=com.docker.compose.service=db" --format "{{.Names}}") | Select-Object -First 1
        if (-not $db) { Stop-WithError "The database container of project $MigrateProject is not running." }
        # Read-only on the source: a dump and a read-only mount of the files volume.
        & docker exec $db pg_dump -U sbom -Fc sbom -f /tmp/sbom-migrate.dump
        if ($LASTEXITCODE -ne 0) { Stop-WithError "pg_dump failed in $db." }
        & docker cp "$($db):/tmp/sbom-migrate.dump" (Join-Path $migrate "sbom.dump") | Out-Null
        & docker exec $db rm -f /tmp/sbom-migrate.dump
        $entries = (& docker run --rm -v "$($migrate):/m:ro" --entrypoint pg_restore postgres:16-alpine -l /m/sbom.dump | Measure-Object -Line).Lines
        if ($entries -le 10) { Stop-WithError "The database copy could not be read back ($entries entries)." }
        & docker run --rm -v "$($MigrateProject)_sbom-blobs:/data:ro" -v "$($migrate):/backup" --entrypoint tar postgres:16-alpine czf /backup/sbom-blobs.tar.gz -C /data .
        if ($LASTEXITCODE -ne 0) { Stop-WithError "Copying the stored SBOM files failed." }
    }
    finally { $ErrorActionPreference = $previous }
    Copy-Item $envFile (Join-Path $migrate "env.txt")
    Write-Note ("database {0:N0} MB ({1} entries), SBOM files {2:N0} MB" -f ((Get-Item (Join-Path $migrate "sbom.dump")).Length / 1MB), $entries, ((Get-Item (Join-Path $migrate "sbom-blobs.tar.gz")).Length / 1MB))
}

# --- the disc: cloud-init settings, the bundle, the first-boot script -------------------------
Write-Step "Writing the installation disc"
$lf = New-Object Text.UTF8Encoding $false
function Write-LfFile { param([string]$Path, [string]$Text) [IO.File]::WriteAllText($Path, $Text.Replace("`r`n", "`n"), $lf) }

# The bundle, without the Windows parts (the machine has no use for its own disk image).
Get-ChildItem $bundle -File | ForEach-Object { Copy-Item $_.FullName (Join-Path $stage "bundle") }
foreach ($dir in @("linux", "ca")) {
    if (Test-Path (Join-Path $bundle $dir)) { Copy-Item (Join-Path $bundle $dir) (Join-Path $stage "bundle") -Recurse }
}
Get-ChildItem (Join-Path $stage "bundle") -File -Include *.cmd, *.ps1 -Recurse | Remove-Item

$instance = "sbom-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
Write-LfFile (Join-Path $stage "meta-data") "instance-id: $instance`nlocal-hostname: sbom-platform`n"

if ($useNat) {
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notlike "vEthernet*" -and $_.InterfaceAlias -notlike "Loopback*" } |
        ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
    if ($dns.Count -eq 0) { Stop-WithError "Could not find this server's DNS servers; the machine needs them to reach the update addresses." }
    $dnsYaml = ($dns | ForEach-Object { "          - $_" }) -join "`n"
    Write-LfFile (Join-Path $stage "network-config") @"
version: 2
ethernets:
  eth0:
    match:
      driver: hv_netvsc
    set-name: eth0
    dhcp4: false
    addresses: [$vmAddress/24]
    routes:
      - to: default
        via: $hostAddress
    nameservers:
      addresses:
$dnsYaml
"@
}
else {
    Write-LfFile (Join-Path $stage "network-config") "version: 2`nethernets:`n  eth0:`n    match:`n      driver: hv_netvsc`n    set-name: eth0`n    dhcp4: true`n"
}

Write-LfFile (Join-Path $stage "user-data") @"
#cloud-config
hostname: sbom-platform
users:
  - name: sbomadmin
    groups: [sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $publicKey
ssh_pwauth: false
package_update: false
package_upgrade: false
runcmd:
  - [sh, -c, "mkdir -p /mnt/sbom-disc && (mount -o ro LABEL=cidata /mnt/sbom-disc || mount -o ro /dev/sr0 /mnt/sbom-disc) && sh /mnt/sbom-disc/bundle/linux/vm-firstboot.sh /mnt/sbom-disc >> /var/log/sbom-firstboot.log 2>&1; umount /mnt/sbom-disc"]
"@

Write-LfFile (Join-Path $stage "sbom\settings.env") @"
SBOM_PUBLIC_URL='$PublicUrl'
SBOM_HTTP_PROXY='$Proxy'
SBOM_NO_PROXY='$NoProxy'
"@

$iso = Join-Path $vmDir "sbom-install.iso"
New-IsoFromFolder -Folder $stage -IsoPath $iso
Remove-Item -Recurse -Force $stage
Write-Note ("disc {0:N0} MB" -f ((Get-Item $iso).Length / 1MB))

# --- network ----------------------------------------------------------------------------
if ($useNat) {
    Write-Step "Private network $Subnet.0/24, port $Port forwarded to the machine"
    if (-not (Get-VMSwitch -Name $SbomSwitchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $SbomSwitchName -SwitchType Internal | Out-Null
    }
    $ifAlias = "vEthernet ($SbomSwitchName)"
    if (-not (Get-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $hostAddress -ErrorAction SilentlyContinue)) {
        New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $hostAddress -PrefixLength 24 | Out-Null
    }
    if (-not (Get-NetNat -Name $SbomNatName -ErrorAction SilentlyContinue)) {
        New-NetNat -Name $SbomNatName -InternalIPInterfaceAddressPrefix "$Subnet.0/24" | Out-Null
    }
    Get-NetNatStaticMapping -NatName $SbomNatName -ErrorAction SilentlyContinue | Remove-NetNatStaticMapping -Confirm:$false
    Add-NetNatStaticMapping -NatName $SbomNatName -Protocol TCP -ExternalIPAddress "0.0.0.0" -ExternalPort $Port -InternalIPAddress $vmAddress -InternalPort 8080 | Out-Null
    if (-not (Get-NetFirewallRule -Name "SBOM-Platform-HTTP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "SBOM-Platform-HTTP" -DisplayName "SBOM Platform (TCP $Port)" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    }
    else { Set-NetFirewallRule -Name "SBOM-Platform-HTTP" -LocalPort $Port }
    $switch = $SbomSwitchName
}
else {
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) { Stop-WithError "No Hyper-V switch named '$SwitchName'." }
    $switch = $SwitchName
}

# --- the machine -------------------------------------------------------------------------
Write-Step "Creating the virtual machine $SbomVmName ($Cpu CPUs, $MemoryGB GB memory, $DataDiskGB GB data disk)"
$osDisk = Join-Path $vmDir "sbom-system.vhdx"
$dataDisk = Join-Path $vmDir "sbom-data.vhdx"
Copy-Item $osImage $osDisk
Resize-VHD -Path $osDisk -SizeBytes 30GB
if (-not (Test-Path $dataDisk)) { New-VHD -Path $dataDisk -SizeBytes ([int64]$DataDiskGB * 1GB) -Dynamic | Out-Null }

New-VM -Name $SbomVmName -Generation 2 -MemoryStartupBytes ([int64]$MemoryGB * 1GB) -VHDPath $osDisk -SwitchName $switch -Path $vmDir | Out-Null
Set-VM -Name $SbomVmName -StaticMemory -ProcessorCount $Cpu -AutomaticStartAction Start -AutomaticStartDelay 0 `
    -AutomaticStopAction ShutDown -CheckpointType Disabled -Notes "SBOM Platform. Managed by install-windows.ps1 / upgrade-windows.ps1 in $InstallRoot."
Set-VMFirmware -VMName $SbomVmName -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMHardDiskDrive -VMName $SbomVmName -Path $dataDisk
Add-VMDvdDrive -VMName $SbomVmName -Path $iso
Enable-VMIntegrationService -VMName $SbomVmName -Name "Guest Service Interface" -ErrorAction SilentlyContinue

@"
InstallRoot=$InstallRoot
Port=$Port
UseNat=$useNat
VmAddress=$(if ($useNat) { $vmAddress } else { "" })
PublicUrl=$PublicUrl
"@ | Out-File (Join-Path $state "install.txt") -Encoding ascii

Write-Step "Starting it. The first start installs the platform: 5 to 15 minutes."
Start-VM -Name $SbomVmName

# --- wait --------------------------------------------------------------------------------
$address = $vmAddress
if (-not $useNat) {
    $deadline = (Get-Date).AddMinutes(5)
    do {
        Start-Sleep -Seconds 5
        $address = (Get-VMNetworkAdapter -VMName $SbomVmName).IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
    } while (-not $address -and (Get-Date) -lt $deadline)
    if (-not $address) { Stop-WithError "The machine did not report an address. Check the switch's DHCP." }
    "VmAddress=$address" | Out-File (Join-Path $state "install.txt") -Append -Encoding ascii
}
$inner = "http://$($address):8080"
if (-not (Wait-PlatformHealthy -Url $inner -Minutes 25)) {
    Write-Host "The platform did not answer within 25 minutes. The first-boot log:" -ForegroundColor Yellow
    $null = Invoke-VmCommand -Address $address -KeyFile $keyFile -KnownHosts $knownHosts -Command "sudo tail -n 60 /var/log/sbom-firstboot.log" -AllowFail
    exit 1
}
# Health answers before the first-boot script has finished (a migration restores after it).
$deadline = (Get-Date).AddMinutes(30)
do {
    Start-Sleep -Seconds 10
    $code = Invoke-VmCommand -Address $address -KeyFile $keyFile -KnownHosts $knownHosts -Command "test -f /srv/sbom/firstboot.done" -AllowFail
} while ($code -ne 0 -and (Get-Date) -lt $deadline)
if ($code -ne 0 -or -not (Wait-PlatformHealthy -Url $inner -Minutes 10)) {
    Write-Host "The first start did not finish. Log:" -ForegroundColor Yellow
    $null = Invoke-VmCommand -Address $address -KeyFile $keyFile -KnownHosts $knownHosts -Command "sudo tail -n 60 /var/log/sbom-firstboot.log" -AllowFail
    exit 1
}

# The installation disc is no longer needed, and on a move it holds that installation's secrets.
Set-VMDvdDrive -VMName $SbomVmName -Path $null
Remove-Item -Force $iso

$credentials = Join-Path $InstallRoot "CREDENTIALS.txt"
if (-not $MigrateFrom) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $text = & ssh.exe -i $keyFile -o BatchMode=yes -o "UserKnownHostsFile=$knownHosts" "sbomadmin@$address" "sudo cat /opt/sbom-platform/CREDENTIALS.txt" 2>$null
    $ErrorActionPreference = $previous
    if ($text) { ($text -join "`r`n").Replace("http://localhost:8080", $(if ($PublicUrl) { $PublicUrl } else { $inner })) | Out-File $credentials -Encoding ascii }
}

Write-Host ""
Write-Ok "SBOM Platform is installed and running."
Write-Host ""
if ($useNat) {
    Write-Host "  Open            $PublicUrl   (from other machines)"
    Write-Host "                  $inner   (from this server)"
}
else { Write-Host "  Open            $inner" }
if (Test-Path $credentials) { Write-Host "  Sign in         see $credentials (delete it once stored)" }
if ($MigrateFrom) {
    Write-Host "  Sign in         as before: the data and accounts of $MigrateFrom were moved."
    Write-Note "The Docker Desktop installation is still running and unchanged. Once this one is checked,"
    Write-Note "stop it in $MigrateFrom with: docker compose stop   (keep its data until you are sure)"
}
Write-Host "  Upgrade         upgrade-windows.cmd from a newer bundle"
Write-Host "  Machine         Hyper-V Manager: $SbomVmName (starts with this server)"
Write-Host "  Shell           ssh -i $keyFile sbomadmin@$address"
Write-Host "  Backups         nightly inside the machine, /var/backups/sbom-platform"
Write-Host ""
