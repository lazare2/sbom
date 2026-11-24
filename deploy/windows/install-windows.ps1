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

    Brought along: the database, the stored SBOMs, .env, PUBLIC_URL (so an https:// address and
    its HTTPS-only sign-in cookies stay), and what the installation added itself: its
    docker-compose.override.yml, the host files it mounts (an HTTPS certificate and key, a proxy
    configuration - also from outside the folder, e.g. C:\sbom-tls), the ports it published
    (443 ...) and the images it uses that are not the platform's; plus its own certificates
    in ca\. In the machine they are in /opt/sbom-platform (mounted files under migrated/).

.PARAMETER Resume
    Continues after "Not enough memory" or another failure to start the new machine: everything
    else is already prepared. Free memory first (Docker Desktop holds several GB; once the data
    copy is done it can be quit), or ask for less: .\install-windows.cmd -Resume -MemoryGB 6
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
    [string]$MigrateProject = "sbom-platform",
    # More ports of this server to forward to the same port in the machine, e.g. 443 for HTTPS.
    # A move adds the ports the old installation's docker-compose.override.yml published.
    [int[]]$ExtraPorts = @(),
    # Continue an installation whose machine was created but could not start (for example for
    # lack of memory): sets -MemoryGB and -Cpu on it and starts it. Nothing is copied again.
    [switch]$Resume
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$bundle = Split-Path $here -Parent
. (Join-Path $here "common.ps1")

$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
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
$existing = Get-VM -Name $SbomVmName -ErrorAction SilentlyContinue
if ($Resume) {
    if (-not $existing) { Stop-WithError "-Resume: there is no machine named $SbomVmName to continue. Run without -Resume." }
    if ($existing.State -ne "Off") {
        Stop-WithError "-Resume: $SbomVmName is $($existing.State), not Off. If it is installed and running, use upgrade-windows.cmd for changes."
    }
}
elseif ($existing) {
    Stop-WithError "A virtual machine named $SbomVmName exists already. To upgrade it use upgrade-windows.cmd; if a first install stopped before it started, use -Resume."
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

# The installation being moved: what it added itself, and the address people used. Read now, so
# a port it needs that is still taken stops the install before anything is copied or created.
$overrideInfo = $null
if ($MigrateFrom -and -not $Resume) {
    $oldEnv = Join-Path $MigrateFrom ".env"
    if (-not (Test-Path $oldEnv)) { Stop-WithError "$oldEnv not found. -MigrateFrom is the folder holding the installation's .env." }
    $oldOverride = Join-Path $MigrateFrom "docker-compose.override.yml"
    if (Test-Path $oldOverride) {
        $overrideInfo = Get-OverrideMigration -Path $oldOverride -Root $MigrateFrom
        $ExtraPorts = @($ExtraPorts) + @($overrideInfo.Ports)
        foreach ($f in @($overrideInfo.Files | Where-Object Missing)) {
            Write-Note "!! The old docker-compose.override.yml mounts $($f.Source), which does not exist; it is left out."
        }
    }
    # Kept, so links and the HTTPS-only sign-in cookies of an https:// address stay right.
    if ([string]::IsNullOrEmpty($PublicUrl)) {
        $old = Select-String -Path $oldEnv -Pattern '^PUBLIC_URL=(.+)$' | Select-Object -First 1
        if ($old) {
            $value = $old.Matches[0].Groups[1].Value.Trim().Trim('"').Trim("'")
            if ($value -match '^https?://' -and $value -notmatch '^https?://(localhost|127\.0\.0\.1)([:/]|$)') { $PublicUrl = $value }
        }
    }
}
$ExtraPorts = @($ExtraPorts | Where-Object { $_ -and $_ -ne $Port } | Sort-Object -Unique)

if ($useNat -and -not $Resume) {
    foreach ($p in $ExtraPorts) {
        if (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue) {
            Stop-WithError "Port $p is in use on this server. If it is the old installation's web front end, run 'docker compose stop web api' in $MigrateFrom (the database stays up for the copy), then run this again."
        }
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
# A new machine has new host keys; an entry from an earlier one would make SSH refuse it.
if (Test-Path $knownHosts) { Remove-Item -Force $knownHosts }
if (-not (Test-Path $keyFile)) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & ssh-keygen.exe -q -t ed25519 -N '""' -C "sbom-platform-host" -f $keyFile 2>&1 | Out-Null
    if (-not (Test-Path $keyFile)) { & ssh-keygen.exe -q -t ed25519 -N "" -C "sbom-platform-host" -f $keyFile 2>&1 | Out-Null }
    $ErrorActionPreference = $previous
    if (-not (Test-Path $keyFile)) { Stop-WithError "Could not create the SSH key." }
}
$publicKey = (Get-Content "$keyFile.pub" -Raw).Trim()

# Everything from here to the machine's creation is skipped by -Resume, which continues with
# what an earlier run prepared. (Not indented: the here-strings below must start at column 0.)
if (-not $Resume) {

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
        # Docker never reads or writes $InstallRoot: Docker Desktop runs as the signed-in user,
        # and the folder is for Administrators only. Files are made inside Docker and fetched
        # with docker cp, which writes as this Administrator.
        & docker exec $db pg_dump -U sbom -Fc sbom -f /tmp/sbom-migrate.dump
        if ($LASTEXITCODE -ne 0) { Stop-WithError "pg_dump failed in $db." }
        $entries = (& docker exec $db pg_restore -l /tmp/sbom-migrate.dump | Measure-Object -Line).Lines
        if ($entries -le 10) {
            & docker exec $db rm -f /tmp/sbom-migrate.dump
            Stop-WithError "The database copy could not be read back ($entries entries)."
        }
        & docker cp "$($db):/tmp/sbom-migrate.dump" (Join-Path $migrate "sbom.dump") | Out-Null
        $copied = $LASTEXITCODE
        & docker exec $db rm -f /tmp/sbom-migrate.dump
        if ($copied -ne 0 -or -not (Test-Path (Join-Path $migrate "sbom.dump"))) { Stop-WithError "Copying the database out of $db failed." }
        # The stored SBOMs, packed in a throwaway container that sees the volume read-only.
        $packer = "sbom-migrate-blobs"
        & docker rm -f $packer *> $null
        & docker run --name $packer -v "$($MigrateProject)_sbom-blobs:/data:ro" --entrypoint tar postgres:16-alpine czf /tmp/sbom-blobs.tar.gz -C /data .
        if ($LASTEXITCODE -ne 0) { & docker rm -f $packer *> $null; Stop-WithError "Packing the stored SBOM files failed." }
        & docker cp "$($packer):/tmp/sbom-blobs.tar.gz" (Join-Path $migrate "sbom-blobs.tar.gz") | Out-Null
        $copied = $LASTEXITCODE
        & docker rm -f $packer *> $null
        if ($copied -ne 0 -or -not (Test-Path (Join-Path $migrate "sbom-blobs.tar.gz"))) { Stop-WithError "Copying the stored SBOM files out failed." }
    }
    finally { $ErrorActionPreference = $previous }
    Copy-Item $envFile (Join-Path $migrate "env.txt")
    Write-Note ("database {0:N0} MB ({1} entries), SBOM files {2:N0} MB" -f ((Get-Item (Join-Path $migrate "sbom.dump")).Length / 1MB), $entries, ((Get-Item (Join-Path $migrate "sbom-blobs.tar.gz")).Length / 1MB))

    # What the installation added itself; vm-firstboot.sh puts it in place in the machine.
    $extra = Join-Path $migrate "extra"
    $caFiles = @(Get-ChildItem (Join-Path $MigrateFrom "ca") -File -ErrorAction SilentlyContinue |
        Where-Object { @("README.md", ".gitkeep") -notcontains $_.Name })
    if ($overrideInfo -or $caFiles.Count -gt 0) { New-Item -ItemType Directory -Force -Path $extra | Out-Null }
    if ($overrideInfo) {
        [IO.File]::WriteAllText((Join-Path $extra "docker-compose.override.yml"), $overrideInfo.Text, (New-Object Text.UTF8Encoding $false))
        $mounted = @($overrideInfo.Files | Where-Object { -not $_.Missing })
        if ($mounted.Count -gt 0) {
            $dest = Join-Path $extra "migrated"
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
            foreach ($f in $mounted) { Copy-Item -LiteralPath $f.Source -Destination (Join-Path $dest $f.Name) -Recurse }
        }
        # Images the override names that the bundle does not carry (a proxy, for instance): the
        # machine may not be allowed to download them, so they travel on the disc.
        $own = @(Get-Content (Join-Path $bundle "images.txt") -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() })
        $foreign = @($overrideInfo.Images | Where-Object { $own -notcontains $_ })
        if ($foreign.Count -gt 0) {
            $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
            & docker save -o (Join-Path $extra "images.tar") @foreign
            $saved = $LASTEXITCODE
            $ErrorActionPreference = $previous
            if ($saved -ne 0) { Stop-WithError "Could not save the image(s) the old override uses ($($foreign -join ', ')) from Docker Desktop." }
        }
        Write-Note ("its own setup: docker-compose.override.yml, {0} mounted file(s){1}{2}" -f $mounted.Count,
            $(if ($ExtraPorts.Count -gt 0) { ", port(s) $($ExtraPorts -join ', ')" } else { "" }),
            $(if ($foreign.Count -gt 0) { ", image(s) $($foreign -join ', ')" } else { "" }))
    }
    if ($caFiles.Count -gt 0) {
        New-Item -ItemType Directory -Force -Path (Join-Path $extra "ca") | Out-Null
        $caFiles | ForEach-Object { Copy-Item $_.FullName (Join-Path $extra "ca") }
        Write-Note "its own CA certificates: $($caFiles.Count)"
    }
    if ($PublicUrl -match '^https://') { Write-Note "address kept: $PublicUrl" }
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
Remove-FolderSafely $stage
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
    foreach ($p in $ExtraPorts) {
        Add-NetNatStaticMapping -NatName $SbomNatName -Protocol TCP -ExternalIPAddress "0.0.0.0" -ExternalPort $p -InternalIPAddress $vmAddress -InternalPort $p | Out-Null
        if (-not (Get-NetFirewallRule -Name "SBOM-Platform-TCP-$p" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name "SBOM-Platform-TCP-$p" -DisplayName "SBOM Platform (TCP $p)" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow | Out-Null
        }
    }
    if ($ExtraPorts.Count -gt 0) { Write-Note "also forwarded: $($ExtraPorts -join ', ')" }
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
ExtraPorts=$($ExtraPorts -join ',')
"@ | Out-File (Join-Path $state "install.txt") -Encoding ascii

}
else {
    # -Resume: the disc, network and machine are there from the run that could not start it.
    $iso = Join-Path $vmDir "sbom-install.iso"
    if (-not (Test-Path $iso)) {
        Stop-WithError "-Resume: $iso is gone, so the first start has nothing to install from. Remove $SbomVmName in Hyper-V Manager, then run without -Resume."
    }
    foreach ($line in @(Get-Content (Join-Path $state "install.txt") -ErrorAction SilentlyContinue)) {
        if ($line -match '^PublicUrl=(.*)$') { $PublicUrl = $Matches[1] }
        if ($line -match '^ExtraPorts=(.+)$') { $ExtraPorts = @($Matches[1].Split(",") | ForEach-Object { [int]$_ }) }
    }
    Set-VMMemory -VMName $SbomVmName -StartupBytes ([int64]$MemoryGB * 1GB)
    Set-VMProcessor -VMName $SbomVmName -Count $Cpu
    Write-Step "Continuing the installation of $SbomVmName ($Cpu CPUs, $MemoryGB GB memory)"
}

# Hyper-V needs the machine's whole memory free at start. Checked here, with what to do, rather
# than leaving Start-VM to fail after everything else is in place.
$availableGB = [math]::Round((Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory).AvailableMBytes / 1024, 1)
$resumeHint = "Everything else is ready; nothing has to be redone. Free memory (Docker Desktop holds several GB, and once the data copy is done it can be quit: whale icon > Quit), or ask for less, then continue with:  .\install-windows.cmd -Resume -MemoryGB $MemoryGB"
if ($availableGB -lt $MemoryGB) {
    Stop-WithError "Only $availableGB GB of memory is available; the machine needs $MemoryGB GB. $resumeHint"
}

Write-Step "Starting it. The first start installs the platform: 5 to 15 minutes."
try { Start-VM -Name $SbomVmName }
catch { Stop-WithError "The machine did not start: $($_.Exception.Message) $resumeHint" }

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
if ($ExtraPorts.Count -gt 0) {
    Write-Host "  Also forwarded  port(s) $($ExtraPorts -join ', ') to the machine"
    Write-Note "Files the moved setup mounts (an HTTPS certificate, for instance) are in the machine in"
    Write-Note "/opt/sbom-platform/migrated - renew a certificate there, then: sudo systemctl restart sbom-platform"
}
Write-Host "  Upgrade         upgrade-windows.cmd from a newer bundle"
Write-Host "  Machine         Hyper-V Manager: $SbomVmName (starts with this server)"
Write-Host "  Shell           ssh -i $keyFile sbomadmin@$address"
Write-Host "  Backups         nightly inside the machine, /var/backups/sbom-platform"
Write-Host ""
