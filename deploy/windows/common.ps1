# Shared by install-windows.ps1 and upgrade-windows.ps1. Dot-sourced, not run.
# ASCII only: Windows PowerShell 5.1 reads a BOM-less file in the ANSI code page.

function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }
function Write-Ok { param([string]$Text) Write-Host $Text -ForegroundColor Green }
function Stop-WithError { param([string]$Text) Write-Host $Text -ForegroundColor Red; exit 1 }

# Where the installation keeps its state on the Windows host. Readable by Administrators only:
# it holds the SSH key that opens the virtual machine.
$SbomVmName = "SBOM-Platform"
$SbomSwitchName = "SBOM-Platform-NAT"
$SbomNatName = "SBOM-Platform-NAT"

function Get-SbomStateDir {
    param([string]$Root)
    $dir = Join-Path $Root "state"
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    return $dir
}

<#
    Writes an ISO 9660 + Joliet image of a folder, with Windows' own IMAPI2 (no admin rights,
    nothing to install). The virtual machine reads it as a CD: cloud-init finds its settings
    on a disc labelled "cidata", and the platform bundle travels on the same disc.
#>
function New-IsoFromFolder {
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$IsoPath, [string]$Label = "cidata")
    if (-not ("SbomIsoWriter" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
public static class SbomIsoWriter {
    public static void Save(object stream, string path) {
        IStream s = (IStream)stream;
        byte[] buffer = new byte[1 << 20];
        IntPtr readPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(4);
        try {
            using (FileStream fs = File.Create(path)) {
                while (true) {
                    s.Read(buffer, buffer.Length, readPtr);
                    int read = System.Runtime.InteropServices.Marshal.ReadInt32(readPtr);
                    if (read <= 0) break;
                    fs.Write(buffer, 0, read);
                }
            }
        } finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(readPtr); }
    }
}
"@
    }
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.FileSystemsToCreate = 3          # ISO 9660 + Joliet: Joliet keeps names like user-data
    $image.VolumeName = $Label
    # The default limit is a CD's 700 MB; the bundle is bigger. 4 GB of 2 KB blocks.
    $image.FreeMediaBlocks = 2097152
    $image.Root.AddTree((Resolve-Path $Folder).Path, $false)
    $result = $image.CreateResultImage()
    if (Test-Path $IsoPath) { Remove-Item -Force $IsoPath }
    $stream = $result.ImageStream
    try { [SbomIsoWriter]::Save($stream, $IsoPath) }
    finally {
        # IMAPI keeps every source file open until its objects are released; the staging folder
        # (which can hold a moved installation's secrets) could not be deleted otherwise.
        foreach ($o in @($stream, $result, $image)) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($o) }
        $stream = $null; $result = $null; $image = $null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
    }
}

# Deletes a folder, retrying while Windows still holds a file in it.
function Remove-FolderSafely {
    param([Parameter(Mandatory)][string]$Path)
    for ($i = 0; $i -lt 10 -and (Test-Path $Path); $i++) {
        try { Remove-Item -Recurse -Force $Path -ErrorAction Stop } catch { Start-Sleep -Seconds 2 }
    }
    if (Test-Path $Path) { Write-Host "Could not delete $Path; delete it by hand." -ForegroundColor Yellow }
}

# Runs a command in the virtual machine over SSH with the installation's own key.
function Invoke-VmCommand {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$KeyFile,
        [Parameter(Mandatory)][string]$Command,
        [string]$KnownHosts,
        [switch]$AllowFail
    )
    $sshArgs = @("-i", $KeyFile, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=$KnownHosts",
        "sbomadmin@$Address", $Command)
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { & ssh.exe @sshArgs 2>&1 | ForEach-Object { "$_" } | Write-Host; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $previous }
    if ($code -ne 0 -and -not $AllowFail) { throw "The command in the virtual machine failed (exit $code): $Command" }
    return $code
}

# Waits until the platform answers on its health endpoint.
function Wait-PlatformHealthy {
    param([Parameter(Mandatory)][string]$Url, [int]$Minutes = 20)
    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline) {
        try {
            # Direct, never through the server's proxy: the machine is on a private network.
            $request = [Net.WebRequest]::Create("$Url/health")
            $request.Proxy = $null
            $request.Timeout = 5000
            $response = $request.GetResponse()
            $ok = [int]$response.StatusCode -eq 200
            $response.Close()
            if ($ok) { return $true }
        }
        catch { }
        Start-Sleep -Seconds 5
    }
    return $false
}
