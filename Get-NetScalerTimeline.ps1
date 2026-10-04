# Get-NetScalerTimeline
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-10-04
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
#
# DuckDB CLI v1.5.6 (2026-09-28)
# https://duckdb.org/install/?platform=windows&environment=cli
#
# The Sleuth Kit v4.14.0 (2025-04-15)
# https://www.sleuthkit.org/sleuthkit/download.php
#
# Strawberry Perl v5.42.3.1 (2026-08-17)
# https://strawberryperl.com/
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
#
# Changelog:
# Version 0.1
# Release Date: 2026-10-04
# Initial Release
#
#
# Tested on Windows 11 Pro (x64) Version 26H2 (10.0.26300.9457) and PowerShell 5.1.26100.9444
# Tested on Windows 11 Pro (x64) Version 26H2 (10.0.26300.9457) and PowerShell 7.6.6
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Get-NetScalerTimeline v0.1 - Automated File System Timeline Creation for NetScaler ADC/Gateway (DFIR)

.DESCRIPTION
  Get-NetScalerTimeline.ps1 is a PowerShell script utilized to simplify the creation of a File System Timeline of a NetScaler VMDK Disk Image (UFS).

  Timeline Analysis is a digital forensics process that extracts file metadata and sorts time-based events in chronological order to reconstruct a security incident.

  The FreeBSD Slice (0xa5) and all UFS partitions in its BSD Disk Label (e.g. /flash and /var) are detected automatically.

  The NetScaler logs (ns.log, httpaccess*.log, httperror*.log) are extracted and checked for log poisoning (CVE-2026-88771).

  Optionally, MD5 and SHA256 file hashes can be calculated for IOC matching (e.g. VirusTotal, Threat Intelligence Reports).

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\Get-NetScalerTimeline".

  Note: The subdirectory 'Get-NetScalerTimeline' is automatically created.

.PARAMETER Path
  Optional. Specifies the path to the VMDK. Either the flat extent (*-flat.vmdk) or the descriptor file (*.vmdk) of a flat/VMFS disk. If omitted, a file dialog opens.

.PARAMETER Hash
  Optional. Calculates the MD5 and SHA256 hashes of all allocated regular files and adds them to DuckDB (table NetScaler, columns MD5 and SHA256).

  The file content is read directly from the image (icat) and hashed in memory, no files are extracted. Deleted files are not hashed, because their data blocks may already be reallocated.

  Note: Each file is read by a separate icat process. This can take 15-20 minutes for a typical NetScaler disk image.

.PARAMETER StartDate
  Optional. Only include events on or after this date (yyyy-MM-dd, UTC).

.PARAMETER EndDate
  Optional. Only include events on or before this date (yyyy-MM-dd, UTC).

.EXAMPLE
  PS> .\Get-NetScalerTimeline.ps1

.EXAMPLE
  PS> .\Get-NetScalerTimeline.ps1 -Path "$env:USERPROFILE\Desktop\NetScaler\VMDK\NetScaler-flat.vmdk"

.EXAMPLE
  PS> .\Get-NetScalerTimeline.ps1 -Path "$env:USERPROFILE\Desktop\NetScaler\VMDK\NetScaler-flat.vmdk" -Hash

.EXAMPLE
  PS> .\Get-NetScalerTimeline.ps1 -Path "$env:USERPROFILE\Desktop\NetScaler\VMDK\NetScaler-flat.vmdk" -StartDate 2026-09-01 -EndDate 2026-10-01

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region CmdletBinding

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [String]$Path,

    [Parameter(Mandatory = $false)]
    [String]$OutputDir,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [String]$StartDate,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [String]$EndDate,

    [Parameter(Mandatory = $false)]
    [Switch]$Hash
)

#endregion CmdletBinding

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\Get-NetScalerTimeline" # Default
}
else
{
    if ($OutputDir -cnotmatch '.+(?=\\)') 
    {
        Write-Host "[Error] You must provide a valid directory path." -ForegroundColor Red
        Exit
    }
    else
    {
        $script:OUTPUT_FOLDER = "$OutputDir\Get-NetScalerTimeline" # Custom
    }
}

# Tools

# DuckDB CLI
$script:DuckDB = "$SCRIPT_DIR\Tools\DuckDB\duckdb.exe"

# The Sleuth Kit (TSK)
$script:fls     = "C:\Tools\sleuthkit\bin\fls.exe"
$script:fsstat  = "C:\Tools\sleuthkit\bin\fsstat.exe"
$script:icat    = "C:\Tools\sleuthkit\bin\icat.exe"
$script:mactime = "C:\Tools\sleuthkit\bin\mactime.pl"
$script:mmls    = "C:\Tools\sleuthkit\bin\mmls.exe"
$script:perl    = "C:\Strawberry\perl\bin\perl.exe"

# Import Functions
$FilePath = "$SCRIPT_DIR\Functions"
if (Test-Path "$FilePath")
{
    if (Test-Path "$FilePath\*.ps1") 
    {
        Get-ChildItem -Path "$FilePath" -Filter *.ps1 | ForEach-Object { . $_.FullName }
    }
}

# System.Drawing is required for the [System.Drawing.Color] cast below (Windows PowerShell does not load it by default)
Add-Type -AssemblyName System.Drawing

# Configuration File (JSON)
if(!(Test-Path "$PSScriptRoot\Config.json"))
{
    Write-Host "[Error] Config.json NOT found." -ForegroundColor Red
    Exit
}
else
{
    $Config = Get-Content "$PSScriptRoot\Config.json" | ConvertFrom-Json

    # BackgroundColor
    if ($Config.ImportExcel.BackgroundColor)
    {
        if ($Config.ImportExcel.BackgroundColor -cnotmatch '^(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5]))$') # <0-255>,<0-255>,<0-255>
        {
            Write-Host "[Error] You must provide a valid RGB Color Code." -ForegroundColor Red
            Exit
        }
    }

    # Excel - Color Scheme
    $script:BackgroundColor = [System.Drawing.Color]$Config.ImportExcel.BackgroundColor
    $script:FontColor       = $Config.ImportExcel.FontColor
}

# Invoke-TSK - Runs a native tool and writes its stdout byte-for-byte to a file.
# PowerShell's '>' operator decodes and re-encodes native output (UTF-16LE in Windows PowerShell 5.1), which corrupts bodyfiles for mactime.pl and mangles non-ASCII file names.
Function Invoke-TSK
{
    Param(
        [Parameter(Mandatory = $true)]
        [String]$FilePath,

        [Parameter(Mandatory = $true)]
        [String[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [String]$OutFile,

        [Parameter(Mandatory = $false)]
        [String]$WorkingDirectory
    )

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName               = $FilePath
    $ProcessInfo.Arguments              = ($ArgumentList | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $ProcessInfo.UseShellExecute        = $false
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError  = $true
    $ProcessInfo.CreateNoWindow         = $true
    $ProcessInfo.EnvironmentVariables["TZ"] = "UTC" # fsstat has no -z option and would print local time w/ a localized time zone name otherwise
    if ($WorkingDirectory) { $ProcessInfo.WorkingDirectory = $WorkingDirectory }

    try
    {
        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
    }
    catch
    {
        return [PSCustomObject]@{
            ExitCode = -1
            StdErr   = "Failed to start $($FilePath): $($_.Exception.InnerException.Message)"
        }
    }

    $StdErr = $Process.StandardError.ReadToEndAsync() # Read stderr asynchronously to prevent a deadlock
    $FileStream = [System.IO.File]::Create($OutFile)
    try
    {
        $Process.StandardOutput.BaseStream.CopyTo($FileStream)
    }
    finally
    {
        $FileStream.Close()
    }
    $Process.WaitForExit()

    [PSCustomObject]@{
        ExitCode = $Process.ExitCode
        StdErr   = $StdErr.Result
    }
}

# Get-TSKFileHash - Streams the content of a file (icat) and calculates MD5 and SHA256 in one pass (no temporary file)
Function Get-TSKFileHash
{
    Param(
        [Parameter(Mandatory = $true)]
        [String[]]$ArgumentList
    )

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName               = $icat
    $ProcessInfo.Arguments              = ($ArgumentList | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $ProcessInfo.UseShellExecute        = $false
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError  = $true
    $ProcessInfo.CreateNoWindow         = $true

    $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
    $StdErr  = $Process.StandardError.ReadToEndAsync() # Read stderr asynchronously to prevent a deadlock
    $Md5     = [System.Security.Cryptography.MD5]::Create()
    $Sha256  = [System.Security.Cryptography.SHA256]::Create()
    $Buffer  = New-Object byte[] 1048576
    $Stream  = $Process.StandardOutput.BaseStream

    try
    {
        while (($Read = $Stream.Read($Buffer, 0, $Buffer.Length)) -gt 0)
        {
            [void]$Md5.TransformBlock($Buffer, 0, $Read, $null, 0)
            [void]$Sha256.TransformBlock($Buffer, 0, $Read, $null, 0)
        }
        [void]$Md5.TransformFinalBlock($Buffer, 0, 0)
        [void]$Sha256.TransformFinalBlock($Buffer, 0, 0)
    }
    finally
    {
        $Process.WaitForExit()
    }

    if ($Process.ExitCode -ne 0)
    {
        return [PSCustomObject]@{ MD5 = $null; SHA256 = $null; Error = $StdErr.Result }
    }

    [PSCustomObject]@{
        MD5    = ([BitConverter]::ToString($Md5.Hash)    -replace '-', '').ToLower()
        SHA256 = ([BitConverter]::ToString($Sha256.Hash) -replace '-', '').ToLower()
        Error  = $null
    }
}

# Get-LineCount - Counts lines without loading the whole file into memory
Function Get-LineCount($File)
{
    $Count = 0
    foreach ($Line in [System.IO.File]::ReadLines($File)) { $Count++ }
    $Count
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Get-NetScalerTimeline v0.1 - Automated File System Timeline Creation for NetScaler ADC/Gateway (DFIR)"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if duckdb.exe exists
if (!(Test-Path "$($DuckDB)"))
{
    Write-Host "[Error] duckdb.exe NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if fls.exe exists
if (!(Test-Path "$($fls)"))
{
    Write-Host "[Error] fls.exe NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if fsstat.exe exists
if (!(Test-Path "$($fsstat)"))
{
    Write-Host "[Error] fsstat.exe NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if icat.exe exists
if (!(Test-Path "$($icat)"))
{
    Write-Host "[Error] icat.exe NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if mmls.exe exists
if (!(Test-Path "$($mmls)"))
{
    Write-Host "[Error] mmls.exe NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if mactime.pl exists
if (!(Test-Path "$($mactime)"))
{
    Write-Host "[Error] mactime.pl NOT found." -ForegroundColor Red
    Write-Host ""
    Exit
}

# Check if perl.exe exists (Strawberry Perl)
if (!(Test-Path "$($perl)"))
{
    Write-Host "[Error] perl.exe NOT found." -ForegroundColor Red
    Write-Host "[Info]  Check out: https://strawberryperl.com/"
    Write-Host ""
    Exit
}

# Check if PowerShell module 'ImportExcel' is installed
if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "[Error] Please install 'ImportExcel' PowerShell module." -ForegroundColor Red
    Write-Host "[Info]  Check out: https://github.com/dfinke/ImportExcel"
    Exit
}

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

# Select VMDK Disk Image (RAW)
if(!($Path))
{
    Function Get-DiskImage($InitialDirectory)
    {
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Virtual Machine Disk|*.vmdk|All Files (*.*)|*.*"
        $OpenFileDialog.Multiselect = $false
        if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
        {
            $OpenFileDialog.FileName
        }
    }

    $Result = Get-DiskImage

    if($Result)
    {
        $script:DiskImage = $Result
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    $script:DiskImage = $Path
}

# Interactive mode (no -Path): Ask for optional File Hashing
if (!($Path) -and !($Hash))
{
    $Answer = [System.Windows.Forms.MessageBox]::Show(
        "Calculate MD5 and SHA256 hashes of all allocated files?`n`nThis can take 15-20 minutes for a typical NetScaler disk image.",
        "Get-NetScalerTimeline.ps1 - File Hashing",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($Answer -eq [System.Windows.Forms.DialogResult]::Yes)
    {
        $Hash = [Switch]::Present
    }
}

# Flush Output Directory
if (Test-Path "$OUTPUT_FOLDER")
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else 
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER\Transcript.txt"

# Get Start Time
$script:StartTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "Get-NetScalerTimeline v0.1 - Automated File System Timeline Creation for NetScaler ADC/Gateway (DFIR)"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Exit Helper
Function Stop-Analysis($Message)
{
    Write-Host "[Error] $Message" -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Input-Check
if (!(Test-Path -LiteralPath "$DiskImage" -PathType Leaf))
{
    Stop-Analysis "$DiskImage does not exist."
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($DiskImage)
if (!($Extension -eq ".vmdk" ))
{
    Stop-Analysis "No VMDK Disk Image provided."
}

# Descriptor File (.vmdk) vs. Flat Extent (*-flat.vmdk)
# Note: The Descriptor File is a small text file (~1KB) starting with '# Disk DescriptorFile' that references the extent(s) holding the actual data.
$DiskImageItem = Get-Item -LiteralPath "$DiskImage"
$IsDescriptor = $false
if ($DiskImageItem.Length -lt 1MB)
{
    $FirstLine = Get-Content -LiteralPath "$DiskImage" -TotalCount 1 -ErrorAction SilentlyContinue
    if ($FirstLine -match '^# Disk DescriptorFile')
    {
        $IsDescriptor = $true
    }
}

$script:ImageFiles = @()
if ($IsDescriptor)
{
    Write-Output "[Info]  VMDK Descriptor File detected ($($DiskImageItem.Name))"
    $Descriptor = Get-Content -LiteralPath "$DiskImage"

    # createType (e.g. vmfs, monolithicFlat, twoGbMaxExtentFlat)
    $CreateType = $Descriptor | Where-Object { $_ -match '^createType="(.+)"' } | ForEach-Object { $Matches[1] } | Select-Object -First 1
    Write-Output "[Info]  Create Type: $CreateType"

    # Snapshot (Delta Disk)
    $ParentCID = $Descriptor | Where-Object { $_ -match '^parentCID=(\w+)' } | ForEach-Object { $Matches[1] } | Select-Object -First 1
    if ($ParentCID -and $ParentCID -ne "ffffffff")
    {
        Write-Host "[Alert] Snapshot (Delta Disk) detected. The data of the parent disk is NOT included." -ForegroundColor Yellow
    }

    # Extent Description: <Access> <Size in Sectors> <Type> "<FileName>"
    foreach ($Line in $Descriptor)
    {
        if ($Line -match '^(RW|RDONLY|NOACCESS)\s+\d+\s+(\w+)\s+"(.+?)"')
        {
            $ExtentType = $Matches[2]
            $ExtentFile = $Matches[3]

            if ($ExtentType -notin @("FLAT","VMFS"))
            {
                Stop-Analysis "Sparse Extent ($ExtentType) is not supported. Please convert the VMDK to RAW first (e.g. qemu-img convert -O raw)."
            }

            $ExtentPath = Join-Path $DiskImageItem.DirectoryName $ExtentFile
            if (!(Test-Path -LiteralPath "$ExtentPath" -PathType Leaf))
            {
                Stop-Analysis "Extent NOT found: $ExtentPath"
            }

            $script:ImageFiles += $ExtentPath
        }
    }

    if ($ImageFiles.Count -eq 0)
    {
        Stop-Analysis "No extent found in VMDK Descriptor File."
    }
}
else
{
    $script:ImageFiles = @($DiskImageItem.FullName)
}

# FileName
$FileName = [IO.Path]::GetFileName($ImageFiles[0])
Write-Output "[Info]  Creating File System Timeline ($FileName) ..."
New-Item "$OUTPUT_FOLDER\Timeline" -ItemType Directory -Force | Out-Null
if ($ImageFiles.Count -gt 1)
{
    Write-Output "[Info]  Split Image: $($ImageFiles.Count) Extents"
}

# Input Size
$InputSize = Get-FileSize(($ImageFiles | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum)
Write-Output "[Info]  Total Input Size: $InputSize"

# Common TSK Arguments (RAW image, split extents are passed in order)
$ImageArgs  = @("-i", "raw")
$TargetArgs = $ImageFiles

# Filesystem Timelining w/ fls

# mmls (media management listing) - Display the partition layout of a volume system (partition table)
Write-Output "[Info]  Analyzing Partition Table ..."
New-Item "$OUTPUT_FOLDER\mmls" -ItemType Directory -Force | Out-Null
Invoke-TSK -FilePath $mmls -ArgumentList ($ImageArgs + $TargetArgs) -OutFile "$OUTPUT_FOLDER\mmls\mmls-all.txt" | Out-Null
Invoke-TSK -FilePath $mmls -ArgumentList ($ImageArgs + @("-a") + $TargetArgs) -OutFile "$OUTPUT_FOLDER\mmls\mmls-allocated.txt" | Out-Null

# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
#
#       Slot      Start        End          Length       Description
# 000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
# 001:  -------   0000000000   0000000062   0000000063   Unallocated
# 002:  000:000   0000000063   0041943005   0041942943   BSD/386, 386BSD, NetBSD, FreeBSD (0xa5)
# 003:  -------   0041943006   0041943039   0000000034   Unallocated

# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
#
#       Slot      Start        End          Length       Description
# 002:  000:000   0000000063   0041943005   0041942943   BSD/386, 386BSD, NetBSD, FreeBSD (0xa5)

# Cannot determine partition type
if (!(Test-Path "$OUTPUT_FOLDER\mmls\mmls-all.txt") -or (Get-Item "$OUTPUT_FOLDER\mmls\mmls-all.txt").Length -eq 0)
{
    Stop-Analysis "Cannot determine partition type."
}

# Check for FreeBSD Slice (0xa5) and get its Start Sector
$Slices = @()
foreach ($Line in Get-Content "$OUTPUT_FOLDER\mmls\mmls-allocated.txt")
{
    if ($Line -match '^\d{3}:\s+\d{3}:\d{3}\s+(\d+)\s+(\d+)\s+(\d+)\s+.*FreeBSD \(0xa5\)')
    {
        $Slices += [Int64]$Matches[1]
    }
}

if ($Slices.Count -eq 0)
{
    Stop-Analysis "No FreeBSD Slice (0xa5) found."
}

# BSD Disk Label
# Offset Sector: 63
# Units are in 512-byte sectors
#
#       Slot      Start        End          Length       Description
# 000:  000       0000000000   0003354623   0003354624   4.2BSD (0x07) --> /flash
# 001:  002       0000000000   0041942942   0041942943   Unused (0x00)
# 002:  Meta      0000000001   0000000001   0000000001   Partition Table
# 003:  001       0003354624   0011952127   0008597504   Swap (0x01)
# 004:  003       0011952128   0011956223   0000004096   4.2BSD (0x07)
# 005:  004       0011956224   0041942942   0029986719   4.2BSD (0x07) --> /var
# 006:  -------   0041942943   0041943039   0000000097   Unallocated
#
# Start sectors are relative to the slice: absolute offset = slice start (DOS partition) + Start (BSD label)
# 0 + 63 = 63 (/flash)
# 11956224 + 63 = 11956287 (/var)

New-Item "$OUTPUT_FOLDER\fsstat" -ItemType Directory -Force | Out-Null
$FileSystems = @()

foreach ($SliceStart in $Slices)
{
    Write-Output "[Info]  FreeBSD Slice (0xa5) found (Start Sector: $SliceStart)"

    # List BSD Disk Label
    $BsdLabel = "$OUTPUT_FOLDER\mmls\mmls-bsd-$SliceStart.txt"
    Invoke-TSK -FilePath $mmls -ArgumentList ($ImageArgs + @("-t", "bsd", "-o", "$SliceStart") + $TargetArgs) -OutFile $BsdLabel | Out-Null

    foreach ($Line in Get-Content $BsdLabel)
    {
        if ($Line -match '^\d{3}:\s+(\d{3})\s+(\d+)\s+(\d+)\s+(\d+)\s+4\.2BSD \(0x07\)')
        {
            $Letter = [char](97 + [int]$Matches[1]) # 000 = a, 001 = b, ...
            $Start  = [Int64]$Matches[2]

            # Modern FreeBSD labels are relative to the slice, old ones are absolute --> try both
            $Found = $false
            foreach ($Offset in @(($SliceStart + $Start), $Start) | Select-Object -Unique)
            {
                # fsstat - Displays the details associated with a file system (Filesystem Layer)
                $FsstatFile = "$OUTPUT_FOLDER\fsstat\fsstat-$Offset.txt"
                # Note: Variable names are case-insensitive --> do NOT use $Fsstat here (would overwrite $fsstat)
                Invoke-TSK -FilePath $fsstat -ArgumentList ($ImageArgs + @("-o", "$Offset") + $TargetArgs) -OutFile $FsstatFile | Out-Null
                $FsstatOutput = Get-Content $FsstatFile -Raw

                if ($FsstatOutput -match 'File System Type: (UFS \d)')
                {
                    $FsType     = $Matches[1]
                    $MountPoint = if ($FsstatOutput -match 'Last Mount Point:[ \t]*(\S+)') { $Matches[1] } else { "" }
                    $VolumeName = if ($FsstatOutput -match 'Volume Name:[ \t]*(\S+)') { $Matches[1] } else { "" }

                    if (!($MountPoint)) { $MountPoint = "/partition-$Letter" }

                    Write-Output "[Info]  Partition $($Letter): $FsType - $MountPoint ($VolumeName) (Offset: $Offset)"

                    $FileSystems += [PSCustomObject]@{
                        Letter     = $Letter
                        Offset     = $Offset
                        Type       = $FsType
                        MountPoint = $MountPoint
                        VolumeName = $VolumeName
                    }

                    $Found = $true
                    break
                }
                else
                {
                    Remove-Item $FsstatFile -Force
                }
            }

            if (!($Found))
            {
                Write-Output "[Info]  Partition $($Letter): No file system found (Offset: $($SliceStart + $Start))"
            }
        }
    }
}

if ($FileSystems.Count -eq 0)
{
    Stop-Analysis "No UFS file system found."
}

# fls - List file and directory names of volume
New-Item "$OUTPUT_FOLDER\fls" -ItemType Directory -Force | Out-Null

# Step #1 - Extract the filesystem bodyfile from forensic image (Filename Layer)
$Bodyfile = "$OUTPUT_FOLDER\fls\1-fls.body"
$Writer = [System.IO.File]::Create($Bodyfile)
try
{
    foreach ($FileSystem in $FileSystems)
    {
        # Mount Point as prefix (e.g. /flash/nsconfig/ns.conf, /var/log/httpaccess.log)
        $Name   = $FileSystem.MountPoint.Trim("/") -replace '[\\/:*?"<>|]', '_'
        if (!($Name)) { $Name = "root" }
        $Prefix = ($FileSystem.MountPoint.TrimEnd("/")) + "/"
        $Body   = "$OUTPUT_FOLDER\fls\1-fls_$Name.body"

        Write-Output "[Info]  Processing $($FileSystem.MountPoint) ..."
        $Result = Invoke-TSK -FilePath $fls -ArgumentList ($ImageArgs + @("-o", "$($FileSystem.Offset)", "-r", "-m", $Prefix) + $TargetArgs) -OutFile $Body

        if ($Result.StdErr)
        {
            $Result.StdErr | Out-File "$OUTPUT_FOLDER\fls\1-fls_$Name.err"
            Write-Host "[Alert] fls reported errors for $($FileSystem.MountPoint) (see 1-fls_$Name.err)" -ForegroundColor Yellow
        }

        $Count = Get-LineCount $Body
        Write-Output "[Info]  $($FileSystem.MountPoint): $('{0:N0}' -f $Count) entries"

        # Combined Bodyfile
        $Reader = [System.IO.File]::OpenRead($Body)
        try { $Reader.CopyTo($Writer) } finally { $Reader.Close() }
    }
}
finally
{
    $Writer.Close()
}

# Step #2 - Extract filesystem timeline in comma separated value format (ISO 8601, UTC)
$Timeline = "$OUTPUT_FOLDER\Timeline\2-mactime-timeline.csv"
$MactimeArgs = @($mactime, "-b", "fls\1-fls.body", "-d", "-y", "-z", "UTC") # Relative path: Perl's open() fails on paths > 260 characters

# Time Window (Date Range): yyyy-mm-dd..yyyy-mm-dd
if ($StartDate -or $EndDate)
{
    if (!($StartDate)) { $StartDate = "1970-01-01" }
    if (!($EndDate))   { $EndDate   = [datetime]::UtcNow.ToString("yyyy-MM-dd") }
    Write-Output "[Info]  Date Range: $StartDate - $EndDate (UTC)"
    # mactime's end date is exclusive --> add one day so that -EndDate is inclusive
    $MactimeEnd = ([datetime]::ParseExact($EndDate, "yyyy-MM-dd", $null)).AddDays(1).ToString("yyyy-MM-dd")
    $MactimeArgs += "$StartDate..$MactimeEnd"
}

Write-Output "[Info]  Creating Timeline w/ mactime ..."
$Result = Invoke-TSK -FilePath $perl -ArgumentList $MactimeArgs -OutFile $Timeline -WorkingDirectory "$OUTPUT_FOLDER"
if ($Result.StdErr)
{
    $Result.StdErr | Out-File "$OUTPUT_FOLDER\Timeline\2-mactime-timeline.err"
}

if (!(Test-Path "$Timeline") -or (Get-Item "$Timeline").Length -eq 0)
{
    Stop-Analysis "mactime failed. Check $OUTPUT_FOLDER\Timeline\2-mactime-timeline.err"
}

# Time Window of the Timeline (first/last event)
# Entries w/o any timestamp (e.g. $OrphanFiles) are listed as 0000-00-00T00:00:00Z
$Total   = 0
$Undated = 0
$First   = $null
$Last    = $null
foreach ($Line in [System.IO.File]::ReadLines($Timeline) | Select-Object -Skip 1)
{
    $Total++
    $Date = $Line.Substring(0, 20)
    if ($Date -like "0000-00-00*")
    {
        $Undated++
    }
    else
    {
        if (!($First)) { $First = $Date }
        $Last = $Date
    }
}

Write-Output "[Info]  $('{0:N0}' -f $Total) timeline entries"

if ($First)
{
    $FirstEvent = $First -replace 'T', ' ' -replace 'Z$', ' UTC'
    $LastEvent  = $Last  -replace 'T', ' ' -replace 'Z$', ' UTC'
    Write-Output "[Info]  Time Window: $FirstEvent - $LastEvent"
}

if ($Undated -gt 0)
{
    Write-Output "[Info]  $('{0:N0}' -f $Undated) entries w/o timestamp (e.g. Orphan Files)"
}

# File Size (CSV)
$Size = Get-FileSize((Get-Item "$Timeline").Length)
Write-Output "[Info]  File Size (CSV): $Size"

# XLSX
if ($Total -lt 1048576)
{
    Write-Output "[Info]  Creating XLSX ..."
    New-Item "$OUTPUT_FOLDER\Timeline" -ItemType Directory -Force | Out-Null
    $IMPORT = Import-Csv "$Timeline" -Delimiter ","
    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Timeline\NetScalerTimeline.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoFilter -WorkSheetName "Timeline" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $LastColumnLetter = $WorkSheet.Dimension.End.Address -replace '\d', ''
    Set-Format -Address $WorkSheet.Cells["A1:$($LastColumnLetter)1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # Column Width
    $WorkSheet.Column(1).Width = 22 # Date
    $WorkSheet.Column(2).Width = 12 # Size
    $WorkSheet.Column(3).Width = 8  # Type
    $WorkSheet.Column(4).Width = 14 # Mode
    $WorkSheet.Column(5).Width = 8  # UID
    $WorkSheet.Column(6).Width = 8  # GID
    $WorkSheet.Column(7).Width = 10 # Meta
    $WorkSheet.Column(8).Width = 120 # File Name
    # HorizontalAlignment "Center" of columns A-G
    $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
    }
    Remove-Variable IMPORT
    [System.GC]::Collect()
}
else
{
    Write-Host "[Alert] Timeline exceeds the Excel row limit (1,048,576). XLSX skipped. Use -StartDate/-EndDate or Timeline Explorer." -ForegroundColor Yellow
}

# Data Import
if (Test-Path "$SCRIPT_DIR\Queries\Bodyfile.sql")
{
    $Utf8Bodyfile = "$OUTPUT_FOLDER\fls\1-fls_utf8.body"
    $Converted = ConvertTo-Utf8Bodyfile -InFile "$OUTPUT_FOLDER\fls\1-fls.body" -OutFile $Utf8Bodyfile
    if ($Converted -gt 0)
    {
        Write-Host "[Alert] $('{0:N0}' -f $Converted) line(s) w/ non-UTF-8 file names (decoded as Latin-1)" -ForegroundColor Yellow
    }

    Write-Output "[Info]  Importing Data into DuckDB ..."
    New-Item "$OUTPUT_FOLDER\Timeline\DuckDB\Database" -ItemType Directory -Force | Out-Null
    $script:Database = "$OUTPUT_FOLDER\Timeline\DuckDB\Database\Bodyfile.duckdb"
    $env:BODYFILE = $Utf8Bodyfile
    & $DuckDB $Database -f "$SCRIPT_DIR\Queries\Bodyfile.sql"

    if ($LASTEXITCODE -ne 0)
    {
        Write-Host "[Error] DuckDB import failed." -ForegroundColor Red
    }
    else
    {
        # Total Records (w/ thousands separators)
        [int]$TotalRecords = (& $DuckDB $Database -noheader -csv -c "SELECT COUNT(*) FROM NetScaler")
        $Rows = '{0:N0}' -f $TotalRecords
        Write-Output "[Info]  Total Rows: $Rows"
    }
}

# Threat Hunting
# TODO

# Log Extraction --> Log Poisoning (CVE-2026-88771)
# pitboss.{0,100}PPE.{0,150}(unexpectedly died|missed too many heartbeats).{0,150}NSPPE.{0,50}(;|[$][(]|&&|[|][|])
if ($Database -and (Test-Path "$Database") -and (Test-Path "$SCRIPT_DIR\Queries\Logs.sql"))
{
    Write-Output "[Info]  Extracting Log Files ..."
    $LogDir = "$OUTPUT_FOLDER\Logs"
    New-Item "$LogDir\raw"  -ItemType Directory -Force | Out-Null
    New-Item "$LogDir\utf8" -ItemType Directory -Force | Out-Null

    # Current and rotated logs (e.g. ns.log, ns.log.0.gz). Only allocated files: data of deleted entries may be overwritten.
    $Query = "SELECT Path, Inode FROM NetScaler WHERE Status = 'Allocated' AND Type = 'Regular File' AND regexp_matches(Path, '^/var/log/(ns[.]log|http[a-z-]*[.]log)([.][0-9]+)?([.]gz)?$') ORDER BY Path"
    $LogFiles = & $DuckDB $Database -csv -c $Query | ConvertFrom-Csv

    foreach ($LogFile in $LogFiles)
    {
        # File system that contains the log (longest matching mount point)
        $FileSystem = $FileSystems | Where-Object { $LogFile.Path.StartsWith($_.MountPoint.TrimEnd("/") + "/") } | Sort-Object { $_.MountPoint.Length } -Descending | Select-Object -First 1
        if (!($FileSystem)) { continue }

        # icat - Output the contents of a file based on its inode number (byte-for-byte)
        $Name = [IO.Path]::GetFileName($LogFile.Path)
        $Raw  = "$LogDir\raw\$Name"
        $Result = Invoke-TSK -FilePath $icat -ArgumentList ($ImageArgs + @("-o", "$($FileSystem.Offset)") + $TargetArgs + @("$($LogFile.Inode)")) -OutFile $Raw
        if ($Result.StdErr)
        {
            Write-Host "[Alert] icat reported errors for $($LogFile.Path)" -ForegroundColor Yellow
        }

        # Decompress rotated logs (*.gz)
        $Plain = $Raw
        if ($Name -like "*.gz")
        {
            $Plain = "$LogDir\raw\$([IO.Path]::GetFileNameWithoutExtension($Name)).tmp"
            $In  = [IO.File]::OpenRead($Raw)
            $Gz  = New-Object IO.Compression.GZipStream($In, [IO.Compression.CompressionMode]::Decompress)
            $Out = [IO.File]::Create($Plain)
            try { $Gz.CopyTo($Out) } finally { $Out.Close(); $Gz.Close(); $In.Close() }
        }

        # Valid UTF-8 for DuckDB (attacker payloads may contain invalid bytes)
        $Utf8Name = $Name -replace '\.gz$', ''
        $Converted = ConvertTo-Utf8Bodyfile -InFile $Plain -OutFile "$LogDir\utf8\$Utf8Name"
        if ($Converted -gt 0)
        {
            Write-Host "[Alert] $Utf8Name`: $Converted line(s) w/ non-UTF-8 content (decoded as Latin-1)" -ForegroundColor Yellow
        }
        if ($Plain -ne $Raw) { Remove-Item $Plain -Force }
    }

    # Hashes of the extracted logs (evidence copies)
    Get-ChildItem "$LogDir\raw" -File | Get-FileHash -Algorithm SHA256 | Select-Object @{n='File';e={Split-Path $_.Path -Leaf}}, Hash | Export-Csv "$LogDir\SHA256.csv" -NoTypeInformation
    Write-Output "[Info]  $(@($LogFiles).Count) log file(s) extracted"

    # Import into DuckDB
    if (@($LogFiles).Count -gt 0)
    {
        $env:LOGFILES = "$LogDir\utf8\*"
        & $DuckDB $Database -f "$SCRIPT_DIR\Queries\Logs.sql"

        if ($LASTEXITCODE -eq 0)
        {
            [int]$Hits = (& $DuckDB $Database -noheader -csv -c "SELECT COUNT(*) FROM LogPoisoning")
            if ($Hits -gt 0)
            {
                Write-Host "[Alert] Log Poisoning: $Hits suspicious line(s) found (CVE-2026-88771) --> View: LogPoisoning" -ForegroundColor Red
            }
            else
            {
                Write-Output "[Info]  Log Poisoning: No suspicious lines found"
            }

            # Log Coverage per Log Type (oldest/newest log write)
            $CoverageQuery = "SELECT regexp_extract(Path, '^/var/log/([a-z-]+[.]log)', 1) AS Log, strftime(MIN(LastModificationTime), '%Y-%m-%d %H:%M:%S') AS Oldest, strftime(MAX(LastModificationTime), '%Y-%m-%d %H:%M:%S') AS Newest, COUNT(*) AS Files FROM NetScaler WHERE Status = 'Allocated' AND regexp_matches(Path, '^/var/log/(ns[.]log|http[a-z-]*[.]log)([.][0-9]+)?([.]gz)?$') GROUP BY ALL ORDER BY Log"
            $Coverage = & $DuckDB $Database -csv -c $CoverageQuery | ConvertFrom-Csv
            foreach ($Entry in $Coverage)
            {
                Write-Host "[Alert] Local $($Entry.Log) coverage: $($Entry.Oldest) UTC - $($Entry.Newest) UTC ($($Entry.Files) files)" -ForegroundColor Yellow
            }
        }
    }
}

# File Hashing (optional) --> MD5 + SHA256 of all allocated regular files
if ($Hash -and $Database -and (Test-Path "$Database") -and (Test-Path "$SCRIPT_DIR\Queries\Hashes.sql"))
{
    Write-Output "[Info]  Calculating File Hashes (MD5, SHA256) ..."
    New-Item "$OUTPUT_FOLDER\Hashes" -ItemType Directory -Force | Out-Null

    # File list via COPY (UTF-8) --> PowerShell would mangle non-ASCII paths when reading DuckDB's console output
    $FileList = "$OUTPUT_FOLDER\Hashes\FileList.csv"
    $SqlPath  = $FileList -replace "'", "''"
    & $DuckDB $Database -c "COPY (SELECT Path, Inode, Bytes FROM NetScaler WHERE Status = 'Allocated' AND Type = 'Regular File' AND NOT Orphan ORDER BY Path) TO '$SqlPath' (HEADER, DELIMITER ',')"
    $Files = Import-Csv $FileList -Encoding UTF8
    $Total = @($Files).Count
    Write-Output "[Info]  $('{0:N0}' -f $Total) allocated regular files"

    $Cache   = @{}   # Key: <Offset>:<Inode> --> hard links are hashed only once
    $Results = New-Object System.Collections.Generic.List[object]
    $Errors  = 0
    $i       = 0

    foreach ($File in $Files)
    {
        $i++
        if ($i % 250 -eq 0)
        {
            Write-Progress -Activity "Calculating File Hashes" -Status "$i / $Total" -PercentComplete ($i / $Total * 100)
        }

        # File system that contains the file (longest matching mount point)
        $FileSystem = $null
        foreach ($Fs in $FileSystems)
        {
            if ($File.Path.StartsWith($Fs.MountPoint.TrimEnd("/") + "/") -and (!$FileSystem -or $Fs.MountPoint.Length -gt $FileSystem.MountPoint.Length))
            {
                $FileSystem = $Fs
            }
        }
        if (!($FileSystem)) { continue }

        $Key = "$($FileSystem.Offset):$($File.Inode)"
        if (!($Cache.ContainsKey($Key)))
        {
            if ([Int64]$File.Bytes -eq 0)
            {
                # Empty file: well-known hashes, no need to start icat
                $Cache[$Key] = [PSCustomObject]@{ MD5 = "d41d8cd98f00b204e9800998ecf8427e"; SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; Error = $null }
            }
            else
            {
                $Cache[$Key] = Get-TSKFileHash -ArgumentList ($ImageArgs + @("-o", "$($FileSystem.Offset)") + $TargetArgs + @("$($File.Inode)"))
                if ($Cache[$Key].Error) { $Errors++ }
            }
        }

        $Results.Add([PSCustomObject]@{
            Path   = $File.Path
            Inode  = $File.Inode
            MD5    = $Cache[$Key].MD5
            SHA256 = $Cache[$Key].SHA256
        })
    }
    Write-Progress -Activity "Calculating File Hashes" -Completed

    $HashFile = "$OUTPUT_FOLDER\Hashes\FileHashes.csv"
    $Results | Export-Csv $HashFile -NoTypeInformation -Encoding UTF8
    if ($Errors -gt 0)
    {
        Write-Host "[Alert] $Errors file(s) could not be read by icat (MD5/SHA256 empty)" -ForegroundColor Yellow
    }

    # Import into DuckDB
    $env:HASHFILE = $HashFile
    & $DuckDB $Database -f "$SCRIPT_DIR\Queries\Hashes.sql"
    if ($LASTEXITCODE -eq 0)
    {
        Write-Output "[Info]  $('{0:N0}' -f $Cache.Count) unique files hashed --> NetScaler.MD5, NetScaler.SHA256"
    }
}

# Launching DuckDB UI (w/ Interactive Notebooks) --> http://localhost:4213/
if ($Database -and (Test-Path "$Database"))
{
    Start-Process -FilePath "$DuckDB" -ArgumentList "-ui", "$Database" -WindowStyle Minimized
}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$EndTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($EndTime-$StartTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 0.5

# MessageBox UI
$MessageBody = "Status: File System Timeline Creation completed.`n`nPress CTRL + D to shutdown DuckDB UI."
$MessageTitle = "Get-NetScalerTimeline.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    # Reset Windows Title
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIInawYJKoZIhvcNAQcCoIInXDCCJ1gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7tDKQWsV90B2NBc/+LkZwrEp
# 676ggiCkMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0B
# AQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0w
# KwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcN
# MjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBD
# b2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC
# AYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDI
# ArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0
# k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD
# 7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arW
# ZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZ
# QgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiW
# u01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35X
# Gf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn3Uay
# WW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF
# 5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0g
# BBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8v
# Y3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYu
# Y3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggr
# BgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQAD
# ggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8
# +Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPk
# KaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapa
# ndPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjF
# V3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATH
# vNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinL
# rYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB
# 0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenL
# bjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tb
# nio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85
# gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGazCCBNOgAwIB
# AgIRAIxBnpO/K86siAYoO3YZvTwwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMC
# R0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQ
# dWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yNDExMTQwMDAwMDBaFw0yNzEx
# MTQyMzU5NTlaMFcxCzAJBgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNoc2Vu
# MRcwFQYDVQQKDA5NYXJ0aW4gV2lsbGluZzEXMBUGA1UEAwwOTWFydGluIFdpbGxp
# bmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDRn27mnIzB6dsJFLMe
# xQQNRd8aMv73DTla68G6Q8u+V2TY1JQ/Z4j2oCI9ATW3K3P7NAPdlE0QmtdjC0F/
# 74jsfil/i8LwxuyT034wabViZKUcodmKsEFhM9am8W5kUgLuC5FIK4wNOq5TfzYd
# HTyJu1eR2XuSDoMp0wg45mOuFNBbYB8DVBtHxobvWq4eCs3lUxX07wR3Qr2Utb92
# w8eU2vKr2Ss9xIh/YvM4UxgBpO1I6O+W2tAB5mmynIgoCfX7mu6iD3A+AhpQ9Gv2
# 09G83y8FPrFJIWU77TTehErbPjZ074xXwrlEkhnGUCk1w+KiNtZHaSn0X+vnhqJ7
# otBxQZQAESlhWXpDKCunnnVnVgwvVWtccAhxZO95eif6Vss/UhCaBZ26szlneGtF
# eTClI4+k3mqfWuodtXjHc8ohAclWp7XVywliwhCFEsAcFkpkCyivey0sqEfrwiMn
# Ry1elH1S37XcQaav5+bt4KxtIXuOVEx3vM9MHdlraW0y1on5E8i4tagdI45TH0LU
# 080ubc2MKqq6ZXtplTu1wdF2Cgy3hfSSLkJscRWApvpvOO6Vtc4jTG/AO6iqN5M6
# Swd+g40XtsxBD/gSk9kMqkgJ1pD1Gp5gkHnP1veut+YgJ9xWcRDJI7vcis9qsXwt
# VybeOCh56rTQvC/Tf6BJtiieEQIDAQABo4IBszCCAa8wHwYDVR0jBBgwFoAUDyrL
# IIcouOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFIxyZAmEHl7uAfEwbB4nzI8MCCLb
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0
# dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6
# hjhodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmlu
# Z0NBUjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9j
# cnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0
# MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAoBgNVHREEITAf
# gR1td2lsbGluZ0BsZXRoYWwtZm9yZW5zaWNzLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AYEAZ0dBMMwluWGb+MD1rGWaPtaXrNZnlZqOZxgbdrMLBKAQr0QGcILCVIZ4SZYa
# evT5yMR6jFGSAjgaFtnk8ZpbtGwig/ed/C/D1Ne8SZyffdtALns/5CHxMnU8ks7u
# t7dsR6zFD4/bmljuoUoi55W6/XU/1pr+tqRaZGJvjSKJQCN9MhFAvXSpPPqRsj27
# ze1+KYIBF1/L0BW0HS0d9ZhGSUoEwqMDLpQf2eqJFyyyzWt21VVhLF6mgZ1dE5tC
# LZY7ERzx6/h5N7F0w361oigizMbCMdST29XOc5mB8q6Cye7OmEfM2jByRWa+cd4R
# ycsN2p2wHRukpq48iX+tPVKmHwNKf+upuKPDQAeV4J7gUCtevIsOtoyiC2+amimu
# 81o424Dl+NsAyCLz0SXvNAhVvtU73H61gtoPa/SWouem2S+bzp7oGvGPop/9mh4C
# Xki6LVeDH3hDM8hZsJg/EToIWiDozTc2yWqwV4Ozyd4x5Ix8lckXMgWuyWcxmLK1
# RmKpMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwF
# ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcT
# C0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAs
# BgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcN
# MjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizI
# CFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ
# 2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2G
# AXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WA
# BKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/F
# DDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop0
# 6m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE
# 9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj
# 3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoq
# zEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7
# jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYw
# ggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2
# d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYD
# VR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVz
# dFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAl
# BggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARa
# AdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsD
# LRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxV
# f7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJ
# yz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGin
# CwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp
# 4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/U
# YOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SB
# IkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14su
# VFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HH
# FHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wgganMIIE
# j6ADAgECAhEAkKwIciD9xafEa1zHDfc9BjANBgkqhkiG9w0BAQwFADBXMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0
# aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTI2MDMyNTAwMDAw
# MFoXDTQxMDMyNDIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGlu
# ZyBDQSBSNDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu5EqiAa2C
# HGL5Zi1bmgPM8NUXwYZJ+BtQqHps43GLTC+sjVLypsBh+8uv+TLkgtVGD//vSmA0
# qrzELf9YRCh2MTAA/aGaQZKGg0BRCmziR3pbCnvgWjtGXBDUyn3j3K2lZAO8KxgF
# tlxwOYEAkL+CCqK4v9zzTl8ZwzDpPMiDIFa5THk8an1ieF5I09cXNrPQw+1ER1li
# ThaG0z6FrOpqwxZWmPRZQBw2E32878UB1bL0Zp91vuWZgsMpNNiPCoBj0/1F+LE8
# +NRokfqacFI0F2tftrRB2W7HQClLR9zjxFbWb5be2rceIfNyHUUfKGIvMI2NzoxS
# lxXnFqUG887D8W1Cj8DFok688JKxWvHR/9aQykSbd+9Vutj36ij2sgq/125wTpUZ
# /AgC0ph50bRs7gFrUyaXE9wSsOqMvCCC+sEm7vd/BemSG0TSHNXSmyCba+FCzeke
# WX03TRIcF3Laqd0Rw24OH7jpei4zaGhcI7nfdhBA4c8RScxNY6jeHLHHmSMMTk9W
# qn7H4dLhUBP5YEwbgbN4uv1i9ltTnHli8t1xHV0StX9BFgrnmunTX19kUXY1H5OR
# JbRZyZDdvm1oZyteDj0SnMozr+YSmdIleDUTXdfoY7b2taz8s2+QbOxLxcahEIYG
# Wzqu6h955tKwcANHcZ4gTmAhT3btuOiQsQIDAQABo4IBbjCCAWowHwYDVR0jBBgw
# FoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFDp0pQxnxkJQwv21/Me7
# KTSC9Hq5MA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMCMGA1UdIAQcMBowCAYGZ4EMAQQCMA4GDCsGAQQBsjEB
# AgEDCDBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1Nl
# Y3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRw
# MG4wRwYIKwYBBQUHMAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8v
# b2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMt5SR2bxngNm+N8o
# c6Gq76Gx1c235fkX7jw8Ho9MAkJGADerHE7dhsBXttqmzgr/7ZZahZSykGRPhPY1
# crj028kB8KzO0dKC2qQBAwtfgqMLKkkX/6bYq2uT33eD6ByAp2/XKD0LcmZh0kKe
# cvSBr6ln9ajX6u1dnx2fA7xEKy1M3qBhfQSUWLtjs2nFt0ELVLptzTlX9ID0cL+i
# OPfdboZ3CelT+JXKVKR2Sge0d4YiFAtPZkfSo8z1Z1x7y/Z9mwMIlBAnyuWXs4Ys
# NuxdrYIt/QxE31PDOJ9DesS4Bc7H9OTORlEV/AvfiF/VepKZpira1MzLYuCw+uoL
# Zn/pkpvd+CvNTS+mEHjBJNa6WK1j8qXFu+jIq+sG9QILHiyB6p/xpHrkJu8zkw39
# 3+VqF9eKlTY2VjRxdycZLrVemZ4Yp3wi33b+W58CllH3HqjmowlZ7SOrgmx8YwYO
# kgrHsXOQHyBp6O4FRb8In0+FzjT7ElGie9V7CfhL3IlVFZ4zjuKsZtH1iU3fGu4z
# /JnOGT6sCb0BbTqe/uhvpFCQBdH5xPGIA/LrbQUXjU2tWJgHhTIqnN/HvHyOHi5t
# M4zP3nhgh2rJ6Kqq2xsHBeNYs/R18xQ8DeIg+c90Eoaeh0YlN1KU8AyYol3K9M+q
# Y5ez8syd/7ZlrRnoVewgH3P1pcswggbiMIIEyqADAgECAhEA507yVbBQT/rbpt/3
# /IujFTANBgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFI0MTAeFw0yNjAzMjUwMDAwMDBaFw0zNzA2MjQyMzU5NTlaMHIxCzAJ
# BgNVBAYTAkdCMRcwFQYDVQQIEw5HcmVhdGVyIExvbmRvbjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIFNpZ25lciBSMzcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy
# /8NtS9xQ2UUtBRF32bj7VK3n4m50Uqjk/zTciSziYV40H1LKah0/oEklYG42E4VC
# P3DvsBUB6DmpCkDZ0jCnZBPIEevaH15ZJOQwFWP2ZXr5YjlJpb68Nlbs+ElNvKx3
# 2/1YHde3qqUSLybjulxPLz6T85+HOIqK7M1Bep8LspyhEP/q6nw5kGxTSrGvufme
# H+JF8CnVBcVMFA40FlIYh0cDJVFhhfTfdWgLy/vWuLMQoKkf3s/FvByf16r0rtby
# Hm/iemwxSioJL9zyZDDKUNAbHXl0dhXo2VxUV2NcPXWXuoKsjL+6cfk6Vm2DHnxA
# lFdFsaBDIF1JOkSnC6PeLlBznZn2buF3vIIYJcq6N/zeFRCk4/HXDz7zgRsRRMdU
# B+rhyk5FoZaBjw0nLq3GZ3fClLUx5es5pUAxzNODMBn7JkFYip2BAGBPER5eV0RO
# hk6tGTG+fUiMiV+vgjg1YnP5FvnYWyEtWeQD/B2hp3vz0RvtdkM0p3igyadzrfpO
# Bq5ppVk/YsuhTQkP99ivneHAGfi5e7lmxJ+meoBPrRLuzMmb81rzzbESjJHMsn5R
# Vtc6Ucs7rcMqQC13PUIO7BbGBETV2ufCmV6lPTp3P7XJOvmnUCRTPbVvMTpxP/z+
# SOHg4/OCBhiqs4FA9+4oQvlkk9w32NGASli9GWrm5wIDAQABo4IBjjCCAYowHwYD
# VR0jBBgwFoAUOnSlDGfGQlDC/bX8x7spNIL0erkwHQYDVR0OBBYEFGEQ6XoSr1HE
# hdTyz6R0D1DNIK/4MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMEoGA1UdIARDMEEwCAYGZ4EMAQQCMDUGDCsGAQQB
# sjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzBK
# BgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29Q
# dWJsaWNUaW1lU3RhbXBpbmdDQVI0MS5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsG
# AQUFBzAChjlodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1l
# U3RhbXBpbmdDQVI0MS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3Rp
# Z28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAD6j2N0azN+hl6k6bKB5/U6VuSOs93
# ZBb3Pczy9VtBIKu4947Z5GwL0aFngIxl+GSuLFrJgPruBCRvKJEJsm7kv+LQ1COV
# CEG9tZ+IRtr4ocUoa53lgdFaENlS0N4wgkZkbQEPv+x+1lSjYh+T4JeL9mUznT7E
# rc6Sp5dWLka5sMP/m3GZi6oJPdPcsCKWagH7m2H2xDGIyHJC5PdH9phvi/Kmhkkt
# iSVTNNqVeV5bWdX2zhRE6UTfz0IcMoCL996lFIydXxOCE4MNDHDM0as4lnTiT/KH
# MccO6l8c9TnUVgmpci9ar1IABZ2U1XUkYjGGSn9MC3EHDP9V39VuBVvZ33/BEV/E
# WSRrf07T7jFplKX+gQr/UOqPGMlE7ZJ72UaUkNJy7bVl3bcLKzdpjIHzLkf/4MVa
# 1V7w8wqCv5W4gOnRGTlud5UMARbRM8BPxR/CXYXoMmIOD8pmTk2axgRL4LG8Xtuc
# hISdCHRmtacAmLGq5XSYSVTHTXADlO48iDKh3HM2r98LSF6f0sG12d8V9Jn7C3wD
# UieOxuKj4MdWrW+hiJU2kF87v6eH00HgCFFc2V0+CvfOCMn7juzS41jLaINcBlKW
# Q/fKb/uDLfWOW73z1I2lFY7Xj8tQ1XYtK5eREjWItM8jpl1cbQOc88btR+0XS2Tm
# boE/141+va2PWzGCBjEwggYtAgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBT
# aWduaW5nIENBIFIzNgIRAIxBnpO/K86siAYoO3YZvTwwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FA/OPNyUpzv7BTGKkXQMxqWMGnEsMA0GCSqGSIb3DQEBAQUABIICACVMCx0M/6vA
# K63NQI8HLNUXhni8fY5GmYqkBtPD0/fi0vNYfOFUjOEwsrJK54Mr3ZXg120VBMTW
# L4aYaNWdhjG6SPZxXImgoQJiT1IC5soQ5JcrJ4oMKhJTxFhlp9mmQs1ovKMnJnXz
# VrG+GEGNmDSnj7eZv/SquYy+Gu5GBD9MjqCN9vmZvodZk5QCpPNs7UQ/HMbOyvIQ
# UKSC+lAiWrwdD0+nnPdBFbmo8PVbGG41WWAVN8z79x2hKjx8pYwA+dypsqDwQhZd
# lTgJUSdQkhOEClxJfYmDh6MwNx0ZDK4A68frcOUI0cqzXsyjAtybIj3UV+dQTURm
# umU8K1GJ2YLA7aTFZC7RHXXYDKsK8+xxvscIeSvGPUPl6XQGVeGAUECwGCWKrInq
# 8QpQ391jUSlEunacJkjwwN/vwAkYXox5aNh3St3WENGsYCeamEhu7BxzDXxEL5jW
# KFxmmCvPzFzNpncUDAP1ao2WJz8/6e58nhoYu+b6bGGi8R8I8HaDSYkLFfAP3iLo
# Yc2CzzopDLf2ptNczCEROSXe+BXZoYOtDa7EkWvuBMiQ99TjPb6ev8eHyTobR/MA
# LsztwCt2ElxjEFt5Vabb4aTB2lgoBNnFU8KbmgoAEXIWtVYIqFPgS6KW106tZFXR
# x56paQKRmuGv/OCT4nHz+MR1dpU4FO2toYIDIzCCAx8GCSqGSIb3DQEJBjGCAxAw
# ggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSNDEC
# EQDnTvJVsFBP+tum3/f8i6MVMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDA0MDc0NjM4WjA/Bgkq
# hkiG9w0BCQQxMgQwqxe4W8brlSny9/kqskj17vPQQI4KWY/FiUb1YaAgk4MkFZ3c
# J5FWNN4lqRHpbsE3MA0GCSqGSIb3DQEBAQUABIICAJOwDZz93vIkaDsGf5xgn0yJ
# iXlhQwpKvKG8HmmYPORcW3eUOv49lq09Lk7FI6kuOaRpu3UtY7K646QG++YqyN7W
# T5QZ3Z8LjunryLIoLAcuTtXhWCvvrMWFSQn820fGIhe+AX6Fk9dwkX5tWKSIbsae
# 5swENZqEg9dd9vn/P09pLn3jF/HoUrjleilcYplXWEiCp86BCNNg4vpTyF6iPdFf
# 8UBCrdX2qhGPSPtF7pB2b7FlJ7FnEgt1TukUBW1yi4aVwuNd+agmDnnF2XkJ9FDZ
# +NIHNQrzBxXs8IDyjFk7vIAkpO4/f2ExoN7dDCJTg6kkPiASGrTFZECj5aubU0JV
# 7SAEtNIyiVbizcWPpDlGggPnZcWbSATqUvg3GmIGDyba89g88tFp4vaJmLMt6BB+
# Th+u6Rt/JQdhoQZJg491ciZI6s19rF8dfC0m5XJd4NJDCnbr4/BFfxoXToj+2qiq
# vlARh3ixdjKS+dqIx0OqoHAI7ENDjoRYxi03dvRGhwzGHQlAw5SjBGKPF0d0DVlb
# OqF6EK3iqQTDPXtfNB9rRZh3CJedb2kBntuMtC22+KEo6Wd78rgmHIu4/vop8TRD
# Jwf/VxcP1SjJAXpzGAg+R75RKSNhmv3mJ5UtYFVqp5jlM5oDqkR0+79vNAz8O/S/
# lj79GvsmaRb6wsP1ci72
# SIG # End signature block
