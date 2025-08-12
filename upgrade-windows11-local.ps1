<# 
.SYNOPSIS
  Windows 11 in-place upgrade via ISO/folder/setup.exe with hardware checks.
  Supports local execution OR orchestrated remote execution that avoids double-hop.

.PARAMETER MediaPath
  Path to a Windows 11 ISO file, a folder containing setup.exe, or setup.exe itself.

.PARAMETER TargetComputer
  (Optional) If provided, the script will create a PSSession to this host, copy media locally,
  and run the upgrade there (Solution #1).

.PARAMETER RemoteCredential
  (Optional) Credential to establish the PSSession to TargetComputer.

.PARAMETER ShareCredential
  (Optional) Credential to access UNC shares when copying media (used locally before sending to remote).

.EXAMPLES
  # Local
  .\upgrade-windows11.ps1 -MediaPath 'C:\ISO\Win11_24H2.iso'

  # Orchestrator (admin box -> remote)
  .\upgrade-windows11.ps1 -TargetComputer 'PC123.domain.local' `
      -RemoteCredential (Get-Credential) `
      -MediaPath '\\ds-share\Public\Win11_24H2\setup.exe'
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$MediaPath,

    [Parameter(Mandatory = $false)]
    [string]$TargetComputer,

    [Parameter(Mandatory = $false)]
    [pscredential]$RemoteCredential,

    [Parameter(Mandatory = $false)]
    [pscredential]$ShareCredential
)

# -----------------------------
# Globals / Logging
# -----------------------------
$logFile = "C:\Windows11UpgradeLog.txt"

Function Write-Log {
    param([string]$Message)
    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage
}

# -----------------------------
# Local-mode Helper: Map UNC temporarily (for copying media locally, if needed)
# -----------------------------
function Resolve-LocalSharePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [pscredential]$Credential
    )
    if ($Path -notmatch '^(\\\\)') {
        return @{ Path = $Path; Drive = $null }  # local path
    }

    # Extract \\server\share
    $m = [regex]::Match($Path, '^\\\\([^\\]+)\\([^\\]+)')
    if (-not $m.Success) { throw "Invalid UNC path: $Path" }
    $shareRoot = $m.Value

    # Quick attempt without mapping (maybe already authenticated)
    try { if (Test-Path -LiteralPath $Path) { return @{ Path = $Path; Drive = $null } } } catch {}

    $driveName = "L$(Get-Random -Maximum 9999)"
    try {
        if ($Credential) {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Credential $Credential -Scope Script -ErrorAction Stop | Out-Null
        } else {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Scope Script -ErrorAction Stop | Out-Null
        }
        $mappedPath = $Path -replace [regex]::Escape($shareRoot), "$driveName`:"
        return @{ Path = $mappedPath; Drive = $driveName }
    } catch {
        throw "Failed to access $shareRoot. $_"
    }
}

# -----------------------------
# Remote payload (functions that will run ON the target)
# -----------------------------
$RemoteUpgradePayload = {
    param([string]$RemoteMediaPath)

    $logFile = "C:\Windows11UpgradeLog.txt"
    function Write-Log {
        param([string]$Message)
        $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp - $Message"
        Add-Content -Path $logFile -Value $logMessage
        Write-Host $logMessage
    }

    Function Check-SystemRequirements {
        Write-Log "Starting system requirement checks..."

        # TPM 2.0
        $tpm = Get-TPM
        if ($null -ne $tpm) {
            if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) {
                try {
                    $tpmVersion = (Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm).SpecVersion
                    if ($tpmVersion -match "^2\.0") {
                        Write-Log "✅ TPM 2.0 found and ready."
                    } else {
                        Write-Log "❌ TPM version $tpmVersion found — Windows 11 requires TPM 2.0."
                        return $false
                    }
                } catch {
                    Write-Log "⚠ Unable to determine TPM version. Error: $_"
                    return $false
                }
            } else {
                Write-Log "❌ TPM present but not fully enabled/activated."
                return $false
            }
        } else {
            Write-Log "❌ TPM not found."
            return $false
        }

        # Secure Boot
        try {
            if (Confirm-SecureBootUEFI -ErrorAction Stop) {
                Write-Log "Secure Boot is enabled."
            } else {
                Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot."
                return $false
            }
        } catch {
            try {
                $sb = Get-CimInstance -Namespace root\wmi -ClassName MSFT_SecureBoot -ErrorAction Stop
                if ($sb.SecureBootEnabled) {
                    Write-Log "Secure Boot is enabled."
                } else {
                    Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot."
                    return $false
                }
            } catch {
                Write-Log "Unable to determine Secure Boot status (Legacy BIOS/non-UEFI or insufficient rights)."
                return $false
            }
        }

        # CPU (x64 or ARM64)
        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
            if ($null -eq $cpu -or $cpu.Count -eq 0) { Write-Log "Unable to read CPU information."; return $false }
            $arch = ($cpu | Select-Object -First 1 -ExpandProperty Architecture)
            $isSupported = $false
            $archName = switch ($arch) {
                9  { $isSupported = $true; "x64" }
                12 { $isSupported = $true; "ARM64" }
                6  { "Itanium" }
                0  { "x86 (32-bit)" }
                5  { "ARM (32-bit)" }
                default { "Unknown ($arch)" }
            }
            if ($isSupported) { Write-Log "$archName processor found." }
            else { Write-Log "64-bit processor not found (detected: $archName). Windows 11 requires x64 or ARM64."; return $false }
        } catch {
            Write-Log "Failed to evaluate CPU compatibility: $_"
            return $false
        }

        # RAM ≥ 4 GB
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($cs.TotalPhysicalMemory -ge 4GB) {
            Write-Log "Sufficient RAM (>= 4GB)."
        } else {
            Write-Log "Insufficient RAM. Windows 11 requires at least 4GB."
            return $false
        }

        # --- Registry checks for upgrade blocks ---
        try {
            $osUpgradeKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade"
            if (Test-Path $osUpgradeKey) {
                $allowUpgrade = Get-ItemProperty -Path $osUpgradeKey -Name AllowOSUpgrade -ErrorAction SilentlyContinue
                if ($allowUpgrade.AllowOSUpgrade -ne 1) {
                    Write-Log "❌ Registry block: AllowOSUpgrade is not set to 1."
                    return $false
                } else {
                    Write-Log "AllowOSUpgrade registry key is set correctly."
                }
            }

            $wuPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            if (Test-Path $wuPolicyKey) {
                $disableUpgrade = Get-ItemProperty -Path $wuPolicyKey -Name DisableOSUpgrade -ErrorAction SilentlyContinue
                if ($disableUpgrade.DisableOSUpgrade -eq 1) {
                    Write-Log "❌ Registry block: DisableOSUpgrade is set to 1."
                    return $false
                }

                $targetRelease = Get-ItemProperty -Path $wuPolicyKey -Name TargetReleaseVersion -ErrorAction SilentlyContinue
                if ($targetRelease.TargetReleaseVersion) {
                    Write-Log "⚠ TargetReleaseVersion policy is set. May restrict upgrade."
                }
            }
        } catch {
            Write-Log "Registry check failed: $_"
        }

        # Storage ≥ 64 GB free on system drive
        $systemDrive = (Get-Item -Path Env:SystemDrive).Value
        $sysDisk     = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        $freeGB      = [math]::Round($sysDisk.FreeSpace / 1GB, 2)
        if ($freeGB -ge 64) {
            Write-Log "Sufficient free space on $systemDrive ($freeGB GB >= 64 GB)."
        } else {
            Write-Log "Insufficient free space on $systemDrive ($freeGB GB). Windows 11 upgrade typically needs ~64 GB free."
            return $false
        }

        Write-Log "System meets the minimum requirements for Windows 11."
        return $true
    }

    function Mount-Win11Iso {
        param([Parameter(Mandatory)][string]$Path)
        try {
            if (-not (Test-Path -LiteralPath $Path)) { throw "ISO not found at: $Path" }
            Write-Log "Mounting ISO: $Path"
            $di = Mount-DiskImage -ImagePath $Path -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 2
            $vol = ($di | Get-Volume) | Where-Object { $_.DriveLetter } | Select-Object -First 1
            if ($null -eq $vol) {
                $di2 = Get-DiskImage -ImagePath $Path
                $vol = Get-Volume -DiskImage $di2 | Where-Object { $_.DriveLetter } | Select-Object -First 1
            }
            if ($null -eq $vol) { throw "Mounted ISO but no drive letter detected." }
            $drive = "$($vol.DriveLetter):"
            Write-Log "ISO mounted at $drive"
            return $drive
        } catch {
            Write-Log "Failed to mount ISO: $_"
            return $null
        }
    }

    function Dismount-Win11Iso {
        param([Parameter(Mandatory)][string]$Path)
        try {
            Write-Log "Dismounting ISO: $Path"
            Dismount-DiskImage -ImagePath $Path -ErrorAction Stop
            Write-Log "ISO dismounted."
        } catch {
            Write-Log "Failed to dismount ISO (may already be gone): $_"
        }
    }

    function Invoke-Win11Upgrade {
        param([Parameter(Mandatory)][string]$MediaPath)

        Write-Log "Preparing Windows 11 upgrade from local media: $MediaPath"
        try {
            $ext  = [System.IO.Path]::GetExtension($MediaPath)
            $leaf = [System.IO.Path]::GetFileName($MediaPath)

            if ($ext -ieq ".iso") {
                $drive = Mount-Win11Iso -Path $MediaPath
                if (-not $drive) { throw "Mount failed; aborting upgrade." }

                $setup = Join-Path $drive "setup.exe"
                if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found at $setup" }

                Write-Log "Launching setup.exe from mounted ISO..."
                $args = "/auto upgrade /quiet /noreboot /dynamicupdate enable"
                Start-Process -FilePath $setup -ArgumentList $args -Wait
                Write-Log "Windows Setup started (silent)."

                Dismount-Win11Iso -Path $MediaPath

            } elseif ($leaf -ieq "setup.exe") {
                if (-not (Test-Path -LiteralPath $MediaPath)) { throw "setup.exe not found: $MediaPath" }
                Write-Log "Launching setup.exe..."
                $args = "/auto upgrade /quiet /noreboot /dynamicupdate enable"
                Start-Process -FilePath $MediaPath -ArgumentList $args -Wait
                Write-Log "Windows Setup started (silent)."

            } else {
                $setup = Join-Path $MediaPath "setup.exe"
                if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found in folder: $MediaPath" }
                Write-Log "Launching setup.exe from folder..."
                $args = "/auto upgrade /quiet /noreboot /dynamicupdate enable"
                Start-Process -FilePath $setup -ArgumentList $args -Wait
                Write-Log "Windows Setup started (silent)."
            }
        } catch {
            Write-Log "Upgrade launch failed: $_"
        }
    }

    Function Monitor-UpgradeStatus {
        Write-Log "Monitoring upgrade status..."
        $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
        if ($p) {
            while (-not $p.HasExited) {
                Write-Log "Upgrade still in progress..."
                Start-Sleep -Seconds 30
                $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
            }
            Write-Log "Upgrade process exited."
        } else {
            Write-Log "No setup.exe process detected (it may have already handed off to the upgrader service)."
        }
    }

    Write-Log "Windows 11 upgrade (remote payload) starting."
    if (Check-SystemRequirements) {
        Invoke-Win11Upgrade -MediaPath $RemoteMediaPath
        Monitor-UpgradeStatus
    } else {
        Write-Log "System does not meet the minimum requirements for Windows 11. Upgrade aborted."
    }
    Write-Log "Windows 11 upgrade (remote payload) finished."
}

# -----------------------------
# Orchestrator Mode (Solution #1) OR Local Mode
# -----------------------------
if ([string]::IsNullOrWhiteSpace($TargetComputer)) {
    # ---------- Local mode ----------
    Write-Log "Running in LOCAL mode."

    # Reuse remote payload locally by invoking with current MediaPath
    & $RemoteUpgradePayload -RemoteMediaPath $MediaPath
    return
}

# ---------- Orchestrator mode ----------
Write-Log "Running in ORCHESTRATOR mode for target: $TargetComputer"

# Create PSSession using Kerberos if possible (use FQDN)
try {
    if ($RemoteCredential) {
        $session = New-PSSession -ComputerName $TargetComputer -Credential $RemoteCredential -Authentication Kerberos -ErrorAction Stop
    } else {
        $session = New-PSSession -ComputerName $TargetComputer -Authentication Kerberos -ErrorAction Stop
    }
    Write-Log "PSSession established to $TargetComputer."
} catch {
    Write-Log "Failed to create PSSession to $TargetComputer : $_"
    throw
}

try {
    # Ensure C:\Temp exists on remote
    Invoke-Command -Session $session -ScriptBlock {
        if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory | Out-Null }
    }

    # Prepare local access to source media (map share if needed)
    $resolved = Resolve-LocalSharePath -Path $MediaPath -Credential $ShareCredential
    $localSource = $resolved.Path
    $localMappedDrive = $resolved.Drive

    # Decide what to copy and where on the remote
    $ext  = [System.IO.Path]::GetExtension($localSource)
    $leaf = [System.IO.Path]::GetFileName($localSource)
    $remoteDest = ''

    if ($ext -ieq ".iso") {
        $remoteDest = "C:\Temp\$leaf"
        Write-Log "Copying ISO to remote: $remoteDest"
        Copy-Item -Path $localSource -Destination $remoteDest -ToSession $session -Force
    } elseif ($leaf -ieq "setup.exe") {
        # Copy the entire folder that contains setup.exe (so all sources exist)
        $srcFolder = Split-Path $localSource -Parent
        $destFolder = "C:\Temp\Win11Media"
        Write-Log "Copying setup folder to remote: $destFolder"
        # Create dest folder
        Invoke-Command -Session $session -ScriptBlock { param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory | Out-Null } } -ArgumentList $destFolder
        Copy-Item -Path (Join-Path $srcFolder '*') -Destination $destFolder -Recurse -ToSession $session -Force
        $remoteDest = (Join-Path $destFolder 'setup.exe')
    } else {
        # Treat as a folder; copy its contents
        $srcFolder = $localSource.TrimEnd('\')
        $leafFolder = Split-Path $srcFolder -Leaf
        $destFolder = "C:\Temp\$leafFolder"
        Write-Log "Copying media folder to remote: $destFolder"
        Invoke-Command -Session $session -ScriptBlock { param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory | Out-Null } } -ArgumentList $destFolder
        Copy-Item -Path (Join-Path $srcFolder '*') -Destination $destFolder -Recurse -ToSession $session -Force
        $remoteDest = $destFolder
    }

    # Run the remote payload with the local (on remote) media path
    Write-Log "Starting upgrade on remote using: $remoteDest"
    Invoke-Command -Session $session -ScriptBlock $RemoteUpgradePayload -ArgumentList $remoteDest

} catch {
    Write-Log "Orchestration failed: $_"
} finally {
    # Unmap any local temporary PSDrive
    if ($localMappedDrive) {
        try { Remove-PSDrive -Name $localMappedDrive -Scope Script -Force -ErrorAction SilentlyContinue } catch {}
    }
    if ($session) {
        Write-Log "Closing PSSession."
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
}
