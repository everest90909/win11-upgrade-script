# Win11Upgrade.psm1

# Module-scope defaults
$script:LogFile = "C:\Windows11UpgradeLog.txt"

function Set-Win11UpgradeLogPath {
<#
.SYNOPSIS
  Sets the log file path for all module operations.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    $script:LogFile = $Path
    Write-Verbose "Log path set to $Path"
}

function Write-Log {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    try {
        Add-Content -Path $script:LogFile -Value $line -Encoding utf8
    } catch {
        # last resort: avoid throwing during logging
    }
    Write-Host $line
}

function Test-Win11Requirements {
<#
.SYNOPSIS
  Validates Windows 11 readiness: TPM 2.0, Secure Boot, CPU (x64/ARM64), RAM ≥ 4GB, and C: free space ≥ 64GB.
.OUTPUTS
  [bool] True if all checks pass; otherwise False.
#>
    [CmdletBinding()]
    param()

    Write-Log "Starting system requirement checks..."

    # TPM 2.0
    $tpm = Get-TPM
    if ($null -ne $tpm) {
        if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) {
            try {
                $tpmVersion = (Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm).SpecVersion
                if ($tpmVersion -match '^2\.0') {
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

    # Storage: C: free space ≥ 64 GB
    $systemDrive = (Get-Item -Path Env:SystemDrive).Value
    $sysDisk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
    $freeGB = [math]::Round($sysDisk.FreeSpace / 1GB, 2)
    if ($freeGB -ge 64) {
        Write-Log "Sufficient free space on $systemDrive ($freeGB GB >= 64 GB)."
    } else {
        Write-Log "Insufficient free space on $systemDrive ($freeGB GB). Windows 11 upgrade typically needs ~64 GB free."
        return $false
    }

    Write-Log "System meets the minimum requirements for Windows 11."
    return $true
}

function Resolve-LocalSharePath {
<#
.SYNOPSIS
  Resolves a path that may be a UNC by temporarily mapping the share (if necessary).
.OUTPUTS
  PSCustomObject with Path and Drive (Drive may be $null if not mapped).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [pscredential]$Credential
    )

    if ($Path -notmatch '^(\\\\)') {
        return [pscustomobject]@{ Path = $Path; Drive = $null }
    }

    $m = [regex]::Match($Path, '^\\\\([^\\]+)\\([^\\]+)')
    if (-not $m.Success) { throw "Invalid UNC path: $Path" }
    $shareRoot = $m.Value

    try {
        if (Test-Path -LiteralPath $Path) {
            return [pscustomobject]@{ Path = $Path; Drive = $null }
        }
    } catch {}

    $driveName = "L$(Get-Random -Maximum 9999)"
    try {
        if ($Credential) {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Credential $Credential -Scope Script -ErrorAction Stop | Out-Null
        } else {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Scope Script -ErrorAction Stop | Out-Null
        }
        $mappedPath = $Path -replace [regex]::Escape($shareRoot), "$driveName`:"
        return [pscustomobject]@{ Path = $mappedPath; Drive = $driveName }
    } catch {
        throw "Failed to access $shareRoot. $_"
    }
}

function Copy-IsoLocallyIfUNC {
<#
.SYNOPSIS
  If ISO is on UNC, copies to local temp and returns the local path; otherwise returns original path.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IsoPath,
        [pscredential]$Credential
    )
    if ($IsoPath -notmatch '^(\\\\)') { return $IsoPath }
    $dest = Join-Path $env:TEMP (Split-Path $IsoPath -Leaf)
    Write-Log "Copying ISO locally to $dest ..."
    try {
        if ($Credential) {
            Start-BitsTransfer -Source $IsoPath -Destination $dest -Credential $Credential -ErrorAction Stop
        } else {
            Start-BitsTransfer -Source $IsoPath -Destination $dest -ErrorAction Stop
        }
        return $dest
    } catch {
        throw "Failed to copy ISO to $dest. $_"
    }
}

function Mount-Win11Iso {
<#
.SYNOPSIS
  Mounts an ISO and returns the drive root (e.g., 'E:').
#>
    [CmdletBinding()]
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
<#
.SYNOPSIS
  Dismounts an ISO image by path (safe if already dismounted).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        Write-Log "Dismounting ISO: $Path"
        Dismount-DiskImage -ImagePath $Path -ErrorAction Stop
        Write-Log "ISO dismounted."
    } catch {
        Write-Log "Failed to dismount ISO (may already be gone): $_"
    }
}

function Invoke-Win11SetupFromMedia {
<#
.SYNOPSIS
  Runs setup.exe from an ISO, a folder, or a direct setup.exe path.
.PARAMETER MediaPath
  .iso | folder with setup.exe | setup.exe
.PARAMETER AutoReboot
  If set, omit /noreboot so Setup can reboot automatically.
.PARAMETER DisableDynamicUpdate
  If set, pass /dynamicupdate disable.
.OUTPUTS
  [bool] True if setup launched, otherwise False.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$MediaPath,
        [switch]$AutoReboot,
        [switch]$DisableDynamicUpdate
    )

    $argDU = if ($DisableDynamicUpdate) { "/dynamicupdate disable" } else { "/dynamicupdate enable" }
    $argReboot = if ($AutoReboot) { "" } else { "/noreboot" }
    $args = "/auto upgrade /quiet $argReboot $argDU".Trim()

    try {
        $ext  = [System.IO.Path]::GetExtension($MediaPath)
        $leaf = [System.IO.Path]::GetFileName($MediaPath)

        if ($ext -ieq ".iso") {
            $drive = Mount-Win11Iso -Path $MediaPath
            if (-not $drive) { throw "Mount failed; aborting upgrade." }
            $setup = Join-Path $drive "setup.exe"
            if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found at $setup" }

            if ($PSCmdlet.ShouldProcess($setup, "Start-Process $args")) {
                Write-Log "Launching setup.exe from mounted ISO..."
                Start-Process -FilePath $setup -ArgumentList $args -Wait
                Write-Log "Windows Setup started (silent)."
            }
            Dismount-Win11Iso -Path $MediaPath
            return $true
        }

        if ($leaf -ieq "setup.exe") {
            if (-not (Test-Path -LiteralPath $MediaPath)) { throw "setup.exe not found: $MediaPath" }
            if ($PSCmdlet.ShouldProcess($MediaPath, "Start-Process $args")) {
                Write-Log "Launching setup.exe..."
                Start-Process -FilePath $MediaPath -ArgumentList $args -Wait
                Write-Log "Windows Setup started (silent)."
            }
            return $true
        }

        # Treat as folder
        $setup = Join-Path $MediaPath "setup.exe"
        if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found in folder: $MediaPath" }
        if ($PSCmdlet.ShouldProcess($setup, "Start-Process $args")) {
            Write-Log "Launching setup.exe from folder..."
            Start-Process -FilePath $setup -ArgumentList $args -Wait
            Write-Log "Windows Setup started (silent)."
        }
        return $true
    } catch {
        Write-Log "Upgrade launch failed: $_"
        return $false
    }
}

function Start-Win11UpgradeLocal {
<#
.SYNOPSIS
  Runs a local in-place upgrade using ISO/folder/setup.exe with readiness checks.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MediaPath,
        [pscredential]$ShareCredential,
        [switch]$AutoReboot,
        [switch]$DisableDynamicUpdate
    )

    Write-Log "Windows 11 upgrade (LOCAL) starting."

    # Resolve possible UNC for local access
    $resolved = Resolve-LocalSharePath -Path $MediaPath -Credential $ShareCredential
    $pathToUse = $resolved.Path
    $mapped = $resolved.Drive

    try {
        if (-not (Test-Win11Requirements)) {
            Write-Log "System does not meet the minimum requirements for Windows 11. Upgrade aborted."
            return
        }

        $ext = [System.IO.Path]::GetExtension($pathToUse)
        if ($ext -ieq ".iso") {
            # If ISO is UNC originally, prefer copying local then mounting (more reliable)
            $localIso = Copy-IsoLocallyIfUNC -IsoPath $pathToUse -Credential $ShareCredential
            [void](Invoke-Win11SetupFromMedia -MediaPath $localIso -AutoReboot:$AutoReboot -DisableDynamicUpdate:$DisableDynamicUpdate)
        } else {
            [void](Invoke-Win11SetupFromMedia -MediaPath $pathToUse -AutoReboot:$AutoReboot -DisableDynamicUpdate:$DisableDynamicUpdate)
        }
    } finally {
        if ($mapped) {
            try { Remove-PSDrive -Name $mapped -Scope Script -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

    # Best-effort monitoring
    $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
    if ($p) {
        while (-not $p.HasExited) {
            Write-Log "Upgrade still in progress..."
            Start-Sleep -Seconds 30
            $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
        }
        Write-Log "Upgrade process exited."
    } else {
        Write-Log "No setup.exe process detected (it may have already handed off)."
    }

    Write-Log "Windows 11 upgrade (LOCAL) finished."
}

function Start-Win11UpgradeRemote {
<#
.SYNOPSIS
  Orchestrates a remote in-place upgrade by copying media to the target and running locally there.
.DESCRIPTION
  Avoids PowerShell remoting double-hop by copying ISO/folder/setup.exe to C:\Temp on the target, then executing locally.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetComputer,
        [Parameter(Mandatory)][pscredential]$RemoteCredential,
        [Parameter(Mandatory)][string]$MediaPath,
        [pscredential]$ShareCredential,
        [switch]$AutoReboot,
        [switch]$DisableDynamicUpdate
    )

    Write-Log "Windows 11 upgrade (REMOTE) starting for $TargetComputer"

    # Create Kerberos-authenticated PSSession (use FQDN for best results)
    try {
        $session = New-PSSession -ComputerName $TargetComputer -Credential $RemoteCredential -Authentication Kerberos -ErrorAction Stop
        Write-Log "PSSession established to $TargetComputer."
    } catch {
        Write-Log "Failed to create PSSession: $_"
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

        # Decide copy destination & what to copy
        $ext  = [System.IO.Path]::GetExtension($localSource)
        $leaf = [System.IO.Path]::GetFileName($localSource)
        $remoteDest = ''

        if ($ext -ieq ".iso") {
            $remoteDest = "C:\Temp\$leaf"
            Write-Log "Copying ISO to remote: $remoteDest"
            Copy-Item -Path $localSource -Destination $remoteDest -ToSession $session -Force
        } elseif ($leaf -ieq "setup.exe") {
            $srcFolder = Split-Path $localSource -Parent
            $destFolder = "C:\Temp\Win11Media"
            Write-Log "Copying setup folder to remote: $destFolder"
            Invoke-Command -Session $session -ScriptBlock { param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory | Out-Null } } -ArgumentList $destFolder
            Copy-Item -Path (Join-Path $srcFolder '*') -Destination $destFolder -Recurse -ToSession $session -Force
            $remoteDest = (Join-Path $destFolder 'setup.exe')
        } else {
            $srcFolder = $localSource.TrimEnd('\')
            $leafFolder = Split-Path $srcFolder -Leaf
            $destFolder = "C:\Temp\$leafFolder"
            Write-Log "Copying media folder to remote: $destFolder"
            Invoke-Command -Session $session -ScriptBlock { param($d) if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory | Out-Null } } -ArgumentList $destFolder
            Copy-Item -Path (Join-Path $srcFolder '*') -Destination $destFolder -Recurse -ToSession $session -Force
            $remoteDest = $destFolder
        }

        # Build the remote payload (minimal functions + run)
        $remoteScript = {
            param([string]$RemoteMediaPath, [string]$LogFile, [bool]$AutoReboot, [bool]$DisableDU)

            $script:LogFile = $LogFile
            function Write-Log { param([string]$Message) $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $l="$ts - $Message"; Add-Content -Path $script:LogFile -Value $l -Encoding utf8; Write-Host $l }

            function Test-Win11Requirements {
                Write-Log "Starting system requirement checks..."
                $tpm = Get-TPM
                if ($null -ne $tpm) {
                    if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) {
                        try {
                            $tpmVersion = (Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm).SpecVersion
                            if ($tpmVersion -match '^2\.0') { Write-Log "✅ TPM 2.0 found and ready." } else { Write-Log "❌ TPM version $tpmVersion found — Windows 11 requires TPM 2.0."; return $false }
                        } catch { Write-Log "⚠ Unable to determine TPM version. Error: $_"; return $false }
                    } else { Write-Log "❌ TPM present but not fully enabled/activated."; return $false }
                } else { Write-Log "❌ TPM not found."; return $false }

                try {
                    if (Confirm-SecureBootUEFI -ErrorAction Stop) { Write-Log "Secure Boot is enabled." } else { Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot."; return $false }
                } catch {
                    try {
                        $sb = Get-CimInstance -Namespace root\wmi -ClassName MSFT_SecureBoot -ErrorAction Stop
                        if ($sb.SecureBootEnabled) { Write-Log "Secure Boot is enabled." } else { Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot."; return $false }
                    } catch { Write-Log "Unable to determine Secure Boot status (Legacy BIOS/non-UEFI or insufficient rights)."; return $false }
                }

                try {
                    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
                    if ($null -eq $cpu -or $cpu.Count -eq 0) { Write-Log "Unable to read CPU information."; return $false }
                    $arch = ($cpu | Select-Object -First 1 -ExpandProperty Architecture)
                    $ok = ($arch -eq 9 -or $arch -eq 12)
                    if ($ok) { Write-Log "$(if($arch -eq 9){'x64'}else{'ARM64'}) processor found." } else { Write-Log "64-bit processor not found. Windows 11 requires x64 or ARM64."; return $false }
                } catch { Write-Log "Failed to evaluate CPU compatibility: $_"; return $false }

                $cs = Get-CimInstance -ClassName Win32_ComputerSystem
                if ($cs.TotalPhysicalMemory -lt 4GB) { Write-Log "Insufficient RAM. Windows 11 requires at least 4GB."; return $false } else { Write-Log "Sufficient RAM (>= 4GB)." }

                $systemDrive = (Get-Item -Path Env:SystemDrive).Value
                $sysDisk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
                $freeGB = [math]::Round($sysDisk.FreeSpace / 1GB, 2)
                if ($freeGB -lt 64) { Write-Log "Insufficient free space on $systemDrive ($freeGB GB)."; return $false } else { Write-Log "Sufficient free space on $systemDrive ($freeGB GB >= 64 GB)." }

                Write-Log "System meets the minimum requirements for Windows 11."
                return $true
            }

            function Mount-Win11Iso { param([string]$Path)
                try {
                    if (-not (Test-Path -LiteralPath $Path)) { throw "ISO not found at: $Path" }
                    Write-Log "Mounting ISO: $Path"
                    $di = Mount-DiskImage -ImagePath $Path -PassThru -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    $vol = ($di | Get-Volume) | Where-Object DriveLetter | Select-Object -First 1
                    if (-not $vol) { $di2 = Get-DiskImage -ImagePath $Path; $vol = Get-Volume -DiskImage $di2 | Where-Object DriveLetter | Select-Object -First 1 }
                    if (-not $vol) { throw "Mounted ISO but no drive letter detected." }
                    return "$($vol.DriveLetter):"
                } catch { Write-Log "Failed to mount ISO: $_"; return $null }
            }
            function Dismount-Win11Iso { param([string]$Path) try { Dismount-DiskImage -ImagePath $Path -ErrorAction Stop } catch {} }

            $argDU = if ($DisableDU) { "/dynamicupdate disable" } else { "/dynamicupdate enable" }
            $argReboot = if ($AutoReboot) { "" } else { "/noreboot" }
            $args = "/auto upgrade /quiet $argReboot $argDU".Trim()

            Write-Log "Windows 11 upgrade (remote payload) starting."
            if (-not (Test-Win11Requirements)) { Write-Log "Min requirements not met. Aborting."; return }

            $ext  = [System.IO.Path]::GetExtension($RemoteMediaPath)
            $leaf = [System.IO.Path]::GetFileName($RemoteMediaPath)

            try {
                if ($ext -ieq ".iso") {
                    $drive = Mount-Win11Iso -Path $RemoteMediaPath
                    if (-not $drive) { throw "Mount failed; aborting." }
                    $setup = Join-Path $drive "setup.exe"
                    if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found at $setup" }
                    Write-Log "Launching setup.exe from mounted ISO..."
                    Start-Process -FilePath $setup -ArgumentList $args -Wait
                    Write-Log "Windows Setup started (silent)."
                    Dismount-Win11Iso -Path $RemoteMediaPath
                } elseif ($leaf -ieq "setup.exe") {
                    if (-not (Test-Path -LiteralPath $RemoteMediaPath)) { throw "setup.exe not found: $RemoteMediaPath" }
                    Write-Log "Launching setup.exe..."
                    Start-Process -FilePath $RemoteMediaPath -ArgumentList $args -Wait
                    Write-Log "Windows Setup started (silent)."
                } else {
                    $setup = Join-Path $RemoteMediaPath "setup.exe"
                    if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found in folder: $RemoteMediaPath" }
                    Write-Log "Launching setup.exe from folder..."
                    Start-Process -FilePath $setup -ArgumentList $args -Wait
                    Write-Log "Windows Setup started (silent)."
                }
            } catch {
                Write-Log "Upgrade launch failed: $_"
            }

            # Monitor best-effort
            $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
            if ($p) {
                while (-not $p.HasExited) {
                    Write-Log "Upgrade still in progress..."
                    Start-Sleep -Seconds 30
                    $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
                }
                Write-Log "Upgrade process exited."
            } else {
                Write-Log "No setup.exe process detected (hand-off may have occurred)."
            }
            Write-Log "Windows 11 upgrade (remote payload) finished."
        }

        $auto = [bool]$AutoReboot
        $du   = [bool]$DisableDynamicUpdate

        # Run remote script with remote media path and our log file path
        $remoteLog = "C:\Windows11UpgradeLog.txt"
        Write-Log "Starting upgrade on remote using copied media."
        Invoke-Command -Session $session -ScriptBlock $remoteScript -ArgumentList $remoteDest, $remoteLog, $auto, $du

    } finally {
        if ($localMappedDrive) {
            try { Remove-PSDrive -Name $localMappedDrive -Scope Script -Force -ErrorAction SilentlyContinue } catch {}
        }
        if ($session) {
            Write-Log "Closing PSSession."
            Remove-PSSession $session -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Windows 11 upgrade (REMOTE) finished for $TargetComputer"
}

# Export public functions
Export-ModuleMember -Function Set-Win11UpgradeLogPath, Test-Win11Requirements, Start-Win11UpgradeLocal, Start-Win11UpgradeRemote
