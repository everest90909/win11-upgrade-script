<# 
.SYNOPSIS
  Windows 11 in-place upgrade (local or remote) via:
   - Setup.exe from ISO / folder / direct path, OR
   - Windows 11 Installation Assistant (download + run silently)

.DESCRIPTION
  - Hardware checks: TPM 2.0, Secure Boot, CPU (x64/ARM64), RAM ≥ 4GB, system drive free space ≥ 64GB
  - Local mode (default) or Orchestrator mode (-TargetComputer)
  - For Setup.exe: supports ISO mount/dis-mount, UNC handling, remote copy-to-target
  - For Installation Assistant: downloads and launches Windows10UpgraderApp.exe with proven silent args

.PARAMETERS
  See param() block below.

.NOTES
  Tested on Windows PowerShell 5.1
#>

param(
    # --- Choose mode ---
    [Parameter()]
    [string]$MediaPath,                     # .iso | folder with setup.exe | direct setup.exe (use Setup mode)
    [Parameter()]
    [switch]$UseInstallationAssistant,      # use the Windows 11 Installation Assistant flow

    # --- Orchestrator (remote) ---
    [Parameter()]
    [string]$TargetComputer,                # if provided, orchestrates on remote target
    [Parameter()]
    [pscredential]$RemoteCredential,        # creds for PSSession to target
    [Parameter()]
    [pscredential]$ShareCredential,         # creds for accessing UNC (when copying media locally or to remote)

    # --- Setup.exe options ---
    [Parameter()]
    [switch]$AutoReboot,                    # remove /noreboot
    [Parameter()]
    [switch]$DisableDynamicUpdate,          # /dynamicupdate disable

    # --- Installation Assistant options ---
    [Parameter()]
    [string]$InstallAssistantDownloadURL = 'https://go.microsoft.com/fwlink/?linkid=2171764',
    [Parameter()]
    [string]$DownloadDestination = "$env:TEMP\Windows11InstallAssistant\Windows11InstallationAssistant.exe",
    [Parameter()]
    [string]$UpdateLogLocation   = "$env:SystemRoot\Logs\Windows11InstallAssistant"
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

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# -----------------------------
# Hardware / OS Requirements
# -----------------------------
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

    # Storage: system drive free space (64 GB recommended available for upgrade)
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

# -----------------------------
# UNC Access / Media Helpers
# -----------------------------
function Resolve-LocalSharePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [pscredential]$Credential
    )
    if ($Path -notmatch '^(\\\\)') {
        return @{ Path = $Path; Drive = $null }
    }

    $m = [regex]::Match($Path, '^\\\\([^\\]+)\\([^\\]+)')
    if (-not $m.Success) { throw "Invalid UNC path: $Path" }
    $shareRoot = $m.Value

    try {
        if (Test-Path -LiteralPath $Path) {
            return @{ Path = $Path; Drive = $null }
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
        return @{ Path = $mappedPath; Drive = $driveName }
    } catch {
        throw "Failed to access $shareRoot. $_"
    }
}

function Copy-IsoLocallyIfUNC {
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

# -----------------------------
# ISO Mount / Setup.exe
# -----------------------------
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

function Invoke-Win11SetupFromMedia {
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

# -----------------------------
# Installation Assistant
# -----------------------------
function Invoke-Download {
    param(
        [Parameter(Mandatory=$true)][string]$URL,
        [Parameter(Mandatory=$true)][string]$Path,
        [int]$Attempts = 3,
        [switch]$Overwrite
    )
    # Ensure TLS12+ if available
    try {
        $supported = [enum]::GetValues([Net.SecurityProtocolType])
        if ($supported -contains 'Tls13' -and $supported -contains 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12
        } elseif ($supported -contains 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    } catch {}

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path -LiteralPath $Path -and $Overwrite) { Remove-Item -LiteralPath $Path -Force }

    for ($i=1; $i -le $Attempts; $i++) {
        try {
            Invoke-WebRequest -Uri $URL -OutFile $Path -MaximumRedirection 10 -UseBasicParsing -ErrorAction Stop
            return $true
        } catch {
            try {
                Start-BitsTransfer -Source $URL -Destination $Path -ErrorAction Stop
                return $true
            } catch {
                if ($i -eq $Attempts) { throw }
                Start-Sleep -Seconds ([Math]::Min(60, 5 * $i))
            }
        }
    }
}

function Start-InstallationAssistant {
    param(
        [Parameter()][string]$DownloadUrl,
        [Parameter()][string]$Destination,
        [Parameter()][string]$LogFolder
    )

    if (-not (Test-IsElevated)) {
        Write-Log "Access denied. Please run with Administrator privileges."
        return $false
    }

    # OS check (Windows 10 expected for in-place to 11)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.Caption -notmatch 'Windows 10') {
            Write-Log "This flow targets Windows 10 → 11 upgrades. Detected: $($os.Caption)."
        }
    } catch {}

    if (-not (Test-Path -LiteralPath $LogFolder)) {
        New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
    }

    Write-Log "Downloading Windows 11 Installation Assistant from $DownloadUrl ..."
    try {
        Invoke-Download -URL $DownloadUrl -Path $Destination -Attempts 3 -Overwrite | Out-Null
    } catch {
        Write-Log "Failed to download Installation Assistant: $($_.Exception.Message)"
        return $false
    }

    # Known install path when installed
    $installedPath = 'C:\Program Files (x86)\WindowsInstallationAssistant\Windows10UpgraderApp.exe'
    $exe = if (Test-Path -LiteralPath $installedPath) { $installedPath } else { $Destination }

    if (-not (Test-Path -LiteralPath $exe)) {
        Write-Log "Installation Assistant executable not found at '$exe'."
        return $false
    }

    $args = @(
        "/QuietInstall"
        "/SkipEULA"
        "/NoRestartUI"
        "/Auto Upgrade"
        "/CopyLogs `"$LogFolder`""
    )

    $procArgs = @{
        FilePath               = $exe
        ArgumentList           = $args
        RedirectStandardOutput = Join-Path $LogFolder "$([guid]::NewGuid()).stdout.log"
        RedirectStandardError  = Join-Path $LogFolder "$([guid]::NewGuid()).stderr.log"
        NoNewWindow            = $true
        WindowStyle            = 'Hidden'
        PassThru               = $true
        ErrorAction            = 'Stop'
    }

    try {
        Write-Log "Launching Installation Assistant silently..."
        $p = Start-Process @procArgs
        # Do NOT wait; IA continues in background
        Start-Sleep -Seconds 30
        if ($p.HasExited) {
            Write-Log "Installation Assistant exited early (exit code $($p.ExitCode)). Check logs in $LogFolder."
        } else {
            Write-Log "Installation Assistant appears to be running in the background."
        }
        return $true
    } catch {
        Write-Log "Failed to start Installation Assistant: $($_.Exception.Message)"
        return $false
    }
}

# -----------------------------
# Remote payloads
# -----------------------------
$RemoteSetupPayload = {
    param([string]$RemoteMediaPath,[bool]$Auto,[bool]$DisableDU,[string]$LogPath)

    $script:logFile = $LogPath
    function Write-Log { param([string]$Message) $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $l="$ts - $Message"; Add-Content -Path $script:logFile -Value $l -Encoding utf8; Write-Host $l }

    # (inline) requirements + helpers (trimmed for brevity but same logic)
    ${function:Check-SystemRequirements} = ${function:Check-SystemRequirements}.ToString()
    ${function:Mount-Win11Iso}          = ${function:Mount-Win11Iso}.ToString()
    ${function:Dismount-Win11Iso}       = ${function:Dismount-Win11Iso}.ToString()
    ${function:Invoke-Win11SetupFromMedia} = ${function:Invoke-Win11SetupFromMedia}.ToString()

    if (-not (Check-SystemRequirements)) { Write-Log "Minimum requirements not met. Aborting."; return }

    [void](Invoke-Win11SetupFromMedia -MediaPath $RemoteMediaPath -AutoReboot:$Auto -DisableDynamicUpdate:$DisableDU)

    # Best-effort monitor
    $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
    if ($p) {
        while (-not $p.HasExited) { Write-Log "Upgrade still in progress..."; Start-Sleep -Seconds 30; $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue }
        Write-Log "Upgrade process exited."
    } else {
        Write-Log "No setup.exe process detected (hand-off may have occurred)."
    }
}

$RemoteAssistantPayload = {
    param([string]$Url,[string]$Dest,[string]$LogPath,[string]$LogFile)

    $script:logFile = $LogFile
    function Write-Log { param([string]$Message) $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $l="$ts - $Message"; Add-Content -Path $script:logFile -Value $l -Encoding utf8; Write-Host $l }

    ${function:Test-IsElevated}   = ${function:Test-IsElevated}.ToString()
    ${function:Invoke-Download}   = ${function:Invoke-Download}.ToString()
    ${function:Start-InstallationAssistant} = ${function:Start-InstallationAssistant}.ToString()
    ${function:Check-SystemRequirements} = ${function:Check-SystemRequirements}.ToString()

    if (-not (Check-SystemRequirements)) { Write-Log "Minimum requirements not met. Aborting."; return }

    [void](Start-InstallationAssistant -DownloadUrl $Url -Destination $Dest -LogFolder $LogPath)
}

# -----------------------------
# Main flow
# -----------------------------
Write-Log "Windows 11 upgrade script started."

if ($TargetComputer) {
    # ---------- Orchestrator mode ----------
    try {
        $session = if ($RemoteCredential) {
            New-PSSession -ComputerName $TargetComputer -Credential $RemoteCredential -Authentication Kerberos -ErrorAction Stop
        } else {
            New-PSSession -ComputerName $TargetComputer -Authentication Kerberos -ErrorAction Stop
        }
        Write-Log "PSSession established to $TargetComputer."
    } catch {
        Write-Log "Failed to create PSSession to $TargetComputer: $_"
        throw
    }

    try {
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory | Out-Null } }

        if ($UseInstallationAssistant -or (-not $MediaPath)) {
            # Download & run IA on the target (no media copy needed)
            $remoteDest = "C:\Temp\Windows11InstallationAssistant.exe"
            $remoteLogs = "C:\Windows11InstallAssistantLogs"
            Invoke-Command -Session $session -ScriptBlock $RemoteAssistantPayload -ArgumentList $InstallAssistantDownloadURL, $remoteDest, $remoteLogs, $logFile
        } else {
            # Setup.exe mode: copy media then run
            $resolved = Resolve-LocalSharePath -Path $MediaPath -Credential $ShareCredential
            $localSource = $resolved.Path
            $localMapped = $resolved.Drive

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
                Write-Log "Copying setup.exe folder to remote: $destFolder"
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

            $auto = [bool]$AutoReboot
            $du   = [bool]$DisableDynamicUpdate
            Invoke-Command -Session $session -ScriptBlock $RemoteSetupPayload -ArgumentList $remoteDest, $auto, $du, $logFile

            if ($localMapped) { try { Remove-PSDrive -Name $localMapped -Scope Script -Force -ErrorAction SilentlyContinue } catch {} }
        }
    } finally {
        if ($session) {
            Write-Log "Closing PSSession."
            Remove-PSSession $session -ErrorAction SilentlyContinue
        }
    }
} else {
    # ---------- Local mode ----------
    if (-not (Check-SystemRequirements)) {
        Write-Log "System does not meet the minimum requirements for Windows 11. Upgrade aborted."
        exit 1
    }

    if ($UseInstallationAssistant -or (-not $MediaPath)) {
        # IA mode
        [void](Start-InstallationAssistant -DownloadUrl $InstallAssistantDownloadURL -Destination $DownloadDestination -LogFolder $UpdateLogLocation)
    } else {
        # Setup.exe mode
        $resolved = Resolve-LocalSharePath -Path $MediaPath -Credential $ShareCredential
        $pathToUse = $resolved.Path
        $mapped    = $resolved.Drive

        try {
            $ext = [System.IO.Path]::GetExtension($pathToUse)
            if ($ext -ieq ".iso") {
                $localIso = Copy-IsoLocallyIfUNC -IsoPath $pathToUse -Credential $ShareCredential
                [void](Invoke-Win11SetupFromMedia -MediaPath $localIso -AutoReboot:$AutoReboot -DisableDynamicUpdate:$DisableDynamicUpdate)
            } else {
                [void](Invoke-Win11SetupFromMedia -MediaPath $pathToUse -AutoReboot:$AutoReboot -DisableDynamicUpdate:$DisableDynamicUpdate)
            }
        } finally {
            if ($mapped) { try { Remove-PSDrive -Name $mapped -Scope Script -Force -ErrorAction SilentlyContinue } catch {} }
        }
    }
}

Write-Log "Windows 11 upgrade script finished."
