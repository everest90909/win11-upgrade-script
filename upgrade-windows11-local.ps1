# upgrade-windows11-local-fixed.ps1
# Local Windows 11 in-place upgrade (Setup.exe or Installation Assistant)
# Fixes: 'A parameter cannot be found that matches parameter name ''and''' by simplifying downloader logic.

param(
    [string]$MediaPath,                         # .iso | folder with setup.exe | setup.exe (if omitted, IA route is used)
    [switch]$UseInstallationAssistant,          # force IA route
    [switch]$AutoReboot,                        # Setup.exe: omit /noreboot
    [switch]$DisableDynamicUpdate,              # Setup.exe: /dynamicupdate disable
    [string]$InstallAssistantDownloadURL = 'https://go.microsoft.com/fwlink/?linkid=2171764',
    [string]$DownloadDestination = "$env:TEMP\Windows11InstallAssistant\Windows11InstallationAssistant.exe",
    [string]$UpdateLogLocation   = "$env:SystemRoot\Logs\Windows11InstallAssistant"
)

$logFile = "C:\Windows11UpgradeLog.txt"

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    try { Add-Content -Path $logFile -Value $line -Encoding utf8 } catch {}
    Write-Host $line
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Check-SystemRequirements {
    Write-Log "Starting system requirement checks..."

    $tpm = Get-TPM
    if ($null -ne $tpm) {
        if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) {
            try {
                $tpmVersion = (Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm).SpecVersion
                if ($tpmVersion -match '^2\.0') { Write-Log "✅ TPM 2.0 found and ready." }
                else { Write-Log "❌ TPM version $tpmVersion found — Windows 11 requires TPM 2.0."; return $false }
            } catch { Write-Log "⚠ Unable to determine TPM version. Error: $_"; return $false }
        } else { Write-Log "❌ TPM present but not fully enabled/activated."; return $false }
    } else { Write-Log "❌ TPM not found."; return $false }

    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) { Write-Log "Secure Boot is enabled." }
        else { Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot."; return $false }
    } catch {
        try {
            $sb = Get-CimInstance -Namespace root\wmi -ClassName MSFT_SecureBoot -ErrorAction Stop
            if ($sb.SecureBootEnabled) { Write-Log "Secure Boot is enabled." }
            else { Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot."; return $false }
        } catch {
            Write-Log "Unable to determine Secure Boot status (Legacy BIOS/non-UEFI or insufficient rights)."
            return $false
        }
    }

    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        if ($null -eq $cpu -or $cpu.Count -eq 0) { Write-Log "Unable to read CPU information."; return $false }
        $arch = ($cpu | Select-Object -First 1 -ExpandProperty Architecture)
        $ok = ($arch -eq 9 -or $arch -eq 12)
        if ($ok) { Write-Log "$(if($arch -eq 9){'x64'}else{'ARM64'}) processor found." }
        else { Write-Log "64-bit processor not found. Windows 11 requires x64 or ARM64."; return $false }
    } catch { Write-Log "Failed to evaluate CPU compatibility: $_"; return $false }

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($cs.TotalPhysicalMemory -lt 4GB) { Write-Log "Insufficient RAM. Windows 11 requires at least 4GB."; return $false }
    else { Write-Log "Sufficient RAM (>= 4GB)." }

    $systemDrive = (Get-Item -Path Env:SystemDrive).Value
    $sysDisk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
    $freeGB = [math]::Round($sysDisk.FreeSpace / 1GB, 2)
    if ($freeGB -lt 64) { Write-Log "Insufficient free space on $systemDrive ($freeGB GB)."; return $false }
    else { Write-Log "Sufficient free space on $systemDrive ($freeGB GB >= 64 GB)." }

    Write-Log "System meets the minimum requirements for Windows 11."
    return $true
}

function Invoke-Download {
    param(
        [Parameter(Mandatory)][string]$URL,
        [Parameter(Mandatory)][string]$Path,
        [int]$Attempts = 3,
        [switch]$Overwrite
    )
    # Simpler, version-tolerant TLS setting
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path -LiteralPath $Path -and $Overwrite) { Remove-Item -LiteralPath $Path -Force }

    for ($i=1; $i -le $Attempts; $i++) {
        try {
            # Prefer BITS (better for large files & resumes)
            Start-BitsTransfer -Source $URL -Destination $Path -ErrorAction Stop
            return $true
        } catch {
            try {
                # Fallback to IWR (no -UseBasicParsing; deprecated)
                Invoke-WebRequest -Uri $URL -OutFile $Path -MaximumRedirection 10 -ErrorAction Stop
                return $true
            } catch {
                if ($i -eq $Attempts) { throw }
                Start-Sleep -Seconds ([Math]::Min(60, 5 * $i))
            }
        }
    }
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
    } catch { Write-Log "Failed to mount ISO: $_"; return $null }
}

function Dismount-Win11Iso {
    param([Parameter(Mandatory)][string]$Path)
    try { Write-Log "Dismounting ISO: $Path"; Dismount-DiskImage -ImagePath $Path -ErrorAction Stop; Write-Log "ISO dismounted." }
    catch { Write-Log "Failed to dismount ISO (may already be gone): $_" }
}

function Invoke-Win11SetupFromMedia {
    param([Parameter(Mandatory)][string]$MediaPath,[switch]$AutoReboot,[switch]$DisableDynamicUpdate)
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
            Write-Log "Launching setup.exe from mounted ISO..."
            Start-Process -FilePath $setup -ArgumentList $args -Wait
            Write-Log "Windows Setup started (silent)."
            Dismount-Win11Iso -Path $MediaPath
            return $true
        }
        if ($leaf -ieq "setup.exe") {
            if (-not (Test-Path -LiteralPath $MediaPath)) { throw "setup.exe not found: $MediaPath" }
            Write-Log "Launching setup.exe..."
            Start-Process -FilePath $MediaPath -ArgumentList $args -Wait
            Write-Log "Windows Setup started (silent)."
            return $true
        }
        $setup = Join-Path $MediaPath "setup.exe"
        if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found in folder: $MediaPath" }
        Write-Log "Launching setup.exe from folder..."
        Start-Process -FilePath $setup -ArgumentList $args -Wait
        Write-Log "Windows Setup started (silent)."
        return $true
    } catch { Write-Log "Upgrade launch failed: $_"; return $false }
}

function Start-InstallationAssistant {
    param(
        [Parameter()][string]$DownloadUrl = 'https://go.microsoft.com/fwlink/?linkid=2171764',
        [Parameter()][string]$Destination = "$env:TEMP\Windows11InstallAssistant\Windows11InstallationAssistant.exe",
        [Parameter()][string]$LogFolder   = "$env:SystemRoot\Logs\Windows11InstallAssistant"
    )
    if (-not (Test-IsElevated)) { Write-Log "Access denied. Please run with Administrator privileges."; return $false }
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop; if ($os.Caption -notmatch 'Windows 10') { Write-Log "This flow targets Windows 10 → 11 upgrades. Detected: $($os.Caption)." } } catch {}
    if (-not (Test-Path -LiteralPath $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }

    Write-Log "Downloading Windows 11 Installation Assistant from $DownloadUrl ..."
    try { Invoke-Download -URL $DownloadUrl -Path $Destination -Attempts 3 -Overwrite | Out-Null }
    catch { Write-Log "Failed to download Installation Assistant: $($_.Exception.Message)"; return $false }

    $installedPath = 'C:\Program Files (x86)\WindowsInstallationAssistant\Windows10UpgraderApp.exe'
    $exe = if (Test-Path -LiteralPath $installedPath) { $installedPath } else { $Destination }
    if (-not (Test-Path -LiteralPath $exe)) { Write-Log "Installation Assistant executable not found at '$exe'."; return $false }

    $args = @("/QuietInstall","/SkipEULA","/NoRestartUI","/Auto Upgrade","/CopyLogs `"$LogFolder`"")
    $procArgs = @{
        FilePath = $exe; ArgumentList = $args;
        RedirectStandardOutput = (Join-Path $LogFolder "$([guid]::NewGuid()).stdout.log");
        RedirectStandardError  = (Join-Path $LogFolder "$([guid]::NewGuid()).stderr.log");
        NoNewWindow = $true; WindowStyle = 'Hidden'; PassThru = $true; ErrorAction = 'Stop'
    }
    try {
        Write-Log "Launching Installation Assistant silently..."
        $p = Start-Process @procArgs
        Start-Sleep -Seconds 30
        if ($p -and -not $p.HasExited) { Write-Log "Installation Assistant appears to be running in the background." }
        elseif ($p) { Write-Log "Installation Assistant exited early (exit code $($p.ExitCode)). Check logs in $LogFolder." }
        else { Write-Log "Installation Assistant launch returned no process object." }
        return $true
    } catch { Write-Log "Failed to start Installation Assistant: $($_.Exception.Message)"; return $false }
}

# ---------------- Main ----------------
Write-Log "Windows 11 upgrade (LOCAL) script started."

$useIA = $UseInstallationAssistant -or [string]::IsNullOrWhiteSpace($MediaPath)
if (-not (Check-SystemRequirements)) {
    Write-Log "System does not meet the minimum requirements for Windows 11. Upgrade aborted."
    exit 1
}

if ($useIA) {
    [void](Start-InstallationAssistant -DownloadUrl $InstallAssistantDownloadURL -Destination $DownloadDestination -LogFolder $UpdateLogLocation)
} else {
    [void](Invoke-Win11SetupFromMedia -MediaPath $MediaPath -AutoReboot:$AutoReboot -DisableDynamicUpdate:$DisableDynamicUpdate)
}

Write-Log "Windows 11 upgrade (LOCAL) script finished."
