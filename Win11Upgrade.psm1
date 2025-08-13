# Win11Upgrade.psm1
# Version: 1.2.2
# Windows 11 in-place upgrade helpers (local + remote orchestrator)
# Supports: Setup.exe (ISO/folder/direct) OR Windows 11 Installation Assistant
# NOTE: Remote payloads are fully self-contained and the downloader uses BITS -> WebClient (no Invoke-WebRequest).

$script:LogFile = "C:\Windows11UpgradeLog.txt"

function Set-Win11UpgradeLogPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
    $script:LogFile = $Path
}

function Write-Log {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    try { Add-Content -Path $script:LogFile -Value $line -Encoding utf8 } catch {}
    Write-Host $line
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Win11Requirements {
    [CmdletBinding()]
    param()
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
        } catch { Write-Log "Unable to determine Secure Boot status (Legacy BIOS/non-UEFI or insufficient rights)."; return $false }
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

function Resolve-LocalSharePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[pscredential]$Credential)
    if ($Path -notmatch '^(\\\\)') { return [pscustomobject]@{ Path=$Path; Drive=$null } }
    $m = [regex]::Match($Path, '^\\\\([^\\]+)\\([^\\]+)')
    if (-not $m.Success) { throw "Invalid UNC path: $Path" }
    $shareRoot = $m.Value
    try { if (Test-Path -LiteralPath $Path) { return [pscustomobject]@{ Path=$Path; Drive=$null } } } catch {}
    $driveName = "L$(Get-Random -Maximum 9999)"
    try {
        if ($Credential) { New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Credential $Credential -Scope Script -ErrorAction Stop | Out-Null }
        else { New-PSDrive -Name $driveName -PSProvider FileSystem -Root $shareRoot -Scope Script -ErrorAction Stop | Out-Null }
        $mappedPath = $Path -replace [regex]::Escape($shareRoot), "$driveName`:"
        return [pscustomobject]@{ Path=$mappedPath; Drive=$driveName }
    } catch { throw "Failed to access $shareRoot. $_" }
}

function Copy-IsoLocallyIfUNC {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IsoPath,[pscredential]$Credential)
    if ($IsoPath -notmatch '^(\\\\)') { return $IsoPath }
    $dest = Join-Path $env:TEMP (Split-Path $IsoPath -Leaf)
    Write-Log "Copying ISO locally to $dest ..."
    try {
        if ($Credential) { Start-BitsTransfer -Source $IsoPath -Destination $dest -Credential $Credential -ErrorAction Stop }
        else { Start-BitsTransfer -Source $IsoPath -Destination $dest -ErrorAction Stop }
        return $dest
    } catch { throw "Failed to copy ISO to $dest. $_" }
}

function Mount-Win11Iso {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { throw "ISO not found at: $Path" }
        Write-Log "Mounting ISO: $Path"
        $di = Mount-DiskImage -ImagePath $Path -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 2
        $vol = ($di | Get-Volume) | Where-Object { $_.DriveLetter } | Select-Object -First 1
        if ($null -eq $vol) { $di2 = Get-DiskImage -ImagePath $Path; $vol = Get-Volume -DiskImage $di2 | Where-Object { $_.DriveLetter } | Select-Object -First 1 }
        if ($null -eq $vol) { throw "Mounted ISO but no drive letter detected." }
        $drive = "$($vol.DriveLetter):"
        Write-Log "ISO mounted at $drive"
        return $drive
    } catch { Write-Log "Failed to mount ISO: $_"; return $null }
}

function Dismount-Win11Iso {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try { Write-Log "Dismounting ISO: $Path"; Dismount-DiskImage -ImagePath $Path -ErrorAction Stop; Write-Log "ISO dismounted." }
    catch { Write-Log "Failed to dismount ISO (may already be gone): $_" }
}

function Invoke-Win11SetupFromMedia {
    [CmdletBinding(SupportsShouldProcess)]
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
        $setup = Join-Path $MediaPath "setup.exe"
        if (-not (Test-Path -LiteralPath $setup)) { throw "setup.exe not found in folder: $MediaPath" }
        if ($PSCmdlet.ShouldProcess($setup, "Start-Process $args")) {
            Write-Log "Launching setup.exe from folder..."
            Start-Process -FilePath $setup -ArgumentList $args -Wait
            Write-Log "Windows Setup started (silent)."
        }
        return $true
    } catch { Write-Log "Upgrade launch failed: $_"; return $false }
}

function Invoke-Download {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$URL,[Parameter(Mandatory)][string]$Path,[int]$Attempts = 3,[switch]$Overwrite)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($Overwrite -and (Test-Path -LiteralPath $Path)) {
    Remove-Item -LiteralPath $Path -Force
}
    for ($i=1; $i -le $Attempts; $i++) {
        try {
            Start-BitsTransfer -Source $URL -Destination $Path -ErrorAction Stop
            return $true
        } catch {
            try {
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($URL, $Path)
                return $true
            } catch {
                if ($i -eq $Attempts) { throw }
                Start-Sleep -Seconds ([Math]::Min(60, 5 * $i))
            }
        }
    }
}

function Start-InstallationAssistant {
    [CmdletBinding()]
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
    catch { Write-Log ("Failed to download Installation Assistant: {0}`n{1}" -f $_.Exception.Message, ($_.InvocationInfo.PositionMessage)) ; return $false }

    $installedPath = 'C:\Program Files (x86)\WindowsInstallationAssistant\Windows10UpgraderApp.exe'
    $exe = if (Test-Path -LiteralPath $installedPath) { $installedPath } else { $Destination }
    if (-not (Test-Path -LiteralPath $exe)) { Write-Log "Installation Assistant executable not found at '$exe'."; return $false }

    $args = @("/QuietInstall","/SkipEULA","/NoRestartUI","/Auto Upgrade","/CopyLogs `"$LogFolder`"")
    $procArgs = @{
        FilePath=$exe; ArgumentList=$args;
        RedirectStandardOutput=(Join-Path $LogFolder "$([guid]::NewGuid()).stdout.log");
        RedirectStandardError=(Join-Path $LogFolder "$([guid]::NewGuid()).stderr.log");
        WindowStyle='Hidden'; PassThru=$true; ErrorAction='Stop'
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

function Start-Win11UpgradeLocal {
    [CmdletBinding()]
    param(
        [string]$MediaPath,
        [switch]$UseInstallationAssistant,
        [pscredential]$ShareCredential,
        [switch]$AutoReboot,
        [switch]$DisableDynamicUpdate,
        [string]$InstallAssistantDownloadURL = 'https://go.microsoft.com/fwlink/?linkid=2171764',
        [string]$DownloadDestination = "$env:TEMP\Windows11InstallAssistant\Windows11InstallationAssistant.exe",
        [string]$UpdateLogLocation   = "$env:SystemRoot\Logs\Windows11InstallAssistant"
    )
    Write-Log "Windows 11 upgrade (LOCAL) starting."
    if (-not (Test-Win11Requirements)) { Write-Log "System does not meet the minimum requirements for Windows 11. Upgrade aborted."; return }
    if ($UseInstallationAssistant -or ([string]::IsNullOrWhiteSpace($MediaPath))) {
        [void](Start-InstallationAssistant -DownloadUrl $InstallAssistantDownloadURL -Destination $DownloadDestination -LogFolder $UpdateLogLocation)
    } else {
        $resolved  = Resolve-LocalSharePath -Path $MediaPath -Credential $ShareCredential
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
    $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
    if ($p) {
        while (-not $p.HasExited) { Write-Log "Upgrade still in progress..."; Start-Sleep -Seconds 30; $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue }
        Write-Log "Upgrade process exited."
    } else { Write-Log "No setup.exe process detected (it may have already handed off)." }
    Write-Log "Windows 11 upgrade (LOCAL) finished."
}

function Start-Win11UpgradeRemote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetComputer,
        [Parameter(Mandatory)][pscredential]$RemoteCredential,
        [string]$MediaPath,
        [switch]$UseInstallationAssistant,
        [pscredential]$ShareCredential,
        [switch]$AutoReboot,
        [switch]$DisableDynamicUpdate,
        [string]$InstallAssistantDownloadURL = 'https://go.microsoft.com/fwlink/?linkid=2171764',
        [string]$DownloadDestination = "C:\Temp\Windows11InstallationAssistant.exe",
        [string]$UpdateLogLocation   = "C:\Windows11InstallAssistantLogs"
    )
    Write-Log "Windows 11 upgrade (REMOTE) starting for $TargetComputer"
    try {
        $session = New-PSSession -ComputerName $TargetComputer -Credential $RemoteCredential -Authentication Kerberos -ErrorAction Stop
        Write-Log "PSSession established to $TargetComputer."
    } catch { Write-Log "Failed to create PSSession: $_"; throw }
    try {
        Invoke-Command -Session $session -ScriptBlock { if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory | Out-Null } }
        if ($UseInstallationAssistant -or ([string]::IsNullOrWhiteSpace($MediaPath))) {
            $RemoteAssistantPayload = {
                param([string]$Url,[string]$Dest,[string]$LogPath,[string]$LogFile)
                $script:LogFile = $LogFile
                function Write-Log { param([string]$Message) $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $l="$ts - $Message"; Add-Content -Path $script:LogFile -Value $l -Encoding utf8; Write-Host $l }
                function Test-IsElevated { $id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id);return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
                function Test-Win11Requirements {
                    Write-Log "Starting system requirement checks..."
                    $tpm=Get-TPM
                    if($null -ne $tpm){
                        if($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated){
                            try{$tpmVersion=(Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm).SpecVersion;if($tpmVersion -match '^2\.0'){Write-Log "✅ TPM 2.0 found and ready."}else{Write-Log "❌ TPM version $tpmVersion found — Windows 11 requires TPM 2.0.";return $false}}catch{Write-Log "⚠ Unable to determine TPM version. Error: $_";return $false}
                        }else{Write-Log "❌ TPM present but not fully enabled/activated.";return $false}
                    }else{Write-Log "❌ TPM not found.";return $false}
                    try{if(Confirm-SecureBootUEFI -ErrorAction Stop){Write-Log "Secure Boot is enabled."}else{Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot.";return $false}}catch{try{$sb=Get-CimInstance -Namespace root\wmi -ClassName MSFT_SecureBoot -ErrorAction Stop;if($sb.SecureBootEnabled){Write-Log "Secure Boot is enabled."}else{Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot.";return $false}}catch{Write-Log "Unable to determine Secure Boot status (Legacy BIOS/non-UEFI or insufficient rights).";return $false}}
                    try{$cpu=Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop;if($null -eq $cpu -or $cpu.Count -eq 0){Write-Log "Unable to read CPU information.";return $false}$arch=($cpu|Select-Object -First 1 -ExpandProperty Architecture);$ok=($arch -eq 9 -or $arch -eq 12);if($ok){Write-Log "$(if($arch -eq 9){'x64'}else{'ARM64'}) processor found."}else{Write-Log "64-bit processor not found. Windows 11 requires x64 or ARM64.";return $false}}catch{Write-Log "Failed to evaluate CPU compatibility: $_";return $false}
                    $cs=Get-CimInstance -ClassName Win32_ComputerSystem;if($cs.TotalPhysicalMemory -lt 4GB){Write-Log "Insufficient RAM. Windows 11 requires at least 4GB.";return $false}else{Write-Log "Sufficient RAM (>= 4GB)."}
                    $systemDrive=(Get-Item -Path Env:SystemDrive).Value;$sysDisk=Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'";$freeGB=[math]::Round($sysDisk.FreeSpace/1GB,2);if($freeGB -lt 64){Write-Log "Insufficient free space on $systemDrive ($freeGB GB).";return $false}else{Write-Log "Sufficient free space on $systemDrive ($freeGB GB >= 64 GB)."}
                    Write-Log "System meets the minimum requirements for Windows 11.";return $true
                }
                function Invoke-Download { param([string]$URL,[string]$Path,[int]$Attempts=3,[switch]$Overwrite)
                    try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12}catch{}
                    $dir=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}
                    if(Test-Path -LiteralPath $Path -and $Overwrite){Remove-Item -LiteralPath $Path -Force}
                    for($i=1;$i -le $Attempts;$i++){
                        try{ Start-BitsTransfer -Source $URL -Destination $Path -ErrorAction Stop; return $true }
                        catch{
                            try{ $wc=New-Object System.Net.WebClient; $wc.DownloadFile($URL,$Path); return $true }
                            catch{ if($i -eq $Attempts){ throw }; Start-Sleep -Seconds ([Math]::Min(60,5*$i)) }
                        }
                    }
                }
                Write-Log "Validating requirements on remote..."
                if (-not (Test-Win11Requirements)) { Write-Log "Minimum requirements not met. Aborting."; return }
                if (-not (Test-IsElevated)) { Write-Log "Access denied. Please run with Administrator privileges."; return }
                if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
                Write-Log "Downloading Windows 11 Installation Assistant from $Url ..."
                try { Invoke-Download -URL $Url -Path $Dest -Attempts 3 -Overwrite | Out-Null }
                catch { Write-Log ("Failed to download Installation Assistant: {0}`n{1}" -f $_.Exception.Message, ($_.InvocationInfo.PositionMessage)) ; return }
                $installedPath='C:\Program Files (x86)\WindowsInstallationAssistant\Windows10UpgraderApp.exe'
                $exe = if (Test-Path -LiteralPath $installedPath) { $installedPath } else { $Dest }
                if (-not (Test-Path -LiteralPath $exe)) { Write-Log "Installation Assistant executable not found at '$exe'."; return }
                $args=@("/QuietInstall","/SkipEULA","/NoRestartUI","/Auto Upgrade","/CopyLogs `"$LogPath`"")
                $procArgs=@{FilePath=$exe;ArgumentList=$args;RedirectStandardOutput=(Join-Path $LogPath "$([guid]::NewGuid()).stdout.log");RedirectStandardError=(Join-Path $LogPath "$([guid]::NewGuid()).stderr.log");NoNewWindow=$true;WindowStyle='Hidden';PassThru=$true;ErrorAction='Stop'}
                try{ Write-Log "Launching Installation Assistant silently..."; $p=Start-Process @procArgs; Start-Sleep -Seconds 30; if($p -and -not $p.HasExited){Write-Log "Installation Assistant appears to be running in the background."} elseif($p){Write-Log "Installation Assistant exited early (exit code $($p.ExitCode)). Check logs in $LogPath."} else { Write-Log "Installation Assistant launch returned no process object." } }catch{ Write-Log "Failed to start Installation Assistant: $($_.Exception.Message)" }
            }
            Invoke-Command -Session $session -ScriptBlock $RemoteAssistantPayload -ArgumentList $InstallAssistantDownloadURL, $DownloadDestination, $UpdateLogLocation, $script:LogFile
        } else {
            $resolved = Resolve-LocalSharePath -Path $MediaPath -Credential $ShareCredential
            $localSource = $resolved.Path
            $localMapped = $resolved.Drive
            $ext  = [System.IO.Path]::GetExtension($localSource)
            $leaf = [System.IO.Path]::GetFileName($localSource)
            if ($ext -ieq ".iso") {
                $remoteDest = "C:\Temp\$leaf"; Write-Log "Copying ISO to remote: $remoteDest"
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
            $RemoteSetupPayload = {
                param([string]$RemoteMediaPath,[bool]$Auto,[bool]$DisableDU,[string]$LogPath)
                $script:LogFile = $LogPath
                function Write-Log { param([string]$Message) $ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; $l="$ts - $Message"; Add-Content -Path $script:LogFile -Value $l -Encoding utf8; Write-Host $l }
                function Test-Win11Requirements {
                    Write-Log "Starting system requirement checks..."
                    $tpm=Get-TPM
                    if($null -ne $tpm){
                        if($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated){
                            try{$tpmVersion=(Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" -ClassName Win32_Tpm).SpecVersion;if($tpmVersion -match '^2\.0'){Write-Log "✅ TPM 2.0 found and ready."}else{Write-Log "❌ TPM version $tpmVersion found — Windows 11 requires TPM 2.0.";return $false}}catch{Write-Log "⚠ Unable to determine TPM version. Error: $_";return $false}
                        }else{Write-Log "❌ TPM present but not fully enabled/activated.";return $false}
                    }else{Write-Log "❌ TPM not found.";return $false}
                    try{if(Confirm-SecureBootUEFI -ErrorAction Stop){Write-Log "Secure Boot is enabled."}else{Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot.";return $false}}catch{try{$sb=Get-CimInstance -Namespace root\wmi -ClassName MSFT_SecureBoot -ErrorAction Stop;if($sb.SecureBootEnabled){Write-Log "Secure Boot is enabled."}else{Write-Log "Secure Boot is not enabled. Windows 11 requires Secure Boot.";return $false}}catch{Write-Log "Unable to determine Secure Boot status (Legacy BIOS/non-UEFI or insufficient rights).";return $false}}
                    try{$cpu=Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop;if($null -eq $cpu -or $cpu.Count -eq 0){Write-Log "Unable to read CPU information.";return $false}$arch=($cpu|Select-Object -First 1 -ExpandProperty Architecture);$ok=($arch -eq 9 -or $arch -eq 12);if($ok){Write-Log "$(if($arch -eq 9){'x64'}else{'ARM64'}) processor found."}else{Write-Log "64-bit processor not found. Windows 11 requires x64 or ARM64.";return $false}}catch{Write-Log "Failed to evaluate CPU compatibility: $_";return $false}
                    $cs=Get-CimInstance -ClassName Win32_ComputerSystem;if($cs.TotalPhysicalMemory -lt 4GB){Write-Log "Insufficient RAM. Windows 11 requires at least 4GB.";return $false}else{Write-Log "Sufficient RAM (>= 4GB)."}
                    $systemDrive=(Get-Item -Path Env:SystemDrive).Value;$sysDisk=Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'";$freeGB=[math]::Round($sysDisk.FreeSpace/1GB,2);if($freeGB -lt 64){Write-Log "Insufficient free space on $systemDrive ($freeGB GB).";return $false}else{Write-Log "Sufficient free space on $systemDrive ($freeGB GB >= 64 GB)."}
                    Write-Log "System meets the minimum requirements for Windows 11.";return $true
                }
                function Mount-Win11Iso { param([string]$Path)
                    try{if(-not(Test-Path -LiteralPath $Path)){throw "ISO not found at: $Path"}
                        $di=Mount-DiskImage -ImagePath $Path -PassThru -ErrorAction Stop; Start-Sleep -Seconds 2
                        $vol=($di|Get-Volume)|Where-Object DriveLetter|Select-Object -First 1
                        if(-not $vol){$di2=Get-DiskImage -ImagePath $Path; $vol=Get-Volume -DiskImage $di2 | Where-Object DriveLetter | Select-Object -First 1}
                        if(-not $vol){throw "Mounted ISO but no drive letter detected."}
                        return "$($vol.DriveLetter):"
                    }catch{ Write-Log "Failed to mount ISO: $_"; return $null }
                }
                function Dismount-Win11Iso { param([string]$Path) try{ Dismount-DiskImage -ImagePath $Path -ErrorAction Stop }catch{} }
                function Invoke-Win11SetupFromMedia { param([string]$MediaPath,[bool]$Auto,[bool]$DisableDU)
                    $argDU = if($DisableDU){"/dynamicupdate disable"}else{"/dynamicupdate enable"}
                    $argReboot = if($Auto){""}else{"/noreboot"}
                    $args = "/auto upgrade /quiet $argReboot $argDU".Trim()
                    try{
                        $ext=[IO.Path]::GetExtension($MediaPath); $leaf=[IO.Path]::GetFileName($MediaPath)
                        if($ext -ieq ".iso"){
                            $drive=Mount-Win11Iso -Path $MediaPath; if(-not $drive){throw "Mount failed; aborting."}
                            $setup=Join-Path $drive "setup.exe"; if(-not(Test-Path -LiteralPath $setup)){throw "setup.exe not found at $setup"}
                            Write-Log "Launching setup.exe from mounted ISO..."; Start-Process -FilePath $setup -ArgumentList $args -Wait; Write-Log "Windows Setup started (silent)."; Dismount-Win11Iso -Path $MediaPath; return $true
                        }
                        if($leaf -ieq "setup.exe"){
                            if(-not(Test-Path -LiteralPath $MediaPath)){throw "setup.exe not found: $MediaPath"}
                            Write-Log "Launching setup.exe..."; Start-Process -FilePath $MediaPath -ArgumentList $args -Wait; Write-Log "Windows Setup started (silent)."; return $true
                        }
                        $setup=Join-Path $MediaPath "setup.exe"; if(-not(Test-Path -LiteralPath $setup)){throw "setup.exe not found in folder: $MediaPath"}
                        Write-Log "Launching setup.exe from folder..."; Start-Process -FilePath $setup -ArgumentList $args -Wait; Write-Log "Windows Setup started (silent)."; return $true
                    }catch{ Write-Log "Upgrade launch failed: $_"; return $false }
                }
                if (-not (Test-Win11Requirements)) { Write-Log "Minimum requirements not met. Aborting."; return }
                [void](Invoke-Win11SetupFromMedia -MediaPath $RemoteMediaPath -Auto:$Auto -DisableDU:$DisableDU)
                $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue
                if ($p) { while (-not $p.HasExited) { Write-Log "Upgrade still in progress..."; Start-Sleep -Seconds 30; $p = Get-Process -Name "setup" -ErrorAction SilentlyContinue } ; Write-Log "Upgrade process exited." }
                else { Write-Log "No setup.exe process detected (hand-off may have occurred)." }
            }
            $auto = [bool]$AutoReboot; $du = [bool]$DisableDynamicUpdate
            Invoke-Command -Session $session -ScriptBlock $RemoteSetupPayload -ArgumentList $remoteDest, $auto, $du, $script:LogFile
            if ($localMapped) { try { Remove-PSDrive -Name $localMapped -Scope Script -Force -ErrorAction SilentlyContinue } catch {} }
        }
    } finally {
        if ($session) { Write-Log "Closing PSSession."; Remove-PSSession $session -ErrorAction SilentlyContinue }
    }
    Write-Log "Windows 11 upgrade (REMOTE) finished for $TargetComputer"
}

Export-ModuleMember -Function Set-Win11UpgradeLogPath, Test-Win11Requirements, Start-Win11UpgradeLocal, Start-Win11UpgradeRemote
