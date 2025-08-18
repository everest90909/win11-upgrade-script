<#
.SYNOPSIS
Copy a PowerShell script to remote computers (by OU or single computer) and execute it.

.DESCRIPTION
- Primary path uses PowerShell Remoting so the script runs under *your* user context.
- Optional fallback to WMI/UNC (copy + launch) if WinRM is unavailable (runs as SYSTEM).
- Optional Scheduled Task mode to run under a specified user credential (with password).

.EXAMPLES
# 1) OU mode, run as your current domain user via WinRM
.\Invoke-RemoteScript.ps1 -OU "OU=Workstations,OU=Corp,DC=contoso,DC=com" -ScriptPath "C:\Tools\Fix.ps1"

# 2) Single machine
.\Invoke-RemoteScript.ps1 -ComputerName PC-001 -ScriptPath "C:\Tools\Fix.ps1" -ScriptArguments "-Verbose"

# 3) OU mode, run via Scheduled Task with explicit credential
.\Invoke-RemoteScript.ps1 -OU "OU=Servers,DC=contoso,DC=com" -ScriptPath C:\Tools\Fix.ps1 -UseScheduledTask

# 4) Skip WMI fallback and fail fast if WinRM isn't available
.\Invoke-RemoteScript.ps1 -ComputerName PC-001 -ScriptPath .\DoThing.ps1 -SkipWmiFallback
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ByOU')]
param(
    [Parameter(ParameterSetName='ByOU', Mandatory=$true)]
    [string]$OU,

    [Parameter(ParameterSetName='ByComputer', Mandatory=$true)]
    [string]$ComputerName,

    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ScriptPath,

    [string]$RemoteFolder = 'C:\Temp',
    [string]$ScriptArguments = '',
    [switch]$EnabledOnly,

    # Only target Windows 10 machines
    [switch]$Windows10Only,

    [switch]$UseScheduledTask,
    [pscredential]$TaskCredential,
    [switch]$SkipWmiFallback
)

begin {
    $ErrorActionPreference = 'Stop'
    $start = Get-Date
    $results = New-Object System.Collections.Generic.List[object]

    $scriptFullPath = (Resolve-Path -Path $ScriptPath).Path
    $scriptName     = [System.IO.Path]::GetFileName($scriptFullPath)

    function Write-Info {
    param([AllowNull()][object]$msg)
    $text = if ($null -eq $msg -or [string]::IsNullOrWhiteSpace([string]$msg)) { '(no details)' } else { [string]$msg }
    Write-Host "[INFO]  $text" -ForegroundColor Cyan
}

function Write-Ok {
    param([AllowNull()][object]$msg)
    $text = if ($null -eq $msg -or [string]::IsNullOrWhiteSpace([string]$msg)) { '(no details)' } else { [string]$msg }
    Write-Host "[ OK ]  $text" -ForegroundColor Green
}

function Write-Warn {
    param([AllowNull()][object]$msg)
    $text = if ($null -eq $msg -or [string]::IsNullOrWhiteSpace([string]$msg)) { '(no details)' } else { [string]$msg }
    # Avoid null issues by always providing a string
    Write-Warning -Message $text
}

function Write-Err {
    param([AllowNull()][object]$msg)
    $text = if ($null -eq $msg -or [string]::IsNullOrWhiteSpace([string]$msg)) { '(no details)' } else { [string]$msg }
    Write-Host "[ERR ]  $text" -ForegroundColor Red
}

    function Test-HostOnline {
        param([Parameter(Mandatory=$true)][string]$Name, [int]$Count = 2)
        try { return (Test-Connection -ComputerName $Name -Count $Count -Quiet -ErrorAction Stop) }
        catch { return $false }
    }

    # NEW: Confirm Windows 10 using AD hint and remote CIM when needed
    function Test-IsWindows10 {
        param(
            [Parameter(Mandatory=$true)][string]$Computer,
            [string]$ADOperatingSystem
        )

        if ($ADOperatingSystem) {
            if ($ADOperatingSystem -like '*Windows 10*') { return $true }
            if ($ADOperatingSystem -like '*Windows 11*') { return $false }
        }

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop |
                  Select-Object -First 1 Caption, Version
            if ($os.Caption -like '*Windows 10*') { return $true }
            if ($os.Caption -like '*Windows 11*') { return $false }
            return $false
        } catch {
            return $null  # undetermined
        }
    }

    # UPDATED: returns Name + OperatingSystem and supports filtering for Win10
    function Get-ComputersFromOU {
        param(
            [Parameter(Mandatory=$true)][string]$OuDn,
            [switch]$EnabledOnly,
            [switch]$Windows10Only
        )

        try {
            $null = Get-ADOrganizationalUnit -Identity $OuDn -ErrorAction Stop
        } catch {
            throw "OU not found: '$OuDn'. Use DN like `"OU=Workstations,DC=contoso,DC=com`". $_"
        }

        $filter = if ($EnabledOnly) { "Enabled -eq `$true" } else { "*" }
        if ($Windows10Only) {
            if ($filter -eq '*') {
                $filter = "OperatingSystem -like 'Windows 10*'"
            } else {
                $filter = "($filter) -and (OperatingSystem -like 'Windows 10*')"
            }
        }

        $comps = Get-ADComputer -SearchBase $OuDn -Filter $filter -Properties DNSHostName,OperatingSystem |
                 Sort-Object -Property Name |
                 Select-Object Name,OperatingSystem
        return $comps
    }

    function CopyAndRun-OverWinRM {
        param(
            [Parameter(Mandatory=$true)][string]$Computer,
            [Parameter(Mandatory=$true)][string]$LocalScriptPath,
            [Parameter(Mandatory=$true)][string]$RemoteFolder,
            [Parameter(Mandatory=$true)][string]$ScriptArguments,
            [switch]$UseScheduledTask,
            [pscredential]$TaskCredential
        )

        $remoteDest = Join-Path $RemoteFolder ([IO.Path]::GetFileName($LocalScriptPath))
        $taskName = "Run-RemoteScript-" + [Guid]::NewGuid().ToString()

        $session = $null
        try {
            $session = New-PSSession -ComputerName $Computer -ErrorAction Stop

            Invoke-Command -Session $session -ScriptBlock {
                param($path) New-Item -Path $path -ItemType Directory -Force | Out-Null
            } -ArgumentList $RemoteFolder

            Copy-Item -ToSession $session -Path $LocalScriptPath -Destination $remoteDest -Force

            if ($UseScheduledTask) {
                if (-not $TaskCredential) {
                    $TaskCredential = Get-Credential -Message "Enter credentials to run the scheduled task on $Computer"
                }

                $user = $TaskCredential.UserName
                $pwd  = $TaskCredential.GetNetworkCredential().Password

                $exitCode = Invoke-Command -Session $session -ScriptBlock {
                    param($dest,$args,$u,$p,$tn)
                    $action     = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dest`" $args"
                    $principal  = New-ScheduledTaskPrincipal -UserId $u -LogonType Password -RunLevel Highest
                    $settings   = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4)
                    $task       = New-ScheduledTask -Action $action -Principal $principal -Settings $settings

                    Register-ScheduledTask -TaskName $tn -InputObject $task -Password $p -Force | Out-Null
                    Start-ScheduledTask -TaskName $tn

                    do {
                        Start-Sleep -Seconds 5
                        $state = (Get-ScheduledTask -TaskName $tn).State
                    } while ($state -eq 'Running')

                    $info = Get-ScheduledTaskInfo -TaskName $tn
                    Unregister-ScheduledTask -TaskName $tn -Confirm:$false
                    return $info.LastTaskResult
                } -ArgumentList $remoteDest, $ScriptArguments, $user, $pwd, $taskName
            }
            else {
                $exitCode = Invoke-Command -Session $session -ScriptBlock {
                    param($dest,$args)
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = "powershell.exe"
                    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$dest`" $args"
                    $psi.UseShellExecute = $false
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $p.WaitForExit()
                    return $p.ExitCode
                } -ArgumentList $remoteDest, $ScriptArguments
            }

            return [pscustomobject]@{
                Computer   = $Computer
                Method     = if ($UseScheduledTask) {'WinRM+Task'} else {'WinRM'}
                CopiedTo   = $remoteDest
                ExitCode   = $exitCode
                Succeeded  = $true
                Notes      = ''
            }
        }
        catch {
            return [pscustomobject]@{
                Computer   = $Computer
                Method     = 'WinRM'
                CopiedTo   = $remoteDest
                ExitCode   = $null
                Succeeded  = $false
                Notes      = $_.Exception.Message
            }
        }
        finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    }

    function CopyAndRun-FallbackWMI {
        param(
            [Parameter(Mandatory=$true)][string]$Computer,
            [Parameter(Mandatory=$true)][string]$LocalScriptPath,
            [Parameter(Mandatory=$true)][string]$RemoteFolder,
            [Parameter(Mandatory=$true)][string]$ScriptArguments
        )

        $remoteDest = Join-Path $RemoteFolder ([IO.Path]::GetFileName($LocalScriptPath))
        try {
            # Build UNC to C$ properly
            if ($RemoteFolder -notmatch '^[cC]:\\') { throw "Fallback expects a drive-backed path like C:\..." }
            $adminShare   = "\\$Computer\C$"
            $relativePath = $RemoteFolder.Substring(3)  # drop "C:\"
            $destFolderUNC = Join-Path $adminShare $relativePath
            New-Item -ItemType Directory -Path $destFolderUNC -Force | Out-Null

            Copy-Item -Path $LocalScriptPath -Destination (Join-Path $destFolderUNC ([IO.Path]::GetFileName($LocalScriptPath))) -Force -ErrorAction Stop

            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteDest`" $ScriptArguments"
            $r = Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName $Computer -ArgumentList $cmd
            $ok = ($r.ReturnValue -eq 0)

            return [pscustomobject]@{
                Computer   = $Computer
                Method     = 'WMI (SYSTEM)'
                CopiedTo   = $remoteDest
                ExitCode   = if ($ok) { 0 } else { $r.ReturnValue }
                Succeeded  = $ok
                Notes      = if ($ok) { 'Launched under SYSTEM (fallback)' } else { 'WMI Create() failed' }
            }
        }
        catch {
            return [pscustomobject]@{
                Computer   = $Computer
                Method     = 'WMI (SYSTEM)'
                CopiedTo   = $remoteDest
                ExitCode   = $null
                Succeeded  = $false
                Notes      = $_.Exception.Message
            }
        }
    }
}

process {
    # Build targets
    if ($PSCmdlet.ParameterSetName -eq 'ByOU') {
        try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "ActiveDirectory module is required. $_" }
        $targets = Get-ComputersFromOU -OuDn $OU -EnabledOnly:$EnabledOnly -Windows10Only:$Windows10Only
        if (-not $targets -or $targets.Count -eq 0) {
            $why = if ($Windows10Only) { " matching Windows 10" } else { "" }
            throw "No computers resolved from OU '$OU'$why (EnabledOnly=$EnabledOnly)."
        }
    } else {
        # Single computer; include AD OS hint if available
        $adOS = (Get-ADComputer -Identity $ComputerName -Properties OperatingSystem -ErrorAction SilentlyContinue).OperatingSystem
        $targets = @([pscustomobject]@{ Name = $ComputerName; OperatingSystem = $adOS })
    }

    Write-Info "Starting copy+execute to $($targets.Count) computer(s). Source: $scriptFullPath"
    Write-Info "Remote folder: $RemoteFolder"
    if ($Windows10Only) { Write-Info "Windows10Only filter is ON." }
    if ($UseScheduledTask) { Write-Info "Scheduled Task mode enabled (credential required)." }

    foreach ($t in $targets) {
        $c    = $t.Name
        $adOS = $t.OperatingSystem

        Write-Host "---- $c ----" -ForegroundColor Yellow

        if (-not (Test-HostOnline -Name $c)) {
            $results.Add([pscustomobject]@{ Computer=$c; Method='N/A'; CopiedTo=''; ExitCode=$null; Succeeded=$false; Notes='Host offline/unreachable' }) | Out-Null
            Write-Warn "$c is offline. Skipping."
            continue
        }

        # NEW: skip non-Windows 10 if requested
        if ($Windows10Only) {
            $is10 = Test-IsWindows10 -Computer $c -ADOperatingSystem $adOS
            if ($is10 -eq $false) {
                $results.Add([pscustomobject]@{ Computer=$c; Method='N/A'; CopiedTo=''; ExitCode=$null; Succeeded=$false; Notes='Skipped: not Windows 10' }) | Out-Null
                Write-Info "$c is not Windows 10. Skipping."
                continue
            }
            elseif ($is10 -eq $null) {
                $results.Add([pscustomobject]@{ Computer=$c; Method='N/A'; CopiedTo=''; ExitCode=$null; Succeeded=$false; Notes='Skipped: OS undetermined (firewall or permissions)' }) | Out-Null
                Write-Warn "$c OS undetermined (CIM access failed). Skipping."
                continue
            }
        }

        if ($PSCmdlet.ShouldProcess($c, "Copy and execute $scriptName")) {
            $r = CopyAndRun-OverWinRM -Computer $c -LocalScriptPath $scriptFullPath -RemoteFolder $RemoteFolder -ScriptArguments $ScriptArguments -UseScheduledTask:$UseScheduledTask -TaskCredential $TaskCredential
            if (-not $r.Succeeded -and -not $SkipWmiFallback) {
                Write-Warn "WinRM path failed on $c ($($r.Notes)). Trying WMI/UNC fallback (runs as SYSTEM)."
                $r = CopyAndRun-FallbackWMI -Computer $c -LocalScriptPath $scriptFullPath -RemoteFolder $RemoteFolder -ScriptArguments $ScriptArguments
            }

            if ($r.Succeeded) { Write-Ok "$c -> Success via $($r.Method). ExitCode: $($r.ExitCode)" }
            else              { Write-Err "$c -> Failed. $($r.Notes)" }

            $results.Add($r) | Out-Null
        }
    }
}

end {
    $stop = Get-Date
    Write-Host ""
    Write-Host "===== Summary ($($start.ToString('u')) → $($stop.ToString('u'))) =====" -ForegroundColor White
    $ok   = ($results | ? {$_.Succeeded}).Count
    $fail = ($results | ? {-not $_.Succeeded}).Count
    "{0} total | {1} succeeded | {2} failed" -f $results.Count,$ok,$fail | Write-Host

    $results | Sort-Object Computer | Format-Table Computer,Method,CopiedTo,ExitCode,Succeeded,Notes -AutoSize
}
