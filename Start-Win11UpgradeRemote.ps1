<#  Upgrade Windows 10 → 11 across an OU
    Requirements:
      - RSAT ActiveDirectory module installed on the machine running this
      - WinRM enabled on targets (PowerShell remoting)
      - Your account (or supplied credential) is local admin on targets
      - Import the Win11Upgrade module (v1.2.2 or newer) first
#>

Import-Module ActiveDirectory
Import-Module .\Win11Upgrade.psm1 -Force     # path to the module you downloaded

# ======= EDIT THESE =======
$OuDn                  = 'OU=Workstations,OU=Corp,DC=contoso,DC=com'
$UseInstallationAssistant = $true            # $true = use Installation Assistant; $false = use Setup.exe media
$MediaPath             = '\\fileserver\dist\Win11_24H2\Win11_24H2.iso'  # used only if $UseInstallationAssistant:$false
$ShareCredential       = $null               # if MediaPath is a UNC and needs alternate creds: Get-Credential
$RemoteCredential      = Get-Credential      # creds with admin rights on targets
$PerHostLogFolder      = 'C:\Win11UpgradeLogs'
$ResultCsv             = 'C:\Win11UpgradeResults.csv'
# ==========================

# Prepare results
$results = New-Object System.Collections.Generic.List[object]

# Pull candidate computers from AD (filter to Windows 10 to reduce noise; we’ll still verify on-box)
$adComputers = Get-ADComputer -SearchBase $OuDn -LDAPFilter '(&(objectClass=computer)(operatingSystem=Windows 10*))' `
                -Properties operatingSystem,operatingSystemVersion,dNSHostName

foreach ($c in $adComputers) {
    $name = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }
    $row  = [ordered]@{
        ComputerName  = $name
        Ping          = $false
        WinRM         = $false
        AD_OS         = $c.operatingSystem
        Remote_OS     = $null
        UpgradeStart  = (Get-Date)
        UpgradeTried  = $false
        Result        = 'Skipped'
        Notes         = $null
        LogPath       = $null
    }

    try {
        # Quick reachability
        if (-not (Test-Connection -ComputerName $name -Count 1 -Quiet)) {
            $row.Ping  = $false
            $row.Notes = "Unreachable (ICMP)."
            $results.Add([pscustomobject]$row)
            continue
        }
        $row.Ping = $true

        # WinRM ready?
        try {
            Test-WSMan -ComputerName $name -ErrorAction Stop | Out-Null
            $row.WinRM = $true
        } catch {
            $row.Notes = "WinRM not available: $($_.Exception.Message)"
            $results.Add([pscustomobject]$row)
            continue
        }

        # Confirm it is actually Windows 10 on the target (AD can be stale)
        $remoteOs = Invoke-Command -ComputerName $name -Credential $RemoteCredential -ScriptBlock {
            (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
        }
        $row.Remote_OS = $remoteOs

        if ($remoteOs -notlike '*Windows 10*') {
            $row.Result = "Skipped (Remote OS is not Windows 10: $remoteOs)"
            $results.Add([pscustomobject]$row)
            continue
        }

        # Set a unique per-host log path used by the module’s remote payload
        $hostLog = Join-Path $PerHostLogFolder "$($name)-Win11Upgrade.log"
        if (-not (Test-Path -LiteralPath (Split-Path $hostLog -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $hostLog -Parent) -Force | Out-Null
        }
        Set-Win11UpgradeLogPath -Path $hostLog
        $row.LogPath = $hostLog

        # Kick off the upgrade
        $row.UpgradeTried = $true
        if ($UseInstallationAssistant) {
            Start-Win11UpgradeRemote -TargetComputer $name `
                -RemoteCredential $RemoteCredential `
                -UseInstallationAssistant `
                -ErrorAction Stop
        } else {
            Start-Win11UpgradeRemote -TargetComputer $name `
                -RemoteCredential $RemoteCredential `
                -MediaPath $MediaPath `
                -ShareCredential $ShareCredential `
                -ErrorAction Stop
        }

        $row.Result = 'Started'
        $results.Add([pscustomobject]$row)
    }
    catch {
        $row.Result = 'Error'
        $row.Notes  = $_.Exception.Message
        $results.Add([pscustomobject]$row)
        continue
    }
}

# Save outcomes
$results | Export-Csv -NoTypeInformation -Path $ResultCsv
Write-Host "Done. Results saved to $ResultCsv"
