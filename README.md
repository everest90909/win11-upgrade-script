Windows 11 In-Place Upgrade (PowerShell)
Automates a Windows 11 in-place upgrade using Microsoft Setup (setup.exe) from an ISO, a folder, or a direct setup.exe path.
Includes hardware readiness checks (TPM 2.0, Secure Boot, CPU, RAM, storage) and a remote orchestrator mode that avoids the PowerShell “double-hop” problem by copying media to the target before running the upgrade.

✨ Features
✅ TPM 2.0, Secure Boot, CPU (x64/ARM64), RAM (≥4 GB), storage (≥64 GB) checks

✅ Works with ISO / folder / setup.exe (local or UNC)

✅ Remote orchestration: copy media to target, then run locally on the target (no CredSSP required)

✅ ISO on UNC? It’s copied locally to the target before mounting (reliable for SYSTEM/Intune)

✅ Clear logging to C:\Windows11UpgradeLog.txt

✅ Minimal switches on setup.exe for a silent in-place upgrade

🧰 Requirements
Windows 10 device you’re upgrading (target)

PowerShell 5.1+ (Windows PowerShell)

Setup media for Windows 11 (ISO, or a folder containing setup.exe)

Permissions:

Local run: read access to media

Remote run: ability to copy to C:\Temp on the target and execute PowerShell remoting

Secure Boot enabled and TPM 2.0 (script validates)

The script launches Windows Setup with:
/auto upgrade /quiet /noreboot /dynamicupdate enable

📦 Script
upgrade-windows11.ps1

Local mode (default): run on the target device.

Orchestrator mode: run from your admin box and specify -TargetComputer. Script will:

Create a PSSession

Copy media to C:\Temp\… on the target

Run the upgrade locally on the target

Monitor best-effort

🚀 Quick Start
Local (on the target)
powershell
Copy
Edit
# ISO
.\upgrade-windows11.ps1 -MediaPath 'C:\ISO\Win11_24H2_English_x64.iso'

# Folder containing setup.exe
.\upgrade-windows11.ps1 -MediaPath 'D:\Win11_24H2'

# Direct setup.exe
.\upgrade-windows11.ps1 -MediaPath 'D:\Win11_24H2\setup.exe'
Orchestrator (from admin box → remote target)
powershell
Copy
Edit
# Using domain creds to connect to the target
.\upgrade-windows11.ps1 `
  -TargetComputer 'PC123.domain.local' `
  -RemoteCredential (Get-Credential) `
  -MediaPath '\\fileserver\dist\Win11_24H2\setup.exe'
Orchestrator mode copies media to C:\Temp\ on the target to avoid double-hop issues.
If your -MediaPath is a UNC that requires access, you can also pass -ShareCredential for the copy step.

🔧 Parameters
Parameter	Required	Type	Description
-MediaPath	Yes	string	Path to .iso, setup.exe, or a folder containing setup.exe. Local or UNC.
-TargetComputer	No	string	Run in orchestrator mode against a remote target (FQDN recommended).
-RemoteCredential	No	pscredential	Credential used to create the PSSession to the target.
-ShareCredential	No	pscredential	Credential used to access a UNC media path before copying to the target.

📝 What the Script Does (Flow)
Hardware checks on the target:

TPM present/ready/enabled/activated, SpecVersion 2.0

Secure Boot (via Confirm-SecureBootUEFI with a MSFT_SecureBoot fallback)

CPU x64 (9) or ARM64 (12)

RAM ≥ 4 GB

System drive free space ≥ 64 GB

Media handling

If ISO (UNC or local): copies ISO locally to target, mounts, runs setup.exe, then dismounts

If folder: copies folder to C:\Temp\… on target (or uses it directly in local mode)

If setup.exe: copies its entire folder to ensure sources\* is present

Launches setup silently:

/auto upgrade /quiet /noreboot /dynamicupdate enable

Monitors setup.exe process best-effort and logs to C:\Windows11UpgradeLog.txt

🔒 Security & Permissions
Orchestrator mode uses Kerberos by default (-Authentication Kerberos)—use an FQDN for the target.

No CredSSP is required with this approach since the media is copied to the target first.

For scheduled/managed runs, prefer a domain service account with read access to the media and remote admin rights on the target.

🧪 Common Scenarios
Access denied on UNC (local mode)
Use -ShareCredential or copy media locally first.

In a PSSession (double-hop)
Use orchestrator mode with -TargetComputer, which copies media to the target and runs locally there.

ISO on a share
The script automatically copies the ISO to %TEMP% on the target before mounting.

Auto-reboot desired
Remove /noreboot from the setup arguments in the script.

Air-gapped / no updates
Switch /dynamicupdate enable → /dynamicupdate disable.

Lab only (override compatibility)
Add /compat ignorewarning (not recommended for production).

🗂️ Repo Structure (suggested)
bash
Copy
Edit
.
├─ upgrade-windows11.ps1     # Main script
├─ README.md                 # This file
└─ LICENSE                   # (Optional) MIT or your license
📄 Logging
All actions append to: C:\Windows11UpgradeLog.txt

Sample entries:

yaml
Copy
Edit
2025-08-12 13:40:15 - Starting system requirement checks...
2025-08-12 13:40:17 - ✅ TPM 2.0 found and ready.
2025-08-12 13:40:18 - Secure Boot is enabled.
2025-08-12 13:40:20 - x64 processor found.
2025-08-12 13:40:21 - Sufficient free space on C: (180.25 GB >= 64 GB).
2025-08-12 13:40:25 - Launching setup.exe from mounted ISO...
🧯 Troubleshooting
Access is denied (Test-Path / Copy-Item):

Ensure the account has share + NTFS read.

Use -ShareCredential for UNC access.

In orchestrator mode, media is copied to the target first—prefer that.

Could not read from remote repository (git push):

Use HTTPS remote and push with a PAT, or set up SSH keys.

Confirm-SecureBootUEFI fails:

Run as Administrator and ensure system boots in UEFI mode.

Script falls back to MSFT_SecureBoot check.

Setup exits quickly / no process found:

That can happen if Setup hands off; rely on logs and Windows Setup logs in C:\$WINDOWS.~BT\Sources\Panther.

🤝 Contributing
PRs welcome! Please:

Open an issue describing the change/bug.

Target the main branch.

Keep logging consistent and avoid breaking the local/orchestrator flows.

📜 License
MIT — see LICENSE for details.

⚠️ Disclaimer
This script runs an in-place OS upgrade. Test thoroughly in a lab before production.
You are responsible for validating compatibility with your imaging, security, AV, disk encryption, and device management stack.
