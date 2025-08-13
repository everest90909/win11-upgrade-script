# Windows 11 In‑Place Upgrade (PowerShell)

This repository contains a robust PowerShell automation that performs an **in‑place upgrade to Windows 11** using either:

1) **Windows Setup (`setup.exe`)** from an **ISO**, a **media folder**, or a direct **`setup.exe`** path, **or**
2) the **Windows 11 Installation Assistant** (downloaded at runtime and launched silently).

The script supports **local** execution and an **orchestrator mode** (run from your admin box) that **copies media to the target** first to avoid the WinRM “double‑hop” problem.

---

## ✨ Highlights

- Full **hardware readiness checks**: TPM 2.0, Secure Boot, CPU (x64/ARM64), RAM ≥ 4 GB, **system drive free space ≥ 64 GB**.
- **Two upgrade paths** in one script:
  - **Setup.exe** from ISO/folder/direct path (mounts/dismounts ISO as needed).
  - **Installation Assistant** (download + quiet switches).
- **Local or Orchestrated remote** execution:
  - Remote mode uses a PSSession, **copies the media to `C:\Temp` on the target**, then runs locally there.
- **UNC-aware**: optional credentials for share access; ISO on a share is **copied locally** before mounting.
- Clear logging to `C:\Windows11UpgradeLog.txt` (and IA copy logs when applicable).

---

## 📁 Script

`upgrade-windows11.ps1`

- **Local mode**: runs checks and upgrade on the current machine.
- **Orchestrator mode**: specify a `-TargetComputer` (FQDN recommended); the script creates a PSSession, copies media (or downloads IA) to the target, runs locally there, and monitors best‑effort.

---

## 🧰 Requirements

- Target device: Windows 10 (upgrading to Windows 11).
- Windows PowerShell **5.1+**.
- Administrator privileges on the target.
- If using media from a UNC path, ensure **share + NTFS read** permissions (or pass `-ShareCredential`).

> Windows Setup is launched with: `/auto upgrade /quiet /noreboot /dynamicupdate enable` by default.  
> You can change reboot/update behavior with switches below.

---

## 🚀 Quick Start

### Local — Using Windows Setup (ISO / folder / setup.exe)

```powershell
# ISO
.\upgrade-windows11.ps1 -MediaPath 'C:\ISO\Win11_24H2_English_x64.iso'

# Folder containing setup.exe
.\upgrade-windows11.ps1 -MediaPath 'D:\Win11_24H2'

# Direct setup.exe
.\upgrade-windows11.ps1 -MediaPath 'D:\Win11_24H2\setup.exe'
```

### Local — Using Installation Assistant (no media needed)

```powershell
.\upgrade-windows11.ps1 -UseInstallationAssistant
```

### Orchestrator — Remote target (copies media to target first)

```powershell
# Setup.exe route (UNC or local media path on your admin box)
.\upgrade-windows11.ps1 `
  -TargetComputer 'PC123.domain.local' `
  -RemoteCredential (Get-Credential) `
  -MediaPath '\\fileserver\dist\Win11_24H2\setup.exe'
```

### Orchestrator — Installation Assistant on remote target

```powershell
.\upgrade-windows11.ps1 `
  -TargetComputer 'PC123.domain.local' `
  -RemoteCredential (Get-Credential) `
  -UseInstallationAssistant
```

> In orchestrator mode, the script creates `C:\Temp\` on the target (if missing), copies media there (or downloads IA), and then runs locally on that machine. This avoids the **double‑hop** issue.

---

## 🔧 Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-MediaPath` | `string` | No* | Path to **.iso**, **setup.exe**, or a **folder** containing `setup.exe`. Local or UNC. *Required for Setup route unless using `-UseInstallationAssistant`. |
| `-UseInstallationAssistant` | `switch` | No | Use the **Windows 11 Installation Assistant** route (download + quiet run). |
| `-TargetComputer` | `string` | No | Run in orchestrator mode against a remote target (FQDN recommended). |
| `-RemoteCredential` | `pscredential` | No | Credential for the PSSession to `-TargetComputer`. |
| `-ShareCredential` | `pscredential` | No | Credential to access a **UNC** media path before copying. |
| `-AutoReboot` | `switch` | No | Setup: remove `/noreboot` so Windows can reboot automatically. |
| `-DisableDynamicUpdate` | `switch` | No | Setup: pass `/dynamicupdate disable`. |
| `-InstallAssistantDownloadURL` | `string` | No | Source URL used to download the Installation Assistant. |
| `-DownloadDestination` | `string` | No | Local path where the IA installer is saved. |
| `-UpdateLogLocation` | `string` | No | Folder for IA copy logs. |

---

## 🧪 What the Script Does

1. **Validates hardware** on the target: TPM 2.0 (SpecVersion), Secure Boot, CPU (x64/ARM64), RAM, and C: space.  
2. **Handles media** (Setup.exe route):
   - ISO on UNC? Copy **locally** first, then mount and run `setup.exe`.
   - Folder or direct `setup.exe`? Use it directly (or copy to target in orchestrator mode).
   - **Dismounts** the ISO after staging (Setup has already copied what it needs).
3. **Installation Assistant route**:
   - Downloads the installer (or uses installed `Windows10UpgraderApp.exe`) and runs quietly with proven args.
4. **Monitors** `setup.exe` best‑effort and logs to `C:\Windows11UpgradeLog.txt` (IA logs go to your `-UpdateLogLocation`).

---

## 🔒 Security Notes

- Use **FQDN** for `-TargetComputer` to ensure Kerberos.  
- Orchestrator mode **does not** require CredSSP, because we copy to the target first.  
- Scheduled tasks should run under a **domain service account** with the necessary rights (avoid `SYSTEM` for network access).

---

## 🗂 Suggested Repo Layout

```
.
├─ upgrade-windows11.ps1
├─ README.md
└─ LICENSE      # optional
```

---

## 🧯 Troubleshooting

- **Access is denied** to a UNC path  
  Ensure share + NTFS read, or pass `-ShareCredential`. In orchestrator mode, media is copied to the target first.

- **Detached HEAD / push errors (git)**  
  Create a branch from your current state and push:  
  `git switch -c fix/update && git push -u origin fix/update`

- **`Confirm-SecureBootUEFI` fails**  
  Run as **Administrator** and ensure **UEFI** boot. The script falls back to `MSFT_SecureBoot` via CIM when possible.

- **Setup exits quickly / process not found**  
  Setup may hand off to other processes. Check `C:\$WINDOWS.~BT\Sources\Panther` and the module log: `C:\Windows11UpgradeLog.txt`.

---

## ⚙️ Customization Tips

- **Auto‑reboot**: add `-AutoReboot`.  
- **Disable dynamic update**: add `-DisableDynamicUpdate`.  
- **Change IA URL/log paths**: override `-InstallAssistantDownloadURL`, `-DownloadDestination`, `-UpdateLogLocation`.

---

## ⚠️ Disclaimer

This script performs an **in‑place OS upgrade**. Test thoroughly before production use. Validate compatibility with your security tooling, disk encryption, and device management stack.
