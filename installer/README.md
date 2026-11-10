# CrioFire installer

`CrioFire.Installer.wixproj` builds a Windows Installer package per architecture,
`criofire-<version>-x64.msi` and `criofire-<version>-arm64.msi`, with the WiX Toolset v7.
WiX v7 is used under its Open Source Maintenance Fee EULA, accepted by CrioSoft LLC
(`<AcceptEula>wix7</AcceptEula>` in the project); organizations above the EULA's revenue threshold
pay the monthly maintenance fee. See https://docs.firegiant.com/wix/osmf/.

## What the installer does

| Step | Detail |
| --- | --- |
| Files | `%ProgramFiles%\CrioFire` (self-contained .NET 10 runtime included, nothing else to install) |
| Service | Registers `criofire` (`criofire-svc.exe`, LocalSystem, automatic start, depends on BFE, restarts if it fails) and starts it |
| Firewall | `criofire setup`: registers CrioFire with the Windows Filtering Platform and sets the starting mode (fresh install only) |
| Command line | Adds the install folder to the system `PATH`, so `criofire` works in any terminal |
| Start menu | "CrioFire Private Firewall" shortcut to `criofire-ui.exe` |
| Data folder | `%ProgramData%\criofire` (traffic log, temporary rules): SYSTEM and Administrators full control, Users read-only |
| Sign-in start | Optional `HKLM\...\Run` entry, `criofire-ui.exe --tray --machine`: the app starts in the notification area for everyone. Each user can turn it off in Settings |
| Uninstall | Runs `criofire uninstall --remove-data`: removes every CrioFire filter, the WFP provider and sublayer, and the data folder, then the service and files |
| Upgrades | A newer MSI upgrades in place and keeps rules, mode, the install folder and the sign-in choice, and skips the Setup options page; downgrades are refused |
| Running app | Asks the app to exit before replacing files, and ends it if it does not within 5 seconds |

## Setup wizard

Welcome, License, Install folder, **Setup options**, Ready, Finish (with "Open CrioFire now").
The welcome page and banners carry the CrioFire ice-and-fire look (`Assets/Dialog.bmp`,
`Assets/Banner.bmp`); the license page is generated from `LICENSE` by `build/license-rtf.py`.

Setup options:

- When a program without a rule connects out: **Learning** (default), **Ask**, or **Allow-list only**
- Allow the programs that are running now (default on; only for Ask and Allow-list)
- Start CrioFire in the notification area when anyone signs in (default on)

Everything can be changed later in the app.

## Silent and managed installs

All options are Windows Installer properties:

| Property | Values | Default |
| --- | --- | --- |
| `CRIOFIRE_MODE` | `learning`, `ask`, `allowlist` | `learning` |
| `CRIOFIRE_ALLOW_RUNNING` | `1` or `0` | `1` |
| `CRIOFIRE_AUTOSTART` | `1` or `0` | `1` (on upgrade: the earlier choice) |
| `INSTALLFOLDER` | a folder | `%ProgramFiles%\CrioFire` |

```powershell
msiexec /i criofire-0.1.0-x64.msi /qn CRIOFIRE_MODE=ask
msiexec /x criofire-0.1.0-x64.msi /qn
```

## Building locally (Windows)

```powershell
./build/publish.ps1 -Arch x64 -Version v0.1.0
./build/package-msi.ps1 -Arch x64 -Version v0.1.0     # out\msi\criofire-0.1.0-x64.msi
./build/test-msi.ps1 -Msi out\msi\criofire-0.1.0-x64.msi   # installs, checks, uninstalls (admin; changes this PC)
```

CI builds both MSIs on every push, installs the x64 one on the runner, checks the service, the
Windows Filtering Platform registration, the mode, the sign-in entry, the shortcut and `PATH`, then
uninstalls it and checks that nothing is left. Releases build the MSIs from the signed binaries and
sign the MSIs too (see `docs/RELEASING.md`).
