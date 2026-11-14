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
| Running app | Asks the app to exit before replacing files (it exits on the end-session message) |

## Languages

One MSI speaks the app's 16 languages and follows the Windows display language (English
otherwise). `build/package-msi.ps1` builds the installer once per language from
`Strings/<culture>.wxl` plus the WiX UI extension's translations, all with the same ProductCode
and the same cabinet, and stores each language in the English MSI as a transform named after its
language ID (regional variants such as es-MX or fr-CA get the nearest one). Windows Installer
applies the matching one by itself; `TRANSFORMS=:<id>` picks one by hand:

```powershell
msiexec /i criofire-0.1.0-x64.msi TRANSFORMS=:1041   # Japanese
```

Every language is stored as UTF-8 (code page 65001), the only one that also covers Hindi and
Bengali. The pages keep the left-to-right layout in Arabic and Urdu (the text itself reads right
to left), as with the WiX UI extension's own Arabic. The license is shown in English. How to change
or add texts: `docs/TRANSLATING.md`. `./build/package-msi.ps1 -EnglishOnly` builds just English,
for a quicker local build.

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

## CrioFire Server installer

`server/CrioFire.Server.Installer.wixproj` builds `criofire-server-<version>-<arch>.msi`, the
company server (see `docs/SERVER.md`).

| Step | Detail |
| --- | --- |
| Files | `%ProgramFiles%\CrioFire Server` (self-contained .NET 10 and ASP.NET Core runtime, the web console) |
| Service | Registers `criofire-server` (LocalSystem, automatic start, restarts if it fails) and starts it |
| Setup | `criofire-server setup --port <port>` (fresh install only): the port, a Windows Firewall rule for it, a data folder only SYSTEM and Administrators can read, and the server's certificate |
| Command line | Adds the install folder to the system `PATH`, so `criofire-server` works in an administrator prompt |
| Finish | "Open the CrioFire Server console now": `https://localhost:<port>/`, where the first administrator is created |
| Uninstall | Removes the service, the program and the firewall rule. `%ProgramData%\criofire-server` (enrolled PCs, policies, administrators, the certificate PCs pinned) is kept, so a reinstall picks up where it left off; delete it to start over |
| Upgrades | Keep the port, the install folder and all data; skip the Server options page |

Wizard: Welcome, License, Install folder, **Server options** (the port, default 7443), Ready, Finish.

| Property | Values | Default |
| --- | --- | --- |
| `CRIOFIRE_SERVER_PORT` | 1 to 65535 | `7443` (on upgrade: the earlier port) |
| `INSTALLFOLDER` | a folder | `%ProgramFiles%\CrioFire Server` |

```powershell
msiexec /i criofire-server-0.1.0-x64.msi /qn CRIOFIRE_SERVER_PORT=7443
```

## Building locally (Windows)

```powershell
./build/publish.ps1 -Arch x64 -Version v0.1.0
./build/package-msi.ps1 -Arch x64 -Version v0.1.0     # out\msi\criofire-0.1.0-x64.msi
./build/test-msi.ps1 -Msi out\msi\criofire-0.1.0-x64.msi   # installs, checks, uninstalls (admin; changes this PC)
./build/package-server-msi.ps1 -Arch x64 -Version v0.1.0     # out\msi\criofire-server-0.1.0-x64.msi
./build/test-server-msi.ps1 -Msi out\msi\criofire-server-0.1.0-x64.msi
```

CI builds all four MSIs on every push, installs the x64 CrioFire one on the runner, checks the
service, the Windows Filtering Platform registration, the mode, the sign-in entry, the shortcut and
`PATH`, then uninstalls it and checks that nothing is left; then again in Hindi, through the
language stored in the MSI. Packaging itself checks that each language's transform is small (texts
only), sets that language and translates the Setup options page. It does the same with the x64 server
MSI: the service, the firewall rule, the data folder's permissions, the console answering over HTTPS
and creating the first administrator, then uninstall (the server's data stays). Releases build the
MSIs from the signed binaries and sign the MSIs too (see `docs/RELEASING.md`).