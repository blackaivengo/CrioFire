# CrioFire Private Firewall

A free, open source application firewall for Windows 10 and 11 (x64 and ARM64) that puts every
network connection under your control. Built by CrioSoft LLC with C# and .NET 10, licensed under GPL-3.0.

> **Status: Phase 0 prototype.** The command line can block individual programs through the
> Windows Filtering Platform (WFP). Alerts, the rule editor and the background service's local API
> arrive in Phase 1. Do not rely on it for protection yet.

## What's here

| Path | File | What it is |
| --- | --- | --- |
| `src/CrioFire.Core` | `CrioFire.Core.dll` | WFP bindings and the rule model: provider, sublayer, per-app filters |
| `src/CrioFire.Cli` | `criofire.exe` | Command line for scripting and recovery |
| `src/CrioFire.Service` | `criofire-svc.exe` | Windows service (service name `criofire`), runs as LocalSystem |
| `src/CrioFire.App` | `criofire-ui.exe` | WPF desktop app: alerts, rules, blocked and live connections, mode |
| `tests/CrioFire.Tests` | | Unit tests, including struct-layout checks for the WFP and IP Helper bindings |
| `tests/CrioFire.IntegrationTests` | | Tests against the real filtering engine (admin, `CRIOFIRE_INTEGRATION=1`) |
| `build/publish.ps1` | | Publishes all three apps, self-contained, per architecture |
| `.github/workflows` | | CI on x64 + ARM64; approval-gated signed releases |

## Build

Requirements: Windows 10 or 11 and the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```powershell
dotnet build CrioFire.slnx -c Release
dotnet test CrioFire.slnx -c Release
./build/publish.ps1 -Arch x64      # or arm64; output in out\x64
```

## Try the prototype

From an **administrator** terminal, in the published folder:

```powershell
.\criofire.exe install                                   # register CrioFire with WFP
.\criofire.exe block "C:\Path\To\SomeApp.exe"            # block its outbound traffic
.\criofire.exe list                                      # show CrioFire's filters
.\criofire.exe events                                    # connections CrioFire blocked (last 10 min)
.\criofire.exe unblock "C:\Path\To\SomeApp.exe"          # undo
.\criofire.exe allow "C:\Path\To\Browser.exe"             # allow a program (matters in ask/allowlist)
.\criofire.exe allow "C:\Path\To\Tool.exe" --for 60       # allow for an hour, then the rule is removed
.\criofire.exe mode allowlist --allow-running           # block programs without a rule (asks you to confirm)
.\criofire.exe mode learning                             # back to allowing programs without a rule
.\criofire.exe panic                                     # recovery: remove every CrioFire rule
.\criofire.exe uninstall                                 # remove rules and unregister
```

While the `criofire` service runs, every connection CrioFire blocks is also appended to
`%ProgramData%\criofire\blocked.log` (one JSON object per line; rotated at 10 MB).

### The desktop app

Start `criofire-ui.exe` from the published folder while the `criofire` service runs. It needs no
administrator rights.

- **Mode** picker at the top. Switching to `ask` or `allowlist` offers to allow everything running
  now, then asks you to confirm within 60 seconds that your network still works.
- **Rules**: every allow and block rule, with the time a temporary rule ends. Add a program to
  allow or block, or remove a rule.
- **Blocked**: connections CrioFire stopped in the last hour, and whether your rule or the mode
  stopped them. Allow or keep blocking a program from here.
- **Connections**: live TCP and UDP connections with the program that owns each, updated every 3
  seconds.
- **Alerts** in `ask` mode: a small window in the corner for each program the mode stopped.
  *Allow* and *Block* add a permanent rule; *Allow for 1 hour* adds one that CrioFire removes
  again (`criofire allow <app> --for 60` does the same). Closing the alert means "not now": the
  program stays blocked and you aren't asked again until the app restarts.

Temporary rules are kept in `%ProgramData%\criofire\temporary-rules.json`, so they expire on
time even if the service restarts; the service removes them within a few seconds of expiry.

### Without administrator rights

While the `criofire` service runs, the desktop app and the command line talk to it over a local
named pipe (`\\.\pipe\criofire`), so they work from a normal account:

- Anyone signed in to the PC can read status, rules, mode and blocked connections.
- Changing rules or the mode is allowed for an elevated administrator, or for CrioFire's own
  `criofire.exe` / `criofire-ui.exe` started from the service's install folder (which only
  administrators can write to). Other programs are refused.
- The pipe cannot be reached over the network, and no other program can take over its name.

From an administrator terminal, `criofire` talks to the filtering engine directly, so recovery
commands such as `criofire panic` work even when the service is stopped.

### Modes

| Mode | Programs without a rule | Notes |
| --- | --- | --- |
| `learning` (default) | may connect | nothing is blocked unless a rule says so |
| `ask` | blocked outbound | the app shows an alert for each one: Allow, Allow for 1 hour, or Block |
| `allowlist` | blocked outbound, silently | only programs with an allow rule connect |

In `ask` and `allowlist` CrioFire always lets through loopback (connections that stay on this PC),
Windows services hosted in `svchost.exe` (DNS, DHCP, Windows Update) and the Windows kernel.
Inbound traffic stays under Windows Firewall plus any per-app inbound rules you add.
`--allow-running` first gives every program running now an allow rule, a quick way to start.

Safety by design: switching to `ask` or `allowlist` asks you to confirm within 60 seconds that
your network still works, and switches back if you don't. `criofire panic` always removes every
CrioFire filter, the mode included. Filters are persistent and survive reboots until you remove them.
You can inspect them with `netsh wfp show filters`.

## How it works

CrioFire registers its own WFP provider (`criofire-provider`) and sublayer (`criofire-sublayer`),
then adds filters at the ALE connect (outbound) and receive-accept (inbound) layers for IPv4 and
IPv6, matched on the application's ID. No kernel driver is used; see
[docs/adr/0001-no-kernel-driver.md](docs/adr/0001-no-kernel-driver.md).

## Releases and signing

Releases are built and signed only by GitHub Actions, and only after the maintainer approves the
run. Binaries are signed by **CrioSoft LLC** through Azure Artifact Signing.
See [docs/RELEASING.md](docs/RELEASING.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

CrioFire Private Firewall is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License version 3 or later. See [LICENSE](LICENSE).
Copyright (C) 2026 CrioSoft LLC.
