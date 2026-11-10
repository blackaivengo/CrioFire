# CrioFire Private Firewall

An application firewall for Windows 10 and 11 (x64 and ARM64) that puts every network connection
under your control. Built by CrioSoft LLC with C# and .NET 10. Source-available: free for personal
use, non-profits, schools, government and businesses on up to 3 computers; other business use needs
a yearly license per computer (see [LICENSING.md](LICENSING.md)).

> **Status: pre-release.** The service, command line, desktop app and installer work end to end
> through the Windows Filtering Platform (WFP), but there is no signed release yet. Do not rely on
> it for protection yet.

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

## Install

Download `criofire-<version>-x64.msi` (or `-arm64.msi` for ARM PCs) from the GitHub Releases page
and run it. Setup asks how CrioFire should start (Learning, Ask or Allow-list), whether to allow the
programs already running, and whether to start the app at sign-in. Silent installs and all options:
see [installer/README.md](installer/README.md). Uninstalling removes every CrioFire rule.

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
.\criofire.exe block --in --tcp --port 445              # block a port inbound, for every program
.\criofire.exe allow "C:\Path\To\Chat.exe" --port 443   # with "block <app>": the app may use port 443 only
.\criofire.exe block --addr 203.0.113.0/24              # block an address range outbound
.\criofire.exe remove <filter-id>                        # remove a rule (all its filters) by an ID from list
.\criofire.exe mode allowlist --allow-running           # block programs without a rule (asks you to confirm)
.\criofire.exe mode learning                             # back to allowing programs without a rule
.\criofire.exe panic                                     # recovery: remove every CrioFire rule
.\criofire.exe uninstall                                 # remove rules and unregister
```

**Network rules** (`--port`, `--addr`, `--tcp`, `--udp`, optionally with a program) match by
port and remote address. Ports are the remote port for outbound connections and the local port for
inbound ones; lists and ranges work (`80,443,8000-8100`). Addresses can be single IPv4/IPv6
addresses, CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`) or ranges (`10.0.0.1-10.0.0.50`). When rules
overlap, the more specific one wins: program + port/address, then port/address, then a plain program
rule; between equally specific rules, block wins.

While the `criofire` service runs, every connection CrioFire blocks is also appended to
`%ProgramData%\criofire\blocked.log` (one JSON object per line; rotated at 10 MB).

### The desktop app

Start `criofire-ui.exe` from the published folder while the `criofire` service runs. It needs no
administrator rights. Its look is ice and fire: light blue means allowed or safe, fire red means
blocked, on glass panels that glow softly in their color. Light and dark themes follow Windows by
default; switch with the sun/moon button or in **Settings** (remembered per user in
`%LocalAppData%\CrioFire\ui.txt`).

- **Dashboard**: the protection ring and mode (Learning / Ask / Allow-list), blocked connections
  over the last 24 hours, the programs blocked most, programs waiting for your decision, and live
  connections. Switching to Ask or Allow-list offers to allow everything running now, then asks you
  to confirm within 60 seconds that your network still works.
- **Activity**: connections blocked in the last hour; allow a program, allow it for an hour, or keep it blocked.
- **Rules**: program rules (with the time a temporary rule ends) and network rules; allow or block a
  program, add a network rule (port, address, protocol, direction, optionally one program, with a
  plain-language preview), or remove one.
- **Connections**: live TCP and UDP connections with the program that owns each, every 3 seconds.
- **Reports**: the last 24 hours, 7 days or 30 days: totals compared with the period before,
  blocked connections per hour or day (your rules vs. no rule yet), the programs and destinations
  blocked most, outbound vs. inbound. **Export CSV** for spreadsheets; **Save as PDF** prints the
  report (choose "Microsoft Print to PDF").
- **Alerts** in `ask` mode: a window in the corner for each program the mode stopped.
  *Allow* and *Block* add a permanent rule; *Allow 1 hour* adds one that CrioFire removes again
  (`criofire allow <app> --for 60` does the same). Press and hold *Allow 1 hour* for 15 minutes,
  30 minutes or 24 hours (or use the arrow keys): release over one to pick it, then press the button
  again to confirm. Closing the alert means "not now": the program stays blocked and waits on the
  dashboard.
- **Notification area**: the CrioFire flame sits next to the clock. It turns gray when the service
  isn't running and shows a red dot when programs wait for your decision. Click it to open the
  app; right-click to switch mode, start with Windows, or exit. Closing the window keeps CrioFire
  in the notification area (Settings can turn that off); exiting the app never stops the firewall
  service. Only one copy of the app runs: starting it again brings the window forward.
- **Start with Windows**: Settings, the tray menu, or the offer when you first switch to Ask mode.
  It adds `criofire-ui.exe --tray` to your user's startup programs (HKCU `Run`), so alerts work
  right after you sign in.

Reports come from the service's log of blocked connections (`%ProgramData%\criofire\blocked.log`,
plus `blocked.1.log` after it rotates at 10 MB). Temporary rules are kept in
`%ProgramData%\criofire\temporary-rules.json`, so they expire on time even if the service restarts.

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

Copyright (C) 2026 CrioSoft LLC. CrioFire is licensed under the
[PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) with
CrioSoft's additional permissions for small businesses (up to 3 computers) and a 30-day business
evaluation; see [LICENSE](LICENSE). It is free for personal use, charities, schools, public research,
public safety, health and environmental organizations, and government institutions.

Other business or commercial use needs a CrioSoft Commercial License, priced per protected computer
per year: see [LICENSING.md](LICENSING.md) for who pays and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)
for the terms. Versions published before November 2026 remain available under GPL-3.0 to those who
received them.
