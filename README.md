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
| `src/CrioFire.Server` | `criofire-server.exe` | The company's own CrioFire Server: PCs enroll and report to it, with a web console for administrators (see [docs/SERVER.md](docs/SERVER.md)) |
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

Businesses managing many PCs also install `criofire-server-<version>-x64.msi` on one machine: a
company server with a web console for policies, enrollment, status and the license
(see [docs/SERVER.md](docs/SERVER.md)).

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
.\criofire.exe allowed                                   # what was allowed to connect, and why (last hour)
.\criofire.exe block --service DiagTrack                 # block one Windows service, even inside svchost.exe
.\criofire.exe block System --in                         # rules for the Windows kernel use the name "System"
.\criofire.exe auto                                      # the automatic rules; "auto svchost off" turns one off
.\criofire.exe export my-rules.json                       # save every rule to a file
.\criofire.exe import my-rules.json --dry-run             # what an import would change (--replace removes others)
.\criofire.exe backups                                   # automatic backups; "restore <name>" puts one back
.\criofire.exe enroll fw01:7443 <code> --fingerprint <fp>   # let the company's CrioFire Server manage this PC
.\criofire.exe license <key>                              # enter a business license key (free use needs none)
.\criofire.exe protection on                             # tamper protection: rule changes need administrator approval
.\criofire.exe changed                                   # allowed programs whose file changed since you allowed them
.\criofire.exe trust "C:\Path\To\Chat.exe"              # you checked it: allow the changed program again
.\criofire.exe mode allowlist --allow-running           # block programs without a rule (asks you to confirm)
.\criofire.exe mode learning                             # back to allowing programs without a rule
.\criofire.exe panic                                     # allow everything; your rules are paused, not deleted
.\criofire.exe panic block                               # block all network traffic (loopback still works)
.\criofire.exe resume                                    # end panic: your rules apply again
.\criofire.exe panic remove                              # last resort: delete every CrioFire rule
.\criofire.exe uninstall                                 # remove rules and unregister
```

**Tamper protection.** By default CrioFire's own app and command line (from the install folder) may
change rules for any signed-in user, so a harmful program running as that user could start
`criofire.exe` to allow itself. With tamper protection on (Settings, or `criofire protection on`
from an administrator prompt), every change needs an elevated CrioFire: the app asks Windows for
approval (UAC) for each change, and the command line needs an administrator prompt. Turning it off
needs approval too. The service's data folder is writable only by administrators and the service.

**Backups.** The service saves the rules to `%ProgramData%\criofire\backups` whenever they change
(checked every 5 minutes), and before every import or "remove all rules"; the newest 30 are kept.
Export and Import (on the Rules page, or `criofire export|import`) move rules between PCs as a
readable JSON file. Import merges by default; Replace also removes rules that are not in the file.

**Microsoft Store apps** live in a folder named after their exact version, so CrioFire keys their
rules by package family instead of path (`pkg:Microsoft.WindowsTerminal_8wekyb3d8bbwe`): a filter
on the package SID covers sandboxed Store apps, plus one per program file for desktop apps from the
Store. The service renews these rules within a minute when the app updates. Allowing or blocking a
program inside `WindowsApps` makes this kind of rule automatically.

**Program identity.** When you allow a program, CrioFire records who signed it (its Authenticode
publisher) and a SHA-256 fingerprint of the file. The service checks allowed programs every 30
seconds: a new version from the same publisher is accepted, as that is how programs update; another
publisher, a lost signature, or new contents of an unsigned program count as a change. In Ask and
Allow-list mode the program is then blocked until you allow it again (`criofire trust`, or Review in
the app); in Learning mode it is reported only. Files in the Windows folder and the kernel are not
checked.

**Network rules** (`--port`, `--addr`, `--tcp`, `--udp`, optionally with a program) match by
port and remote address. Ports are the remote port for outbound connections and the local port for
inbound ones; lists and ranges work (`80,443,8000-8100`). Addresses can be single IPv4/IPv6
addresses, CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`) or ranges (`10.0.0.1-10.0.0.50`). When rules
overlap, the more specific one wins: program + port/address, then port/address, then a plain program
rule; between equally specific rules, block wins.

While the `criofire` service runs, every connection CrioFire blocks is also appended to
`%ProgramData%\criofire\blocked.log` (one JSON object per line), and every
connection that was **allowed** goes to `allowed.log`, summed per minute, with the reason: your
program, service or network rule, an automatic rule (Windows services, Windows kernel), loopback,
or no rule at all (Learning mode, or inbound traffic left to Windows Firewall). For svchost.exe the
service also notes which Windows service owned the socket, when it is still open.

**History settings** (Settings → Connection history, or `criofire logs`): how long connections are
kept (7, 30, 90 days or a year; any 1 to 3650 days with `criofire logs --keep <days>`; 30 by default),
how much each log may use (20 MB by default, the previous file `*.1.log` included; `--size <MB>`),
and whether allowed connections are recorded at all (`--allowed off`: Traffic and Reports then show
blocked connections only). Older lines are removed every hour; the settings live in
`%ProgramData%\criofire\log-settings.txt`. *Clear history* (`criofire logs --clear`) forgets every
recorded connection; like rule changes, these need administrator approval when tamper protection is on.

### Seeing and controlling everything

Nothing that reaches the network is hidden, including what CrioFire or Windows allows by default:

- **Activity → Allowed** lists every program and service that connected in the last hour, in or
  out, with the reason and a count; **Block it** or **Always allow** works on any row.
- **Windows services** get their own rules (`criofire block --service <name>`, or *Service rule...*
  in the app), matched by the service SID, so one service can be blocked without touching the others
  in the same svchost.exe. A service rule beats a rule for svchost.exe and the automatic rules.
- **The Windows kernel** ("System": file sharing, NetBIOS, ICMP) can be allowed or blocked like a program.
- **Networks**: any rule can apply only on some kinds of network, as Windows classifies them: home
  and work (private, domain) or public (cafés, hotels, unknown networks). Elsewhere the mode decides.
  E.g. block file sharing on public networks only: `criofire block --in --tcp --port 445 --networks public`,
  or right-click a rule → *Networks*. Settings shows which networks the PC is on now.
- **Domains**: block or allow a site by name, with every name under it: `criofire block --domain
  doubleclick.net`, or *Domain rule...* on the Rules page (optionally for one program or some networks).
  The filtering platform only sees addresses, so the service follows Windows' own name lookups and
  adds a filter for the addresses each lookup of a covered name (or its CNAME) returns; an address
  drops out an hour after the last lookup that returned it. The more specific domain wins when rules
  overlap. Limits: sites sharing an address with a blocked domain are blocked too, and lookups an
  application makes on its own (a browser's secure DNS) are not seen.
- **Automatic rules** are listed under Rules and can be switched off (`criofire auto svchost off`);
  the choice is kept in `%ProgramData%\criofire\auto-rules.txt`. Loopback and inbound handling are
  shown there too.
- **Local network shortcut**: one switch (Rules → Automatic rules, or `criofire auto lan on`) lets every
  program reach your own network in Ask and Allow-list modes: printers, file shares, casting, smart-home
  devices (private, link-local, multicast and broadcast addresses). It applies on home and work
  networks only, never on public ones, and a program you blocked stays blocked. Off until you turn it on.
- **Data used per program**: Connections → *Data used* (or `criofire usage [today|7d|30d]`) shows how
  much each program sent and received today or over the last 7 or 30 days, most first. The service
  reads Windows' own network events (Microsoft-Windows-Kernel-Network: process id and byte count of
  every TCP and UDP send and receive) and keeps only per-program daily totals for 31 days, in
  `%ProgramData%\criofire\data-usage.json`. Traffic that stays on the PC (loopback) is not counted;
  Windows services that share a svchost.exe are counted together. *Clear counts* (or
  `criofire usage --reset`) starts again from zero.
- **Updates**: once a day the service asks GitHub Releases whether a newer CrioFire is out (the
  request carries nothing about the PC or its rules; the service's own connections are allowed in
  every mode). A newer version shows a banner and one notification, with a link to the release page;
  nothing is downloaded or installed. Settings → Updates, or `criofire updates off`, turns it off;
  `criofire version --check` asks once. Administrators can turn it off for a PC with the DWORD
  `DisableUpdateCheck` = 1 under `HKLM\SOFTWARE\Policies\CrioSoft\CrioFire`.
- **Dashboard and Reports** show allowed traffic next to blocked traffic: totals, how much was
  allowed automatically, the programs and services allowed most, the reasons and destinations, and
  the same in the CSV export.

### The desktop app

Start `criofire-ui.exe` from the published folder while the `criofire` service runs. It needs no
administrator rights. Its look is ice and fire: light blue means allowed or safe, fire red means
blocked, on glass panels that glow softly in their color. Light and dark themes follow Windows by
default; switch with the sun/moon button or in **Settings** (remembered per user in
`%LocalAppData%\CrioFire\ui.txt`).

The app follows the Windows display language when it is one of its 16 (English, Chinese
(Simplified), Hindi, Spanish, Arabic, French, Bengali, Portuguese (Brazil), Russian, Indonesian,
Urdu, German, Japanese, Turkish, Korean, Vietnamese), else English; **Settings → Language** picks
another. The command line and the service stay in English. See [docs/TRANSLATING.md](docs/TRANSLATING.md).

- **Dashboard**: the protection ring and mode (Learning / Ask / Allow-list), blocked connections
  over the last 24 hours, the programs blocked most, programs waiting for your decision, and live
  connections. Switching to Ask or Allow-list offers to allow everything running now, then asks you
  to confirm within 60 seconds that your network still works. Click any panel, or a program in one,
  to open its full list in Activity.
- **Activity**: every blocked and allowed connection the service recorded, grouped by program or
  service, destination, port and reason. Filter by blocked / allowed, the last hour to 30 days,
  direction, reason (your rules, no rule, automatic, local only, panic) and search text, 100 rows a
  page. Select one or many rows (Ctrl, Shift, or *Select page*) to allow, allow for an hour, or
  block them at once: blocked rows stopped by a port/address rule remove that rule, svchost.exe rows
  get a service rule. The details pane shows the program (description, publisher, version), its
  Windows services, the remote address with host name and whether it is local or on the internet,
  the port and its usual service, the local endpoint, why it was blocked or allowed, the rules that
  apply, and what the program has open right now; open its file location or copy the details.
- **Rules**: *What is blocked* at the top lists every port and address a rule blocks (click one to
  see the rules behind it) and how many programs and services are blocked. Below, program, port and
  address, and service rules, filtered by text (a program, service, port such as 445, or address such
  as 10.0.0.5, also inside ranges), allow/block, direction and kind, and sorted by any column. Click
  a rule's Allow or Block chip to switch it; select several to switch or remove them at once; the
  right-click menu also changes the direction. Add program, network and service rules from the top.
- **Connections**: live TCP and UDP connections with the program, and for svchost.exe the services,
  that own each, every 3 seconds; allow or block the selected one. *Data used* lists how much each
  program sent and received today, in 7 days or in 30 days, with its share of the total.
- **Reports**: the last 24 hours, 7 days or 30 days: totals compared with the period before,
  blocked connections per hour or day (your rules vs. no rule yet), the programs and destinations
  blocked most, outbound vs. inbound, and what was allowed and why. **Export CSV** for spreadsheets;
  **Save as PDF** writes a print-ready PDF (US Letter) with CrioFire Private Firewall and CrioSoft LLC
  on every page, page numbers, and every table continued over as many pages as it needs, column
  headings repeated; it ends with the rules in force when it was made.
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
plus `blocked.1.log` after it rotates, as the history settings allow). Temporary rules are kept in
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

In `ask` and `allowlist` CrioFire lets through loopback (connections that stay on this PC) and, by
default, Windows services hosted in `svchost.exe` (DNS, DHCP, Windows Update) and the Windows kernel.
Both can be switched off, a third one (the local network, on home and work networks) can be switched
on, and everything they allow is listed under Activity → Allowed.
Inbound traffic stays under Windows Firewall plus any per-app inbound rules you add.
`--allow-running` first gives every program running now an allow rule, a quick way to start.

Safety by design: switching to `ask` or `allowlist` asks you to confirm within 60 seconds that
your network still works, and switches back if you don't. Filters are persistent and survive reboots
until you remove them.

### Panic

When something can't connect, or something is connecting that shouldn't, panic (the **Panic...**
button in the app, or `criofire panic`) offers three ways out:

| Choice | What happens | Your rules |
| --- | --- | --- |
| Allow everything (`panic`, `panic allow`) | Every connection in and out is allowed | Kept, paused |
| Block all network traffic (`panic block`) | No new connection in or out; traffic that stays on this PC still works; connections already open are not cut | Kept, overridden |
| Remove all rules (`panic remove`) | Every CrioFire filter is deleted, mode back to Learning | Deleted, cannot be undone |

The first two add one filter per layer above every rule and change nothing else, so **Resume**
(`criofire resume`) brings back exactly the rules, mode and automatic rules there were before. Panic
stays on across restarts until you resume; the app shows a banner and the tray icon a red dot meanwhile.
You can inspect them with `netsh wfp show filters`.

## How it works

**What the service sees of your browsing.** For domain rules, the service reads Windows' name lookups
as they complete (a real-time event trace of the DNS client). Each lookup is compared with your domain
rules in memory and then dropped: nothing is written to disk or sent anywhere, and when there are no
domain rules the lookups are not even compared.

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
