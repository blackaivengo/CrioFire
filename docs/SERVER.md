# CrioFire Server

CrioFire Server is the company's own server for CrioFire: PCs enroll with it once and then check in
every 5 minutes with a small state report (mode, panic, rule counts, programs that changed, tamper
protection, license): a few hundred bytes, no connection data. What a PC blocked and allowed is sent
only when an administrator asks for it, for that one PC, so even thousands of PCs do not flood the
server. It runs on a machine the company controls; nothing goes to CrioSoft.

It comes with a web console for administrators, an installer, and the organization's license,
which the server hands to every PC.

## Install it

On the server machine (Windows 10/11 or Windows Server 2016 or later, 64-bit), run
`criofire-server-<version>-x64.msi` from the GitHub Releases page. It asks for the port (default
7443), then:

- installs `%ProgramFiles%\CrioFire Server` and the `criofire-server` service (starts with Windows),
- allows the port in Windows Firewall (allow it in any other firewall between PCs and the server),
- makes the server's own HTTPS certificate (self-signed, 10 years) in `%ProgramData%\criofire-server`,
  a folder only SYSTEM and administrators can read,
- opens the console in your browser on the server, where you create the first administrator.

The browser warns about the certificate the first time, because the server made it itself. Check
that the fingerprint the browser shows matches `criofire-server fingerprint`, then accept it. PCs pin
that fingerprint when they enroll, so no certificate authority is needed.

Silent install: `msiexec /i criofire-server-<version>-x64.msi /qn CRIOFIRE_SERVER_PORT=7443`, then
create the first administrator with `criofire-server admin add <name>`. More in
[installer/README.md](../installer/README.md).

Uninstalling removes the program, the service and the firewall rule, and keeps the data folder
(enrolled PCs, policies, administrators, the certificate PCs pinned): reinstall and everything is
as it was. Delete `%ProgramData%\criofire-server` to start over.

Settings: `%ProgramData%\criofire-server\settings.json`, e.g. `{ "port": 9443, "checkinSeconds": 600 }`
(check-ins every 30 to 3600 seconds; default 300). To change the port later, run
`criofire-server setup --port 9443` (it also updates the firewall rule), restart the service, and
re-enroll PCs with the new address.

<details><summary>Without the installer</summary>

```powershell
dotnet publish src/CrioFire.Server -c Release -r win-x64 --self-contained -o "C:\Program Files\CrioFire Server"
& "C:\Program Files\CrioFire Server\criofire-server.exe" setup --port 7443
sc.exe create criofire-server binPath= "\"C:\Program Files\CrioFire Server\criofire-server.exe\"" start= auto DisplayName= "CrioFire Server"
sc.exe start criofire-server
```

</details>

## The admin console

Everything below can be done in a browser at `https://<server>:7443/`. The first administrator is
created in the browser on the server itself (from any other PC the console only says how), or with
`criofire-server admin add <name>` from an administrator prompt on the server.

- **Overview**: how many PCs are online, need attention or are offline, and why (panic on, programs
  changed since they were allowed, a policy not applied yet, an expired license...).
- **Computers**: search and filter the PCs; select some, all shown, or one, and apply a policy, remove
  it, or remove the PCs from the server. Click a PC for its details, to change its policy, or to ask
  it for what it blocked and allowed.
- **Policies**: create and edit policies (mode, whether users may add rules, tamper protection, the
  automatic Windows rules, and program, port/address, service and domain rules, each optionally for
  some kinds of network only), add rules from a file made
  with `criofire export`, apply a policy to all, some or one PC, and choose the one new PCs get.
- **Add computers**: make an enrollment code and copy the command to run on each PC.
- **License**: enter the organization's license key and see how many seats are used.
- **Administrators**: add and remove administrators, change your password.

Other administrator commands: `admin list`, `admin remove <name>`, `admin password <name>`.

The console signs you out after 8 hours without use. Sign-in tries are limited to 10 a minute per
address, and the console's pages only run their own scripts (a strict Content Security Policy).
Allow port 7443 only from the networks your PCs and administrators are on.

## Enroll PCs

In the console, **Add computers** makes a code and shows the command; or, on the server:

```powershell
criofire-server token --uses 50 --days 14 --note "Office PCs"
```

It prints the command to run on each PC from an administrator prompt, for example:

```powershell
criofire enroll fw01.contoso.local:7443 cfe_9DDk... --fingerprint 8E:C6:07:...
```

The PC then shows "Managed by the CrioFire Server ..." in Settings, and `criofire server` shows the
last check-in. `criofire unenroll` leaves; the PC's rules stay as they are.

Other server commands: `tokens` (codes that still work), `revoke <id>`, `devices` (enrolled PCs and
their last report), `fingerprint`.

## Policies: the organization's rules

A policy is a set of rules (made with `criofire export` on a PC set up the way you want), plus what
users may still change. Assign it to PCs; they apply it at their next check-in, and again whenever
you change it.

```powershell
criofire-server policy create "Office" --rules office-rules.json --mode ask
criofire-server policy create "Kiosk" --rules kiosk-rules.json --mode allowlist --lock --protect
criofire-server policy assign pol_1a2b3c4d PC-042 PC-043      # or --all
criofire-server policy default pol_1a2b3c4d                   # what new PCs get when they enroll
criofire-server policy update pol_1a2b3c4d --rules office-rules-v2.json
criofire-server policy list
```

- **Organization rules always win.** They live in their own filter sublayer above the user's: an
  organization block beats any user allow, and an organization allow is a hard permit that user
  blocks cannot override. Only panic "block everything" beats them.
- `--mode` sets the mode on every PC with the policy (users cannot change it); without it, users choose.
- `--lock` removes users' own rules (a backup is kept on the PC) and lets them add none.
  Without it, users may add their own rules next to the organization's.
- `--protect` switches tamper protection on and keeps it on.
- Rules for programs that are not installed on a PC are skipped there.
- Unassigning a policy (`assign none ...`) or deleting it removes its rules from the PCs at their
  next check-in; `criofire unenroll` on a PC removes them at once. The user's own rules stay.

## The license

Enter the organization's CrioFire business license once, on the server (the License page, or
`criofire-server license <key>`). The server gives it to every PC at its next check-in, so nobody
enters the key on each PC; PCs check CrioSoft's signature themselves before using it. A renewed key
reaches every PC the same way.

Seats are counted against the enrolled PCs: the overview and the License page say when more PCs are
enrolled than the license covers. Nothing stops working when that happens, or when a license
expires; the console just says so. `criofire-server license` shows the same from the command line;
`criofire-server license --remove` stops handing out the key (PCs keep the one they have).

## See what one PC blocked and allowed

```powershell
criofire-server activity PC-042 --hours 24 --kind all     # ask; the PC answers after its next check-in
criofire-server activity PC-042 --show                    # what it sent
```

The PC sends its connections grouped by program, destination and reason, most frequent first (up to
500 rows). The server refuses connection data nobody asked for.

## Security

- Enrollment codes and device secrets are random (192 and 256 bits) and stored only as SHA-256
  hashes on the server. On the PC, the secret is in `%ProgramData%\criofire\server.json`, readable
  only by SYSTEM and administrators.
- All traffic is HTTPS; with `--fingerprint` the PC accepts only the server's own certificate.
- Administrator passwords are stored as salted PBKDF2-SHA256 hashes (210,000 iterations) in
  `%ProgramData%\criofire-server\admins.json`. The console's sign-in cookie is HTTPS-only and not
  readable by scripts; its keys are protected with Windows DPAPI.
- In Ask and Allow-list mode CrioFire has a built-in permit for its own service, so it can always
  reach the server.
