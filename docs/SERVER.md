# CrioFire Server

CrioFire Server is the company's own server for CrioFire: PCs enroll with it once and then check in
every 5 minutes with a small state report (mode, panic, rule counts, programs that changed, tamper
protection, license): a few hundred bytes, no connection data. What a PC blocked and allowed is sent
only when an administrator asks for it, for that one PC, so even thousands of PCs do not flood the
server. It runs on a machine the company controls; nothing goes to CrioSoft.

> **Status:** step 1 of 4: enrollment and status reporting. Pushing rules (policies), the admin web
> console and an installer for the server follow.

## Set it up (for now, by hand)

On the server machine (Windows 10/11 or Windows Server), from an administrator prompt in the
repository:

```powershell
dotnet publish src/CrioFire.Server -c Release -r win-x64 --self-contained -o "C:\Program Files\CrioFire Server"
sc.exe create criofire-server binPath= "\"C:\Program Files\CrioFire Server\criofire-server.exe\"" start= auto DisplayName= "CrioFire Server"
New-NetFirewallRule -DisplayName "CrioFire Server" -Direction Inbound -Protocol TCP -LocalPort 7443 -Action Allow
sc.exe start criofire-server
```

On first start it makes its own HTTPS certificate (self-signed, 10 years) in
`%ProgramData%\criofire-server`. PCs pin its fingerprint when they enroll, so no certificate
authority is needed. Another port or check-in interval: `%ProgramData%\criofire-server\settings.json`
with `{ "port": 9443, "checkinSeconds": 600 }` (30 to 3600 seconds; default 300).

## Enroll PCs

On the server:

```powershell
& "C:\Program Files\CrioFire Server\criofire-server.exe" token --uses 50 --days 14 --note "Office PCs"
```

It prints the command to run on each PC from an administrator prompt, for example:

```powershell
criofire enroll fw01.contoso.local:7443 cfe_9DDk... --fingerprint 8E:C6:07:...
```

The PC then shows "Managed by the CrioFire Server ..." in Settings, and `criofire server` shows the
last check-in. `criofire unenroll` leaves; the PC's rules stay as they are.

Other server commands: `tokens` (codes that still work), `revoke <id>`, `devices` (enrolled PCs and
their last report), `fingerprint`.

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
- In Ask and Allow-list mode CrioFire has a built-in permit for its own service, so it can always
  reach the server.
