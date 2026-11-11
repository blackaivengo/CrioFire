# Contributing to CrioFire Private Firewall

Thanks for helping. CrioFire changes how a PC talks to the network, so changes are reviewed
with safety first.

## Ground rules

- Open an issue before large changes, so we can agree on the approach.
- Keep pull requests focused; include tests for logic that can run without admin rights.
- Never add a filter that can block all traffic without a recovery path (`criofire panic remove`
  must always undo it, and `criofire panic` must let everything through above it).
- Changes to `src/CrioFire.Core/Interop` must keep `InteropLayoutTests` passing and cite the
  Windows SDK definition they follow.

## Sign your commits (DCO)

By contributing you certify the [Developer Certificate of Origin](https://developercertificate.org/).
Add a sign-off line to every commit:

```
git commit -s -m "Describe the change"
```

## Build and test

```powershell
dotnet build CrioFire.slnx -c Release
dotnet test CrioFire.slnx -c Release
```

`tests/CrioFire.IntegrationTests` really blocks and unblocks a small test program
(`CrioFire.TestPeer.exe`) through the Windows Filtering Platform and checks that its connections
fail and recover: outbound and inbound, IPv4 and IPv6, loopback and internet. They change the
machine's firewall, so they skip unless you opt in from an **administrator** terminal:

```powershell
$env:CRIOFIRE_INTEGRATION = '1'
dotnet test tests/CrioFire.IntegrationTests -c Release
```

Each test removes everything it adds; if a run is interrupted, `criofire uninstall` cleans up.
CI runs them on every push on x64 and ARM64 (GitHub's Windows runners are administrators).

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

CrioFire is source-available under the PolyForm Noncommercial License 1.0.0 with CrioSoft's additional
permissions (see [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md)). Because CrioSoft also sells commercial
licenses, contributors agree to the [Contributor License Agreement](CLA.md): state in your first pull request
"I have read the CrioFire Contributor License Agreement and agree to it."
