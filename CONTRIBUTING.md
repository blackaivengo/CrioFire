# Contributing to CrioFire Private Firewall

Thanks for helping. CrioFire changes how a PC talks to the network, so changes are reviewed
with safety first.

## Ground rules

- Open an issue before large changes, so we can agree on the approach.
- Keep pull requests focused; include tests for logic that can run without admin rights.
- Never add a filter that can block all traffic without a recovery path (`criofire panic` must
  always undo it).
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

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Contributions are licensed under GPL-3.0-or-later, the project's license.
