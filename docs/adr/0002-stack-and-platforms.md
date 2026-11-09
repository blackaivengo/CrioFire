# ADR 0002: Language, UI and platforms

- Status: Accepted
- Date: 2026-11-09

## Decision

- C# on .NET 10 (LTS, supported to November 2028) for the service, app and command line.
- WPF for the desktop app, so it looks and behaves the same on Windows 10 and 11.
- Windows 10 and 11, 64-bit only: x64 and ARM64. Both are built and tested in CI.
- License: GPL-3.0-or-later. Code from other GPL-3.0 firewalls may be reused with attribution.
- Publisher on signed binaries: CrioSoft LLC, via Azure Artifact Signing.

## Naming

Every file name starts with `criofire`: `criofire.exe`, `criofire-ui.exe`, `criofire-svc.exe`,
`criofire.db`, `criofire-<version>-<arch>.msi`. Code namespaces use `CrioFire`. The Windows
service is named `criofire`, the local API pipe is `\\.\pipe\criofire`, and the WFP objects are
`criofire-provider` and `criofire-sublayer`.
