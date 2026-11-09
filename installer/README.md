# Installer (Phase 1)

Planned: a WiX MSI per architecture, `criofire-<version>-x64.msi` and
`criofire-<version>-arm64.msi`, that installs to `%ProgramFiles%\CrioFire`, registers the
`criofire` Windows service, creates `%ProgramData%\criofire\`, and on uninstall runs
`criofire uninstall` so no filters are left behind.

Phase 0 releases ship signed zip files instead.
