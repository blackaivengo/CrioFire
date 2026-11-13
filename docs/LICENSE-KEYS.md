# License keys (for CrioSoft)

Businesses with more than 3 computers enter a license key in CrioFire (Settings, License, or
`criofire license <key>`). CrioFire checks the key itself, offline: the key is signed with
CrioSoft's private key, and CrioFire carries the matching public key. No activation server.

A key looks like `CRIOFIRE1.<payload>.<signature>`. The payload says who the license is for, the
edition (business, provider or trial), the number of computers, and when it expires. An expired
license never switches protection off: CrioFire keeps working and says the license expired.

## One-time setup: the signing key

Do this once, on a computer you trust, with the key folder **outside this repository** (a USB stick
kept offline is best):

```powershell
dotnet run --project tools/CrioFire.LicenseTool -- newkey E:\criofire-license
```

It asks for a password (at least 12 characters) and creates:

- `criofire-license-private.pem`: the private key, encrypted with the password. Keep it and the
  password safe, with a second copy somewhere else. If it is lost, no new keys can be issued for
  the CrioFire versions already out; if it leaks, anyone can make keys.
- `LicensePublicKey.pem`: copy it over `src/CrioFire.Core/LicensePublicKey.pem` and commit it.
  Builds from then on can check keys.

## Issuing a key

```powershell
dotnet run --project tools/CrioFire.LicenseTool -- issue --key E:\criofire-license\criofire-license-private.pem `
    --to "Contoso Ltd" --seats 25 --email it@contoso.example
```

Defaults: business edition, 12 months (`--months`, `--days`); `--edition trial` defaults to 30 days,
`--edition provider` is for IT service providers. Every key issued is also recorded in
`issued-licenses.csv` next to the private key. Send the customer the key line.

Check a key: `criofire-license verify <key>` (with the key built in) or
`verify <key> --public E:\criofire-license\LicensePublicKey.pem`.

## Counting computers

A key states how many computers it covers. A single PC cannot count the others, so standalone PCs
only show the license. The CrioFire Server (admin console) will count the managed PCs against it.
