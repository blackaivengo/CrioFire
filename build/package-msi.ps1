<#
.SYNOPSIS
  Builds the CrioFire MSI for one architecture from a published folder.

.DESCRIPTION
  Run build/publish.ps1 first (or point -PublishDir at a folder of signed binaries).
  Output: out\msi\criofire-<version>-<arch>.msi

.EXAMPLE
  ./build/publish.ps1 -Arch x64 -Version v0.1.0
  ./build/package-msi.ps1 -Arch x64 -Version v0.1.0
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string] $Arch,

    [string] $Version = '0.1.0-dev',

    [string] $PublishDir
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $PublishDir) { $PublishDir = Join-Path $root "out/$Arch" }
$PublishDir = (Resolve-Path $PublishDir).Path

foreach ($exe in 'criofire.exe', 'criofire-ui.exe', 'criofire-svc.exe') {
    if (-not (Test-Path (Join-Path $PublishDir $exe))) { throw "Missing $exe in $PublishDir. Run build/publish.ps1 first." }
}

# Windows Installer versions are numeric (major.minor.build): drop any "-prerelease" suffix.
$numeric = ($Version.TrimStart('v') -split '[-+]')[0]
if ($numeric -notmatch '^\d+\.\d+\.\d+$') { throw "Version '$Version' must start with major.minor.patch, e.g. v0.1.0" }

$out = Join-Path $root 'out/msi'
New-Item -ItemType Directory -Force $out | Out-Null

dotnet build (Join-Path $root 'installer/CrioFire.Installer.wixproj') `
    --configuration Release `
    -p:InstallerPlatform=$Arch `
    -p:ProductVersion=$numeric `
    -p:CrioFirePublishDir=$PublishDir `
    -p:OutputPath="$out\"
if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }

$msi = Join-Path $out "criofire-$numeric-$Arch.msi"
if (-not (Test-Path $msi)) { throw "Expected $msi was not produced" }
Write-Host "Built $msi"
