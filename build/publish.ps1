<#
.SYNOPSIS
  Publishes CrioFire (service, desktop app, command line) for one architecture into out\<arch>.

.EXAMPLE
  ./build/publish.ps1 -Arch x64 -Version v0.1.0
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string] $Arch,

    [string] $Version = '0.1.0-dev'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "out/$Arch"
$ver = $Version.TrimStart('v')

if (Test-Path $out) { Remove-Item $out -Recurse -Force }

# All three apps share one self-contained .NET 10 runtime in the same folder.
foreach ($project in 'src/CrioFire.Service', 'src/CrioFire.App', 'src/CrioFire.Cli') {
    dotnet publish (Join-Path $root $project) `
        --configuration Release `
        --runtime "win-$Arch" `
        --self-contained true `
        --output $out `
        -p:Version=$ver `
        -p:DebugType=embedded
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project" }
}

foreach ($exe in 'criofire.exe', 'criofire-ui.exe', 'criofire-svc.exe') {
    if (-not (Test-Path (Join-Path $out $exe))) { throw "Missing $exe in $out" }
}

Write-Host "Published CrioFire $ver for $Arch to $out"
