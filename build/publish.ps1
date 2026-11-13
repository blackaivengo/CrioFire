<#
.SYNOPSIS
  Publishes CrioFire (service, desktop app, command line) for one architecture into out\<arch>,
  and CrioFire Server into out\server-<arch>.

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
$serverOut = Join-Path $root "out/server-$Arch"
$ver = $Version.TrimStart('v')

foreach ($dir in $out, $serverOut) {
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
}

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

# Licences go with the programs: CrioFire's own, and the notices of the open-source parts it includes.
foreach ($doc in 'LICENSE', 'THIRD-PARTY-NOTICES.md') {
    Copy-Item (Join-Path $root $doc) (Join-Path $out $doc) -Force
}

# CrioFire Server: its own folder (with its own runtime, including ASP.NET Core) and its own installer.
dotnet publish (Join-Path $root 'src/CrioFire.Server') `
    --configuration Release `
    --runtime "win-$Arch" `
    --self-contained true `
    --output $serverOut `
    -p:Version=$ver `
    -p:DebugType=embedded
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed for src/CrioFire.Server' }
foreach ($file in 'criofire-server.exe', 'wwwroot/index.html', 'wwwroot/app.js') {
    if (-not (Test-Path (Join-Path $serverOut $file))) { throw "Missing $file in $serverOut" }
}
foreach ($doc in 'LICENSE', 'THIRD-PARTY-NOTICES.md') {
    Copy-Item (Join-Path $root $doc) (Join-Path $serverOut $doc) -Force
}

Write-Host "Published CrioFire $ver for $Arch to $out, and CrioFire Server to $serverOut"
