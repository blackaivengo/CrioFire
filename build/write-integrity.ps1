<#
.SYNOPSIS
  Writes integrity.json into a published CrioFire folder: every file with its SHA-256 and size.

.DESCRIPTION
  The criofire service compares its folder with this list (shortly after it starts, every 6
  hours, and on "criofire verify") to tell whether the files are the ones CrioFire was built and
  installed with. Run it after the files are final: for a release, after they are signed.
  build/publish.ps1 and build/package-msi.ps1 both run it.

.EXAMPLE
  ./build/write-integrity.ps1 -Folder out/x64 -Version v0.1.0
#>
param(
    [Parameter(Mandatory)]
    [string] $Folder,

    [string] $Version = '0.1.0-dev'
)

$ErrorActionPreference = 'Stop'
$Folder = (Resolve-Path $Folder).Path
$manifest = Join-Path $Folder 'integrity.json'
if (Test-Path $manifest) { Remove-Item $manifest -Force }

$files = @(Get-ChildItem $Folder -Recurse -File | Sort-Object FullName | ForEach-Object {
    [ordered]@{
        path   = $_.FullName.Substring($Folder.Length).TrimStart('\', '/').Replace('\', '/')
        sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size   = $_.Length
    }
})
if ($files.Count -eq 0) { throw "No files in $Folder" }

$json = [ordered]@{
    version    = $Version.TrimStart('v')
    createdUtc = [DateTime]::UtcNow.ToString('o')
    files      = $files
} | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($manifest, $json, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $manifest ($($files.Count) files)"
