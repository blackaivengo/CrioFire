<#
.SYNOPSIS
  Builds the CrioFire MSI for one architecture from a published folder.

.DESCRIPTION
  Run build/publish.ps1 first (or point -PublishDir at a folder of signed binaries).
  Output: out\msi\criofire-<version>-<arch>.msi

  One MSI in 16 languages. The installer is built once per language (installer\Strings\*.wxl),
  then each language is stored in the English MSI as a transform named after its language ID.
  Windows Installer applies the one that matches the Windows display language (an undocumented
  but long-standing feature: the languages are listed in the package's Template summary property),
  and TRANSFORMS=:<LCID> picks one by hand, e.g. msiexec /i criofire.msi TRANSFORMS=:1081.

  All languages share the ProductCode and the very same cabinet (the cabinet cache is seeded with
  the English one), so each transform only carries texts.

.EXAMPLE
  ./build/publish.ps1 -Arch x64 -Version v0.1.0
  ./build/package-msi.ps1 -Arch x64 -Version v0.1.0
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string] $Arch,

    [string] $Version = '0.1.0-dev',

    [string] $PublishDir,

    # Just English, for a quicker local build.
    [switch] $EnglishOnly
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

# The installer's languages (the app's 16) and their Windows language IDs. English is the base.
$languages = [ordered]@{
    'en-US' = 1033; 'zh-CN' = 2052; 'hi-IN' = 1081; 'es-ES' = 3082; 'ar-SA' = 1025; 'fr-FR' = 1036
    'bn-BD' = 2117; 'pt-BR' = 1046; 'ru-RU' = 1049; 'id-ID' = 1057; 'ur-PK' = 1056; 'de-DE' = 1031
    'ja-JP' = 1041; 'tr-TR' = 1055; 'ko-KR' = 1042; 'vi-VN' = 1066
}
# Windows Installer only picks a transform whose ID is exactly the display language, so the same
# transform is also stored under the IDs of common regional variants (like the app's own choice).
$variants = @{
    'zh-CN' = @(4100)                         # Chinese (Singapore)
    'es-ES' = @(1034, 2058, 21514, 58378)     # traditional sort, Mexico, United States, Latin America
    'ar-SA' = @(3073, 14337)                  # Egypt, United Arab Emirates
    'fr-FR' = @(3084, 2060, 4108)             # Canada, Belgium, Switzerland
    'bn-BD' = @(1093)                         # India
    'pt-BR' = @(2070)                         # Portugal
    'ur-PK' = @(2080)                         # India
    'de-DE' = @(3079, 2055)                   # Austria, Switzerland
}
if ($EnglishOnly) { $languages = [ordered]@{ 'en-US' = 1033 } }

# Failures become GitHub annotations, so they can be read on the run page without signing in.
function Write-Annotation([string] $text) {
    if ($env:GITHUB_ACTIONS -eq 'true') {
        $escaped = $text.Replace('%', '%25').Replace("`r", '').Replace("`n", '%0A')
        Write-Host "::error title=MSI packaging failed ($Arch)::$escaped"
    }
}
trap {
    Write-Annotation "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    break
}

# Windows Installer's own functions (msi.dll), for making, checking and storing the transforms.
if (-not ('CrioFireMsi' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'CrioFireMsi.cs') }

$out = Join-Path $root 'out/msi'
$work = Join-Path $root "out/msi-work/$Arch"
$cabCache = Join-Path $work 'cabcache'
New-Item -ItemType Directory -Force $out | Out-Null
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force $work | Out-Null

$productCode = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
$fileName = "criofire-$numeric-$Arch.msi"

foreach ($culture in $languages.Keys) {
    if ($culture -ne 'en-US') {
        # Reuse the English cabinet: same bytes, so the transforms do not carry the program files.
        $cabinets = @(Get-ChildItem (Join-Path $cabCache 'en-US') -Filter *.cab -ErrorAction SilentlyContinue)
        if ($cabinets.Count -eq 0) { throw "The English build left no cabinet in $cabCache\en-US to reuse" }
        New-Item -ItemType Directory -Force (Join-Path $cabCache $culture) | Out-Null
        $cabinets | Copy-Item -Destination (Join-Path $cabCache $culture)
    }
    Write-Host "Building the $culture installer"
    # The Windows Installer validation (ICE) checks the structure, which every language shares.
    $suppressValidation = if ($culture -eq 'en-US') { 'false' } else { 'true' }
    $output = & dotnet build (Join-Path $root 'installer/CrioFire.Installer.wixproj') `
        --configuration Release `
        -p:InstallerPlatform=$Arch `
        -p:ProductVersion=$numeric `
        -p:ProductCode=$productCode `
        -p:CrioFireCulture=$culture `
        -p:SuppressValidation=$suppressValidation `
        -p:CrioFirePublishDir=$PublishDir `
        -p:CabinetCachePath="$cabCache\" `
        -p:OutputPath="$work\out\$culture\" 2>&1
    $output | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        $errors = @($output | Select-String -Pattern ': (error|warning) ' | Select-Object -First 8 | ForEach-Object { $_.Line.Trim() })
        throw "The $culture MSI build failed:`n$($errors -join "`n")"
    }
    # Each language builds into a folder of its own and is copied out right away: a build's
    # incremental clean deletes what an earlier build left in its output folder.
    $built = Join-Path $work "out/$culture/$culture/$fileName"
    if (-not (Test-Path $built)) { throw "Expected $built was not produced" }
    Copy-Item $built (Join-Path $work "$culture.msi")
}

$msi = Join-Path $out $fileName
Copy-Item (Join-Path $work 'en-US.msi') $msi -Force

if ($languages.Count -gt 1) {
    $titleQuery = "SELECT ``Text`` FROM ``Control`` WHERE ``Dialog_``='CrioFireSettingsDlg' AND ``Control``='Title'"
    $languageQuery = "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductLanguage'"
    $englishTitle = [CrioFireMsi]::QueryMsi($msi, $titleQuery)
    $names = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()

    foreach ($culture in @($languages.Keys | Where-Object { $_ -ne 'en-US' })) {
        $lcid = $languages[$culture]
        $mst = Join-Path $work "$culture.mst"
        if (-not [CrioFireMsi]::MakeTransform($msi, (Join-Path $work "$culture.msi"), $mst)) { throw "The $culture MSI does not differ from the English one" }

        # Check it: small (texts only), and it really switches the language and the texts.
        $size = (Get-Item $mst).Length
        if ($size -gt 2MB) { throw "The $culture transform is $([math]::Round($size / 1MB, 1)) MB: it carries more than texts" }
        $scratch = Join-Path $work "check-$culture.msi"
        Copy-Item $msi $scratch
        $language, $title = [CrioFireMsi]::QueryTransformed($scratch, $mst, @($languageQuery, $titleQuery))
        Remove-Item $scratch
        if ($language -ne "$lcid") { throw "The $culture transform sets ProductLanguage $language, not $lcid" }
        if ($title -eq $englishTitle) { throw "The $culture transform leaves the Setup options page in English ($title)" }

        Write-Host ("{0} ({1}): {2:N0} KB" -f $culture, $lcid, ($size / 1KB))
        foreach ($id in @($lcid) + @($variants[$culture] | Where-Object { $_ })) {
            $names.Add("$id")
            $files.Add($mst)
        }
    }

    # English first in the Template property: the default when no other language matches.
    $template = [CrioFireMsi]::Embed($msi, $names.ToArray(), $files.ToArray(), ((@('1033') + $names) -join ','))
    Write-Host "Languages: $template"
}

# The per-language MSIs are unsigned leftovers; release signing checks every criofire-*.msi under out\.
Remove-Item -Recurse -Force $work
Write-Host "Built $msi"
