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
        New-Item -ItemType Directory -Force (Join-Path $cabCache $culture) | Out-Null
        Copy-Item (Join-Path $cabCache 'en-US/*.cab') (Join-Path $cabCache $culture)
    }
    Write-Host "Building the $culture installer"
    # The Windows Installer validation (ICE) checks the structure, which every language shares.
    $suppressValidation = if ($culture -eq 'en-US') { 'false' } else { 'true' }
    dotnet build (Join-Path $root 'installer/CrioFire.Installer.wixproj') `
        --configuration Release `
        -p:InstallerPlatform=$Arch `
        -p:ProductVersion=$numeric `
        -p:ProductCode=$productCode `
        -p:CrioFireCulture=$culture `
        -p:SuppressValidation=$suppressValidation `
        -p:CrioFirePublishDir=$PublishDir `
        -p:CabinetCachePath="$cabCache\" `
        -p:OutputPath="$work\"
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed ($culture)" }
    if (-not (Test-Path (Join-Path $work "$culture/$fileName"))) { throw "Expected $work\$culture\$fileName was not produced" }
}

$msi = Join-Path $out $fileName
Copy-Item (Join-Path $work "en-US/$fileName") $msi -Force

if ($languages.Count -gt 1) {
    # Windows Installer's automation interface, through late binding (it has no type library).
    function Invoke-Method($object, [string] $name, [object[]] $arguments = @()) {
        $object.GetType().InvokeMember($name, [Reflection.BindingFlags]::InvokeMethod, $null, $object, $arguments)
    }
    function Get-Property($object, [string] $name, [object[]] $arguments = @()) {
        $object.GetType().InvokeMember($name, [Reflection.BindingFlags]::GetProperty, $null, $object, $arguments)
    }
    function Set-Property($object, [string] $name, [object[]] $arguments) {
        [void] $object.GetType().InvokeMember($name, [Reflection.BindingFlags]::SetProperty, $null, $object, $arguments)
    }
    function Get-Value($database, [string] $query) {
        $view = Invoke-Method $database 'OpenView' @($query)
        Invoke-Method $view 'Execute' | Out-Null
        $record = Invoke-Method $view 'Fetch'
        $value = if ($record) { Get-Property $record 'StringData' @(1) } else { $null }
        Invoke-Method $view 'Close' | Out-Null
        Close-Com $record
        Close-Com $view
        return $value
    }
    function Close-Com($object) {
        if ($object) { [void] [Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
    }

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $readOnly = 0; $transact = 1; $msiViewModifyAssign = 3
    $base = Invoke-Method $installer 'OpenDatabase' @($msi, $readOnly)
    $englishTitle = Get-Value $base "SELECT ``Text`` FROM ``Control`` WHERE ``Dialog_``='CrioFireSettingsDlg' AND ``Control``='Title'"
    $transforms = [ordered]@{}

    foreach ($culture in @($languages.Keys | Where-Object { $_ -ne 'en-US' })) {
        $lcid = $languages[$culture]
        $mst = Join-Path $work "$culture.mst"
        $localized = Invoke-Method $installer 'OpenDatabase' @((Join-Path $work "$culture/$fileName"), $readOnly)
        # The transform turns the English MSI into this language's. No validation and no error
        # conditions, so it always applies to the package it is stored in.
        if (-not (Invoke-Method $localized 'GenerateTransform' @($base, $mst))) { throw "No differences between English and $culture" }
        Invoke-Method $localized 'CreateTransformSummaryInfo' @($base, $mst, 0, 0) | Out-Null
        Close-Com $localized

        # Check it: small (texts only), and it really switches the language and the texts.
        $size = (Get-Item $mst).Length
        if ($size -gt 2MB) { throw "The $culture transform is $([math]::Round($size / 1MB, 1)) MB: it carries more than texts" }
        $check = Join-Path $work "check-$culture.msi"
        Copy-Item $msi $check
        $db = Invoke-Method $installer 'OpenDatabase' @($check, $transact)
        Invoke-Method $db 'ApplyTransform' @($mst, 0) | Out-Null
        $language = Get-Value $db "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductLanguage'"
        $title = Get-Value $db "SELECT ``Text`` FROM ``Control`` WHERE ``Dialog_``='CrioFireSettingsDlg' AND ``Control``='Title'"
        Close-Com $db
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        Remove-Item $check -ErrorAction SilentlyContinue
        if ($language -ne "$lcid") { throw "The $culture transform sets ProductLanguage $language, not $lcid" }
        if ($title -eq $englishTitle) { throw "The $culture transform leaves the Setup options page in English" }

        Write-Host ("{0} ({1}): {2:N0} KB" -f $culture, $lcid, ($size / 1KB))
        $transforms["$lcid"] = $mst
        foreach ($variant in @($variants[$culture])) { if ($variant) { $transforms["$variant"] = $mst } }
    }
    Close-Com $base
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()

    # Store each transform as a substorage named after its language ID, and list the languages
    # (English first: the default) in the Template summary property.
    $db = Invoke-Method $installer 'OpenDatabase' @($msi, $transact)
    $view = Invoke-Method $db 'OpenView' @('SELECT `Name`, `Data` FROM `_Storages`')
    Invoke-Method $view 'Execute' | Out-Null
    foreach ($name in $transforms.Keys) {
        $record = Invoke-Method $installer 'CreateRecord' @(2)
        Set-Property $record 'StringData' @(1, $name)
        Invoke-Method $record 'SetStream' @(2, $transforms[$name]) | Out-Null
        Invoke-Method $view 'Modify' @($msiViewModifyAssign, $record) | Out-Null
        Close-Com $record
    }
    Invoke-Method $view 'Close' | Out-Null
    Close-Com $view

    $summary = Get-Property $db 'SummaryInformation' @(1)
    $platform = ((Get-Property $summary 'Property' @(7)) -split ';')[0]
    $template = "$platform;" + ((@('1033') + @($transforms.Keys)) -join ',')
    Set-Property $summary 'Property' @(7, $template)
    Invoke-Method $summary 'Persist' | Out-Null
    Close-Com $summary
    Invoke-Method $db 'Commit' | Out-Null
    Close-Com $db
    Close-Com $installer
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    Write-Host "Languages: $template"
}

# The per-language MSIs are unsigned leftovers; release signing checks every criofire-*.msi under out\.
Remove-Item -Recurse -Force $work
Write-Host "Built $msi"
