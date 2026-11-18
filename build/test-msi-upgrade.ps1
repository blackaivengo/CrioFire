<#
.SYNOPSIS
  Installs CrioFire over newer, same and older versions of itself, and checks that each time the
  result is one working CrioFire that kept its rules and settings.
  Used by CI on a throwaway runner (after test-msi.ps1); run it only on a machine you can change.

.DESCRIPTION
  From the MSI given it makes two other builds of the same product (msi.dll, build/CrioFireMsi.cs):
  a newer one (version 99.0.0) and a rebuild of the same version (new ProductCode). Then:
    1. install the newer one, and add a rule;
    2. install the MSI over it (a downgrade): it replaces it;
    3. install the same-version rebuild over that: it replaces it;
    4. run the rebuild once more (the very same package): nothing breaks;
    5. uninstall: nothing is left.
  After each step: one "CrioFire Private Firewall" in Apps, the expected version, the service
  running, CrioFire registered with the Windows Filtering Platform, the rule and the sign-in
  entry still there.

.EXAMPLE
  ./build/test-msi-upgrade.ps1 -Msi out/msi/criofire-0.0.1-x64.msi
#>
param(
    [Parameter(Mandatory)]
    [string] $Msi
)

$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
$providerKey = '4e193e29-b3c2-4427-87b8-2d5a349111c4'   # WfpIds.ProviderKey
$work = Join-Path ([IO.Path]::GetTempPath()) "criofire-upgrade-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$logDir = Split-Path -Parent $Msi
$installDir = Join-Path $env:ProgramFiles 'CrioFire'
$cli = Join-Path $installDir 'criofire.exe'

function Write-Annotation([string] $title, [string] $text) {
    if ($env:GITHUB_ACTIONS -eq 'true') {
        $escaped = $text.Replace('%', '%25').Replace("`r", '').Replace("`n", '%0A')
        Write-Host "::error title=$title::$escaped"
    }
}

trap {
    if ($_.Exception.Message -notlike 'FAILED:*' -and $_.Exception.Message -notlike 'msiexec*') {
        Write-Annotation 'Upgrade test failed' "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    }
    break
}

function Check([bool] $condition, [string] $message) {
    if (-not $condition) {
        Write-Annotation 'Upgrade test failed' $message
        throw "FAILED: $message"
    }
    Write-Host "ok   $message"
}

function Invoke-Msi([string] $arguments, [string] $log) {
    $p = Start-Process msiexec.exe -ArgumentList "$arguments /qn /norestart /l*v `"$log`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        $lines = Get-Content $log
        $lines | Select-Object -Last 60 | Write-Host
        $errors = $lines | Select-String -Pattern 'Error \d{4}|error code|CustomAction .* returned actual error|newer version' |
            Select-Object -First 6 | ForEach-Object { $_.Line }
        Write-Annotation 'msiexec failed' ("msiexec $arguments exited with $($p.ExitCode)`n" + ($errors -join "`n"))
        throw "msiexec $arguments failed with exit code $($p.ExitCode)"
    }
}

function Get-Installed {
    @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
        Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'CrioFire Private Firewall' })
}

function Test-ProviderRegistered {
    $state = Join-Path $env:TEMP "wfp-state-$([guid]::NewGuid()).xml"
    netsh wfp show state file="$state" | Out-Null
    try { return [bool](Select-String -Path $state -Pattern $providerKey -SimpleMatch -Quiet) }
    finally { Remove-Item $state -ErrorAction SilentlyContinue }
}

function Check-Installed([string] $version, [string] $step, [bool] $hasRule = $true) {
    $entries = Get-Installed
    Check ($entries.Count -eq 1) "$($step): one CrioFire in Apps ($($entries.Count): $(($entries | ForEach-Object DisplayVersion) -join ', '))"
    Check ($entries[0].DisplayVersion -eq $version) "$($step): version $version is installed ($($entries[0].DisplayVersion))"
    $svc = Get-Service criofire -ErrorAction SilentlyContinue
    Check ($null -ne $svc) "$($step): the criofire service exists"
    try { $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } catch { Write-Host "Service did not reach Running: $_" }
    Check ((Get-Service criofire).Status -eq 'Running') "$($step): the service is running"
    Check (Test-ProviderRegistered) "$($step): CrioFire is registered with the Windows Filtering Platform"
    $modeText = & $cli mode | Out-String
    Check ($modeText -match 'Mode:\s*learning') "$($step): the mode is still learning ($($modeText.Trim()))"
    if ($hasRule) {
        $rules = & $cli list | Out-String
        Check ($rules -match 'Block' -and $rules -notmatch 'No CrioFire rules') "$($step): the rule added earlier is still there"
    }
    $run = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name CrioFire -ErrorAction SilentlyContinue).CrioFire
    Check ($run -match 'criofire-ui\.exe" --tray --machine$') "$($step): the app still starts at sign-in ($run)"
}

Check ((Get-Installed).Count -eq 0) 'no CrioFire is installed before the test'

# The other builds of the same product.
New-Item -ItemType Directory -Force $work | Out-Null
if (-not ('CrioFireMsi' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'CrioFireMsi.cs') }
$version = [CrioFireMsi]::QueryMsi($Msi, "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion'")
$newer = Join-Path $work 'criofire-newer.msi'
$rebuild = Join-Path $work 'criofire-rebuild.msi'
Copy-Item $Msi $newer
Copy-Item $Msi $rebuild
[CrioFireMsi]::MakeVariant($newer, '99.0.0')
[CrioFireMsi]::MakeVariant($rebuild, $null)
Write-Host "Testing version $version against 99.0.0 and a same-version rebuild"

Write-Host '1. A newer version, with a rule'
Invoke-Msi "/i `"$newer`" CRIOFIRE_MODE=learning CRIOFIRE_ALLOW_RUNNING=0 CRIOFIRE_AUTOSTART=1" (Join-Path $logDir 'upgrade-1-newer.log')
Check-Installed '99.0.0' 'newer version' -hasRule $false
& $cli block --tcp --port 9 | Out-Host
Check ($LASTEXITCODE -eq 0) 'a rule can be added'

Write-Host "2. Version $version over the newer one (a downgrade)"
Invoke-Msi "/i `"$Msi`"" (Join-Path $logDir 'upgrade-2-older.log')
Check-Installed $version 'older over newer'

Write-Host "3. A rebuild of version $version over it"
Invoke-Msi "/i `"$rebuild`"" (Join-Path $logDir 'upgrade-3-same-version.log')
Check-Installed $version 'same version, another build'

Write-Host '4. The very same package once more'
Invoke-Msi "/i `"$rebuild`"" (Join-Path $logDir 'upgrade-4-same-package.log')
Check-Installed $version 'same package again'

Write-Host '5. Uninstall'
$productCode = (Get-Installed)[0].PSChildName
Invoke-Msi "/x $productCode" (Join-Path $logDir 'upgrade-5-uninstall.log')
Check ((Get-Installed).Count -eq 0) 'nothing in Apps'
Check ($null -eq (Get-Service criofire -ErrorAction SilentlyContinue)) 'the service is removed'
Check (-not (Test-Path $installDir)) 'the program folder is removed'
Check (-not (Test-ProviderRegistered)) 'CrioFire is unregistered from the Windows Filtering Platform'

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host 'Upgrade test passed.'
