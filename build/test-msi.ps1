<#
.SYNOPSIS
  Installs a CrioFire MSI silently, checks the result, uninstalls it, and checks nothing is left.
  Used by CI on a throwaway runner; run it only on a machine you can change (administrator).

.EXAMPLE
  ./build/test-msi.ps1 -Msi out/msi/criofire-0.0.1-x64.msi
#>
param(
    [Parameter(Mandatory)]
    [string] $Msi,

    # Learning by default: a blocking mode would cut off a CI runner's own connections.
    [ValidateSet('learning', 'ask', 'allowlist')]
    [string] $Mode = 'learning'
)

$ErrorActionPreference = 'Stop'
$providerKey = '4e193e29-b3c2-4427-87b8-2d5a349111c4'   # WfpIds.ProviderKey
$logDir = Split-Path -Parent $Msi
$installDir = Join-Path $env:ProgramFiles 'CrioFire'
$cli = Join-Path $installDir 'criofire.exe'

# Failures become GitHub annotations, so they can be read on the run page without signing in.
function Write-Annotation([string] $title, [string] $text) {
    if ($env:GITHUB_ACTIONS -eq 'true') {
        $escaped = $text.Replace('%', '%25').Replace("`r", '').Replace("`n", '%0A')
        Write-Host "::error title=$title::$escaped"
    }
}

function Invoke-Msi([string] $arguments, [string] $log) {
    $p = Start-Process msiexec.exe -ArgumentList "$arguments /qn /norestart /l*v `"$log`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        $lines = Get-Content $log
        $lines | Select-Object -Last 60 | Write-Host
        # The interesting part of a verbose MSI log is just before the first "Return value 3".
        $failed = ($lines | Select-String -Pattern 'Return value 3' -SimpleMatch | Select-Object -First 1).LineNumber
        $context = if ($failed) { $lines[[Math]::Max(0, $failed - 25)..($failed - 1)] } else { $lines | Select-Object -Last 25 }
        $errors = $lines | Select-String -Pattern 'Error \d{4}|error code|CustomAction .* returned actual error' | Select-Object -First 5 | ForEach-Object { $_.Line }
        Write-Annotation 'msiexec failed' ("msiexec $arguments exited with $($p.ExitCode)`n" + (($errors + '...' + $context) -join "`n"))
        throw "msiexec $arguments failed with exit code $($p.ExitCode)"
    }
}

function Test-ProviderRegistered {
    $state = Join-Path $env:TEMP "wfp-state-$([guid]::NewGuid()).xml"
    netsh wfp show state file="$state" | Out-Null
    try { return [bool](Select-String -Path $state -Pattern $providerKey -SimpleMatch -Quiet) }
    finally { Remove-Item $state -ErrorAction SilentlyContinue }
}

function Check([bool] $condition, [string] $message) {
    if (-not $condition) {
        Write-Annotation 'Installer test failed' $message
        throw "FAILED: $message"
    }
    Write-Host "ok   $message"
}

trap {
    if ($_.Exception.Message -notlike 'FAILED:*' -and $_.Exception.Message -notlike 'msiexec*') {
        Write-Annotation 'Installer test failed' "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    }
    break
}

Write-Host "Installing $Msi (mode $Mode)"
Invoke-Msi "/i `"$Msi`" CRIOFIRE_MODE=$Mode CRIOFIRE_ALLOW_RUNNING=0 CRIOFIRE_AUTOSTART=1" (Join-Path $logDir 'install.log')

Check (Test-Path $cli) 'criofire.exe is installed'
Check (Test-Path (Join-Path $installDir 'criofire-ui.exe')) 'criofire-ui.exe is installed'
$svc = Get-Service criofire -ErrorAction SilentlyContinue
Check ($null -ne $svc) 'the criofire service exists'
try { $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } catch { Write-Host "Service did not reach Running: $_" }
Check ((Get-Service criofire).Status -eq 'Running') 'the criofire service is running'
Check ((Get-CimInstance Win32_Service -Filter "Name='criofire'").StartMode -eq 'Auto') 'the service starts automatically'
Check (Test-ProviderRegistered) 'CrioFire is registered with the Windows Filtering Platform'
$modeText = & $cli mode | Out-String
Check ($modeText -match "Mode:\s*$Mode") "the mode is $Mode ($($modeText.Trim()))"
$run = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name CrioFire -ErrorAction SilentlyContinue).CrioFire
Check ($run -match 'criofire-ui\.exe" --tray --machine$') "the app starts at sign-in for everyone ($run)"
Check (Test-Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\CrioFire Private Firewall.lnk')) 'the Start menu shortcut exists'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check ($machinePath -like "*$installDir*") 'criofire is on the system PATH'

# A rule through the installed command line, so uninstall has something to clean up.
& $cli block --tcp --port 9 | Out-Host
Check ($LASTEXITCODE -eq 0) 'a rule can be added with the installed command line'

Write-Host "Uninstalling"
Invoke-Msi "/x `"$Msi`"" (Join-Path $logDir 'uninstall.log')

Check ($null -eq (Get-Service criofire -ErrorAction SilentlyContinue)) 'the service is removed'
Check (-not (Test-Path $installDir)) 'the program folder is removed'
Check (-not (Test-Path (Join-Path $env:ProgramData 'criofire'))) '%ProgramData%\criofire is removed'
Check (-not (Test-ProviderRegistered)) 'CrioFire is unregistered from the Windows Filtering Platform (no rules left)'
$run = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name CrioFire -ErrorAction SilentlyContinue).CrioFire
Check ($null -eq $run) 'the sign-in entry is removed'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($machinePath -like "*$installDir*")) 'criofire is removed from the system PATH'

Write-Host 'Installer test passed.'
