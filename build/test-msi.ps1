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
    [string] $Mode = 'learning',

    # A language to install in, by its Windows language ID (the MSI's embedded transform of that
    # name), e.g. 1081 for Hindi. Default: what Windows Installer picks for the runner (English).
    [int] $Language
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

# Runs the installed command line; when it fails, the run page says why: what it printed, how
# the service is, and what the service logged.
function Check-Cli([string[]] $arguments, [string] $message) {
    $output = (& $cli @arguments 2>&1 | Out-String).Trim()
    $code = $LASTEXITCODE
    Write-Host $output
    if ($code -ne 0) {
        $state = (sc.exe query criofire | Out-String).Trim() -replace '\s+', ' '
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = (Get-Date).AddMinutes(-10) } -MaxEvents 6 -ErrorAction SilentlyContinue |
            ForEach-Object { $text = $_.Message -replace '\s+', ' '; "[$($_.ProviderName)] " + $text.Substring(0, [Math]::Min(700, $text.Length)) })
        Write-Annotation "criofire $($arguments -join ' ')" ("exit code $code`n$output`n$state`n" + ($events -join "`n"))
    }
    Check ($code -eq 0) $message
}

trap {
    if ($_.Exception.Message -notlike 'FAILED:*' -and $_.Exception.Message -notlike 'msiexec*') {
        Write-Annotation 'Installer test failed' "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    }
    break
}

$transform = if ($Language) { " TRANSFORMS=:$Language" } else { '' }
$suffix = if ($Language) { "-$Language" } else { '' }
Write-Host "Installing $Msi (mode $Mode$transform)"
$installLog = Join-Path $logDir "install$suffix.log"
Invoke-Msi "/i `"$Msi`" CRIOFIRE_MODE=$Mode CRIOFIRE_ALLOW_RUNNING=0 CRIOFIRE_AUTOSTART=1$transform" $installLog

if ($Language) {
    $languageLine = Select-String -Path $installLog -Pattern 'Property\(S\): ProductLanguage = (\d+)' | Select-Object -Last 1
    $installedLanguage = if ($languageLine) { $languageLine.Matches[0].Groups[1].Value } else { 'none' }
    Check ($installedLanguage -eq "$Language") "the installer ran in language $Language (ProductLanguage $installedLanguage)"
}

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

# CrioFire checks its own files against the list the build made.
$verify = & $cli verify | Out-String
Check ($LASTEXITCODE -eq 0 -and $verify -match 'All \d+ files') "the installed files are the built ones ($($verify.Trim()))"
$planted = Join-Path $installDir 'planted.dll'
Set-Content $planted 'not part of CrioFire'
$verify = & $cli verify | Out-String
Check ($LASTEXITCODE -eq 1 -and $verify -match 'planted\.dll') 'a program file added to the folder is reported'
Remove-Item $planted -Force

if (-not $Language) {
    # Tamper protection locks the service: Windows refuses to stop or reconfigure it, even for this
    # administrator; CrioFire's own command stops it; and the uninstall below still works.
    $protection = & $cli protection | Out-String
    Check ($protection -match 'Tamper protection is on') "tamper protection is on after a fresh install ($($protection.Trim()))"
    Check-Cli @('protection', 'off') 'tamper protection can be turned off'
    Start-Sleep -Seconds 2
    sc.exe config criofire start= auto | Out-Host
    Check ($LASTEXITCODE -eq 0) "with tamper protection off, an administrator may configure the service (exit code $LASTEXITCODE)"
    Check-Cli @('protection', 'on') 'tamper protection can be turned on'
    sc.exe stop criofire | Out-Host
    Check ($LASTEXITCODE -eq 5) "with tamper protection on, 'sc stop' is refused to an administrator (exit code $LASTEXITCODE)"
    sc.exe config criofire start= disabled | Out-Host
    Check ($LASTEXITCODE -eq 5) "with tamper protection on, 'sc config' is refused to an administrator (exit code $LASTEXITCODE)"
    Check ((Get-Service criofire).Status -eq 'Running') 'the service is still running'

    # Ending the process by force: either Windows refuses, or the service is started again.
    taskkill.exe /F /IM criofire-svc.exe | Out-Host
    Start-Sleep -Seconds 6
    try { (Get-Service criofire).WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } catch { Write-Host "Service did not reach Running: $_" }
    Check ((Get-Service criofire).Status -eq 'Running') 'after an attempt to end its process, the service is running'
    Check (Test-ProviderRegistered) 'the rules stayed in the Windows Filtering Platform'

    Check-Cli @('service', 'stop') "'criofire service stop' is accepted from an administrator"
    try { (Get-Service criofire).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { Write-Host "Service did not stop: $_" }
    Check ((Get-Service criofire).Status -eq 'Stopped') 'the service stopped'
    & $cli service start | Out-Host
    try { (Get-Service criofire).WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } catch { Write-Host "Service did not reach Running: $_" }
    Check ((Get-Service criofire).Status -eq 'Running') "'criofire service start' started it again"
}

if (-not $Language) {
    # Does the service's memory grow while it works? Four rounds of what the app asks all day
    # (each on a new connection), with name lookups and connections in between, and the memory
    # after a full collection each time. The numbers go to the run page; steady growth fails.
    function Ask-Service([string] $json) {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'criofire', [System.IO.Pipes.PipeDirection]::InOut)
        try {
            $pipe.Connect(5000)
            $writer = New-Object System.IO.StreamWriter($pipe, (New-Object System.Text.UTF8Encoding($false)))
            $writer.NewLine = "`n"
            $writer.AutoFlush = $true
            $reader = New-Object System.IO.StreamReader($pipe)
            $writer.WriteLine($json)
            return $reader.ReadLine()
        } catch {
            return $null
        } finally {
            $pipe.Dispose()
        }
    }

    function Read-Memory([string] $label) {
        $line = (& $cli diagnostics --gc 2>&1 | Out-String).Trim()
        Write-Host "Service memory, ${label}: $line"
        if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host "::notice title=Service memory, $label::$line" }
        if ($line -match 'private ([\d.]+) MB') { return [double]$Matches[1] }
        return -1
    }

    $ops = 'status', 'list', 'events', 'traffic', 'allowed', 'usage', 'changed', 'logs', 'domains', 'license', 'management', 'update'
    $readings = @(Read-Memory 'at the start')
    $asked = 0
    foreach ($round in 1..4) {
        $until = (Get-Date).AddSeconds(70)
        while ((Get-Date) -lt $until) {
            foreach ($op in $ops) { [void](Ask-Service "{`"op`":`"$op`"}"); $asked++ }
            try { [void][System.Net.Dns]::GetHostAddresses("criofire-test-$asked.example.com") } catch { }
            try { $tcp = New-Object System.Net.Sockets.TcpClient; [void]$tcp.ConnectAsync('127.0.0.1', 445).Wait(200); $tcp.Dispose() } catch { }
        }

        $readings += Read-Memory "after round $round ($asked requests)"
    }

    $grew = [Math]::Round($readings[4] - $readings[1], 1)
    Check ($readings[1] -gt 0 -and $grew -lt 60) "the service's memory stays level under load (rounds 1 to 4: $grew MB; readings $($readings -join ', ') MB)"
}

Write-Host "Uninstalling"
Invoke-Msi "/x `"$Msi`"" (Join-Path $logDir "uninstall$suffix.log")

Check ($null -eq (Get-Service criofire -ErrorAction SilentlyContinue)) 'the service is removed'
Check (-not (Test-Path $installDir)) 'the program folder is removed'
Check (-not (Test-Path (Join-Path $env:ProgramData 'criofire'))) '%ProgramData%\criofire is removed'
Check (-not (Test-ProviderRegistered)) 'CrioFire is unregistered from the Windows Filtering Platform (no rules left)'
$run = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name CrioFire -ErrorAction SilentlyContinue).CrioFire
Check ($null -eq $run) 'the sign-in entry is removed'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($machinePath -like "*$installDir*")) 'criofire is removed from the system PATH'

Write-Host 'Installer test passed.'
