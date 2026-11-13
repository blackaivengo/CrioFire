<#
.SYNOPSIS
  Installs a CrioFire Server MSI silently, checks the result (service, firewall rule, locked-down
  data folder, the console answering, first administrator), uninstalls it, and checks what is left.
  Used by CI on a throwaway runner; run it only on a machine you can change (administrator, PowerShell 7).

.EXAMPLE
  ./build/test-server-msi.ps1 -Msi out/msi/criofire-server-0.0.1-x64.msi
#>
param(
    [Parameter(Mandatory)]
    [string] $Msi,

    [int] $Port = 7443
)

$ErrorActionPreference = 'Stop'
$logDir = Split-Path -Parent $Msi
$installDir = Join-Path $env:ProgramFiles 'CrioFire Server'
$exe = Join-Path $installDir 'criofire-server.exe'
$dataDir = Join-Path $env:ProgramData 'criofire-server'
$base = "https://localhost:$Port"

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
        $failed = ($lines | Select-String -Pattern 'Return value 3' -SimpleMatch | Select-Object -First 1).LineNumber
        $context = if ($failed) { $lines[[Math]::Max(0, $failed - 25)..($failed - 1)] } else { $lines | Select-Object -Last 25 }
        Write-Annotation 'msiexec failed' ("msiexec $arguments exited with $($p.ExitCode)`n" + ($context -join "`n"))
        throw "msiexec $arguments failed with exit code $($p.ExitCode)"
    }
}

function Check([bool] $condition, [string] $message) {
    if (-not $condition) {
        Write-Annotation 'Server installer test failed' $message
        throw "FAILED: $message"
    }
    Write-Host "ok   $message"
}

trap {
    if ($_.Exception.Message -notlike 'FAILED:*' -and $_.Exception.Message -notlike 'msiexec*') {
        Write-Annotation 'Server installer test failed' "$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    }
    break
}

# A leftover data folder (an earlier run) would already have an administrator.
if (Test-Path $dataDir) { Remove-Item $dataDir -Recurse -Force }

Write-Host "Installing $Msi (port $Port)"
Invoke-Msi "/i `"$Msi`" CRIOFIRE_SERVER_PORT=$Port" (Join-Path $logDir 'server-install.log')

Check (Test-Path $exe) 'criofire-server.exe is installed'
Check (Test-Path (Join-Path $installDir 'wwwroot\index.html')) 'the console files are installed'
$svc = Get-Service criofire-server -ErrorAction SilentlyContinue
Check ($null -ne $svc) 'the criofire-server service exists'
try { $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } catch { Write-Host "Service did not reach Running: $_" }
Check ((Get-Service criofire-server).Status -eq 'Running') 'the criofire-server service is running'
Check ((Get-CimInstance Win32_Service -Filter "Name='criofire-server'").StartMode -eq 'Auto') 'the service starts automatically'

$rule = Get-NetFirewallRule -DisplayName 'CrioFire Server' -ErrorAction SilentlyContinue
Check ($null -ne $rule) 'a Windows Firewall rule lets PCs in'
Check ((($rule | Get-NetFirewallPortFilter).LocalPort) -eq "$Port") "the rule is for TCP $Port"

$users = (Get-Acl $dataDir).Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' }
Check ($null -eq $users) 'only SYSTEM and administrators can read the data folder'
Check (Test-Path (Join-Path $dataDir 'server-certificate.pfx')) 'the server made its certificate'
$settings = Get-Content (Join-Path $dataDir 'settings.json') -Raw | ConvertFrom-Json
Check ($settings.port -eq $Port) "settings.json has port $Port"
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check ($machinePath -like "*$installDir*") 'criofire-server is on the system PATH'

# The console answers; the first administrator is created from this machine.
$health = $null
foreach ($i in 1..30) {
    try { $health = (Invoke-WebRequest "$base/health" -SkipCertificateCheck -UseBasicParsing).Content; break } catch { Start-Sleep 1 }
}
Check ($health -eq 'ok') 'the server answers over HTTPS'
Check ((Invoke-WebRequest "$base/" -SkipCertificateCheck -UseBasicParsing).Content -match 'CrioFire Server') 'the console page loads'
$state = Invoke-RestMethod "$base/api/admin/state" -SkipCertificateCheck
Check (-not $state.adminsExist -and $state.canSetUpHere) 'a new server offers to create the first administrator here'
$headers = @{ 'X-CrioFire' = '1' }
$body = @{ name = 'ci-admin'; password = 'a long ci password' } | ConvertTo-Json
$me = Invoke-RestMethod "$base/api/admin/setup" -Method Post -Body $body -ContentType 'application/json' -Headers $headers -SkipCertificateCheck -SessionVariable console
Check ($me.name -eq 'ci-admin') 'the first administrator was created'
$overview = Invoke-RestMethod "$base/api/admin/overview" -WebSession $console -SkipCertificateCheck
Check ($overview.computers -eq 0) 'the administrator is signed in and sees the overview'
$second = try { Invoke-WebRequest "$base/api/admin/setup" -Method Post -Body $body -ContentType 'application/json' -Headers $headers -SkipCertificateCheck -UseBasicParsing; 200 } catch { [int]$_.Exception.Response.StatusCode }
Check ($second -eq 409) 'a second "first administrator" is refused'
$token = (& $exe token --uses 3 | Out-String)
Check ($LASTEXITCODE -eq 0 -and $token -match 'criofire enroll') 'the installed command line creates enrollment codes'

Write-Host 'Uninstalling'
Invoke-Msi "/x `"$Msi`"" (Join-Path $logDir 'server-uninstall.log')

Check ($null -eq (Get-Service criofire-server -ErrorAction SilentlyContinue)) 'the service is removed'
Check (-not (Test-Path $installDir)) 'the program folder is removed'
Check ($null -eq (Get-NetFirewallRule -DisplayName 'CrioFire Server' -ErrorAction SilentlyContinue)) 'the firewall rule is removed'
Check (Test-Path (Join-Path $dataDir 'admins.json')) "the server's data is kept"
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($machinePath -like "*$installDir*")) 'criofire-server is removed from the system PATH'

Remove-Item $dataDir -Recurse -Force
Write-Host 'Server installer test passed.'
