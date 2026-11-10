<#
.SYNOPSIS
  Summarises .trx test results as a table on the GitHub Actions run page.

.DESCRIPTION
  Writes one row per test (outcome, duration, skip reason or error) to $env:GITHUB_STEP_SUMMARY,
  which is visible on the run's summary page without opening logs. Fails if any test failed,
  or if -RequireProject was given and none of that project's tests actually ran.
#>
param(
    [Parameter(Mandatory)] [string] $ResultsDir,
    [string] $Title = 'Tests',
    [string] $RequireProject
)

$ErrorActionPreference = 'Stop'
$files = @(Get-ChildItem $ResultsDir -Filter *.trx -Recurse -ErrorAction SilentlyContinue)
if ($files.Count -eq 0) { throw "No .trx files in $ResultsDir" }

$rows = foreach ($file in $files) {
    [xml] $trx = Get-Content $file.FullName -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $storage = @{}
    foreach ($def in (Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns)) {
        $storage[$def.Node.id] = [IO.Path]::GetFileNameWithoutExtension($def.Node.storage)
    }
    foreach ($r in (Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns)) {
        $n = $r.Node
        $message = ''
        if ($n.Output.ErrorInfo.Message) { $message = $n.Output.ErrorInfo.Message }
        elseif ($n.Output.StdOut) { $message = $n.Output.StdOut }
        [pscustomobject]@{
            Project  = $storage[$n.testId]
            Test     = $n.testName
            Outcome  = $n.outcome
            Duration = $n.duration
            Message  = (($message -replace '\s+', ' ').Trim() -replace '\|', '/')
        }
    }
}

$failed = @($rows | Where-Object Outcome -eq 'Failed')
$passed = @($rows | Where-Object Outcome -eq 'Passed')
$skipped = @($rows | Where-Object { $_.Outcome -notin 'Passed', 'Failed' })

$md = [System.Text.StringBuilder]::new()
[void] $md.AppendLine("### $Title")
[void] $md.AppendLine()
[void] $md.AppendLine("**$($passed.Count) passed, $($failed.Count) failed, $($skipped.Count) skipped**")
[void] $md.AppendLine()
[void] $md.AppendLine('| Result | Project | Test | Time | Note |')
[void] $md.AppendLine('| --- | --- | --- | --- | --- |')
foreach ($row in ($rows | Sort-Object @{ e = { $_.Outcome -ne 'Failed' } }, Project, Test)) {
    $icon = switch ($row.Outcome) { 'Passed' { 'pass' } 'Failed' { 'FAIL' } default { 'skip' } }
    $note = if ($row.Message.Length -gt 200) { $row.Message.Substring(0, 200) + '...' } else { $row.Message }
    [void] $md.AppendLine("| $icon | $($row.Project) | $($row.Test) | $($row.Duration) | $note |")
}

if ($env:GITHUB_STEP_SUMMARY) { $md.ToString() | Add-Content $env:GITHUB_STEP_SUMMARY -Encoding utf8 }
Write-Host $md.ToString()

if ($failed.Count -gt 0) { throw "$($failed.Count) test(s) failed." }
if ($RequireProject) {
    $ran = @($passed | Where-Object Project -eq $RequireProject)
    if ($ran.Count -eq 0) { throw "No $RequireProject tests passed: they were skipped or missing." }
}
