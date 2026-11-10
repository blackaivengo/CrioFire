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

$runProblems = [System.Collections.Generic.List[string]]::new()
$rows = foreach ($file in $files) {
    [xml] $trx = Get-Content $file.FullName -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    # A crashed or aborted run says why in ResultSummary/RunInfos (e.g. "Test host process crashed").
    $summary = (Select-Xml -Xml $trx -XPath '//t:ResultSummary' -Namespace $ns | Select-Object -First 1).Node
    if ($summary -and $summary.outcome -notin 'Completed', 'Passed') {
        $infos = @(Select-Xml -Xml $trx -XPath '//t:RunInfos/t:RunInfo/t:Text' -Namespace $ns | ForEach-Object { $_.Node.InnerText })
        $runProblems.Add("$($file.Name): run $($summary.outcome). $($infos -join ' / ')")
    }
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

# Annotations: shown on the run page even to people who are not signed in (logs and summaries are not).
function Annotate([string] $level, [string] $title, [string] $text) {
    $clean = ($text -replace '%', '%25' -replace "`r", '' -replace "`n", '%0A')
    if ($clean.Length -gt 900) { $clean = $clean.Substring(0, 900) + '...' }
    Write-Host "::$level title=$($title -replace '[:,]', ' ')::$clean"
}

$byProject = $rows | Group-Object Project | ForEach-Object {
    $p = @($_.Group | Where-Object Outcome -eq 'Passed').Count
    $f = @($_.Group | Where-Object Outcome -eq 'Failed').Count
    "$($_.Name): $p passed, $f failed, $($_.Count - $p - $f) skipped"
}
Annotate 'notice' $Title (($byProject -join '; ') + " ($($files.Count) result files)")
foreach ($problem in $runProblems) {
    Annotate 'error' "Test run problem" $problem
}
foreach ($row in ($failed | Select-Object -First 10)) {
    Annotate 'error' "FAIL $($row.Project) $($row.Test)" $row.Message
}

if ($failed.Count -gt 0) { throw "$($failed.Count) test(s) failed." }
if ($RequireProject) {
    $ran = @($passed | Where-Object Project -eq $RequireProject)
    if ($ran.Count -eq 0) {
        $why = @($rows | Where-Object Project -eq $RequireProject | Select-Object -First 3 | ForEach-Object { "$($_.Test): $($_.Outcome) $($_.Message)" })
        $detail = if ($why.Count -gt 0) { $why -join ' / ' } else { "no results for it among: $(($rows.Project | Sort-Object -Unique) -join ', ')" }
        Annotate 'error' "No $RequireProject tests passed" $detail
        throw "No $RequireProject tests passed: they were skipped or missing."
    }
}
